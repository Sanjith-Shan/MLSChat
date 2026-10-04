//! MLSChat client: MLS group state plus a delivery-service connection.
//!
//! The client applies each group's log strictly in sequence order. Entries that
//! arrive early are buffered, entries already applied are dropped, and a gap is
//! filled by fetching from the cursor. Sends carry an idempotency key and are
//! re-sent unchanged after a reconnect until the server answers. A staged commit
//! is merged only when the client reaches it in the log, never on the ack, so
//! every member applies the same commits in the same order.

pub mod testkit;

use ds::wire::*;
use futures_util::{SinkExt, StreamExt};
use mls::codec::Codec;
use mls::group::{create_key_package, CommitOptions, Group, GroupConfig, KeyPackageBundle, Processed, PskStore, Signer};
use mls::messages::{MlsMessage, Proposal};
use mls::CipherSuite;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("mls: {0}")]
    Mls(#[from] mls::Error),
    #[error("codec: {0}")]
    Codec(#[from] mls::CodecError),
    #[error("server rejected: {0:?} (epoch {1})")]
    Rejected(RejectCode, u64),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// A decrypted application message as the user sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    pub group_id: GroupId,
    pub seq: u64,
    pub sender: ClientId,
    pub epoch: u64,
    pub plaintext: Vec<u8>,
    /// When the message was decrypted (for latency measurement).
    pub at: Instant,
}

/// Something the client noticed that a test or UI may want to see.
#[derive(Clone, Debug)]
pub enum Event {
    Joined { group_id: GroupId },
    Message(Received),
    MembershipChanged { group_id: GroupId, epoch: u64 },
    Removed { group_id: GroupId },
    /// A log entry the client could not apply. Should never happen.
    ProcessError { group_id: GroupId, seq: u64, error: String },
}

struct GroupState {
    group: Group,
    next_seq: u64,
    buffer: BTreeMap<u64, Delivery>,
    acked: u64,
    /// identity of each device, by leaf, for routing removes.
    removed: bool,
    /// Next sender_seq for our application messages in this group.
    next_send_seq: u64,
}

#[derive(Clone)]
struct PendingSend {
    req: SendReq,
    kind: Kind,
    sent_at: Instant,
    /// Kept for application messages so they can be re-encrypted if their epoch expires.
    plaintext: Option<Vec<u8>>,
    /// Rejected as out of order: resend after an earlier message is accepted.
    waiting: bool,
    /// Rejected as too old: re-encrypt once our group reaches this epoch.
    defer_until: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum SendOutcome {
    Accepted { seq: u64 },
    Rejected(RejectCode, u64),
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub group: GroupConfig,
    /// In `Relay` baseline mode there is no log order: merge own commits as soon
    /// as they are sent and apply deliveries in arrival order.
    pub optimistic: bool,
    /// Merge our own commit as soon as the server acknowledges it, instead of
    /// when we reach it in the log. Used to give every server mode in exp3 the
    /// same (common, naive) client policy.
    pub merge_on_accept: bool,
    pub ack_every: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig { group: GroupConfig::default(), optimistic: false, merge_on_accept: false, ack_every: 16 }
    }
}

pub struct Client {
    pub id: ClientId,
    pub cs: CipherSuite,
    url: String,
    signer: Signer,
    ws: Option<Ws>,
    groups: HashMap<GroupId, GroupState>,
    key_packages: HashMap<Vec<u8>, KeyPackageBundle>,
    pending: HashMap<MsgId, PendingSend>,
    outcomes: HashMap<u64, SendOutcome>,
    replies: HashMap<u64, ServerMsg>,
    inbox_next: u64,
    next_req: u64,
    pub events: VecDeque<Event>,
    pub config: ClientConfig,
    pub reconnects: u64,
    pub resent: u64,
}

fn new_msg_id() -> MsgId {
    mls::crypto::random_bytes(16)
}

impl Client {
    pub fn new(url: &str, id: &str, cs: CipherSuite, config: ClientConfig) -> Client {
        Client {
            id: id.as_bytes().to_vec(),
            cs,
            url: url.to_string(),
            signer: Signer::generate(cs, id.as_bytes()),
            ws: None,
            groups: HashMap::new(),
            key_packages: HashMap::new(),
            pending: HashMap::new(),
            outcomes: HashMap::new(),
            replies: HashMap::new(),
            inbox_next: 0,
            next_req: 1,
            events: VecDeque::new(),
            config,
            reconnects: 0,
            resent: 0,
        }
    }

    pub fn group(&self, g: &[u8]) -> Option<&Group> {
        self.groups.get(g).map(|s| &s.group)
    }

    pub fn group_ids(&self) -> Vec<GroupId> {
        self.groups.keys().cloned().collect()
    }

    pub fn is_connected(&self) -> bool {
        self.ws.is_some()
    }

    pub fn pending_sends(&self) -> usize {
        self.pending.len()
    }

    pub fn next_seq(&self, g: &[u8]) -> Option<u64> {
        self.groups.get(g).map(|s| s.next_seq)
    }

    // ------------------------------------------------------------------
    // Connection management

    async fn raw_send(&mut self, m: &ClientMsg) -> bool {
        let Some(ws) = self.ws.as_mut() else { return false };
        if ws.send(Message::Binary(m.to_bytes())).await.is_err() {
            self.ws = None;
            return false;
        }
        true
    }

    /// Connect (or reconnect), resynchronise every group from its cursor, and
    /// re-send every unanswered request with its original idempotency key.
    pub async fn connect(&mut self) -> Result<()> {
        let (ws, _) = tokio_tungstenite::connect_async(&self.url).await.map_err(|e| ClientError::Other(format!("connect: {e}")))?;
        if let Ok(s) = match ws.get_ref() {
            MaybeTlsStream::Plain(s) => Ok(s),
            _ => Err(()),
        } {
            s.set_nodelay(true).ok();
        }
        self.ws = Some(ws);
        let hello = ClientMsg::Hello { client_id: self.id.clone() };
        if !self.raw_send(&hello).await {
            return Err(ClientError::Other("hello failed".into()));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.read_one(deadline).await? {
                Some(ServerMsg::HelloOk { inbox_next: _, .. }) => break,
                Some(other) => self.handle_server(other).await,
                None => return Err(ClientError::Other("disconnected during hello".into())),
            }
        }
        let fetches: Vec<(GroupId, u64)> = self.groups.iter().filter(|(_, s)| !s.removed).map(|(g, s)| (g.clone(), s.next_seq)).collect();
        for (g, from) in fetches {
            self.raw_send(&ClientMsg::Fetch { group_id: g, from_seq: from }).await;
        }
        let inbox = ClientMsg::FetchInbox { from_seq: self.inbox_next };
        self.raw_send(&inbox).await;
        let mut resend: Vec<PendingSend> = self.pending.values().filter(|p| p.defer_until.is_none()).cloned().collect();
        resend.sort_by_key(|p| p.req.req_id);
        for p in resend {
            self.resent += 1;
            self.raw_send(&ClientMsg::Send(p.req)).await;
        }
        Ok(())
    }

    /// Reconnect with backoff until it works or `deadline` passes.
    pub async fn ensure_connected(&mut self, deadline: Instant) -> Result<()> {
        let mut backoff = Duration::from_millis(20);
        while self.ws.is_none() {
            if Instant::now() > deadline {
                return Err(ClientError::Timeout("reconnect"));
            }
            match self.connect().await {
                Ok(()) => {
                    self.reconnects += 1;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_millis(500));
                }
            }
        }
        Ok(())
    }

    /// Drop the connection without telling the server (chaos testing).
    pub fn drop_connection(&mut self) {
        self.ws = None;
    }

    async fn read_one(&mut self, deadline: Instant) -> Result<Option<ServerMsg>> {
        let Some(ws) = self.ws.as_mut() else { return Ok(None) };
        let now = Instant::now();
        if now >= deadline {
            return Err(ClientError::Timeout("read"));
        }
        match tokio::time::timeout(deadline - now, ws.next()).await {
            Err(_) => Err(ClientError::Timeout("read")),
            Ok(None) | Ok(Some(Err(_))) => {
                self.ws = None;
                Ok(None)
            }
            Ok(Some(Ok(Message::Binary(b)))) => Ok(Some(ServerMsg::from_bytes(&b)?)),
            Ok(Some(Ok(Message::Close(_)))) => {
                self.ws = None;
                Ok(None)
            }
            Ok(Some(Ok(_))) => Ok(Some(ServerMsg::FetchDone { group_id: vec![], next_seq: 0 })),
        }
    }

    /// Process incoming traffic until `deadline` or until `until` returns true.
    /// Reconnects transparently.
    pub async fn pump(&mut self, deadline: Instant, mut until: impl FnMut(&Client) -> bool) -> Result<()> {
        loop {
            if until(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ClientError::Timeout("pump"));
            }
            if self.ws.is_none() {
                self.ensure_connected(deadline).await?;
                continue;
            }
            match self.read_one(deadline).await {
                Ok(Some(m)) => self.handle_server(m).await,
                Ok(None) => {}
                Err(ClientError::Timeout(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Drain whatever is already available without blocking for long.
    pub async fn poll(&mut self, wait: Duration) -> Result<()> {
        let deadline = Instant::now() + wait;
        let _ = self.pump(deadline, |_| false).await;
        Ok(())
    }

    async fn handle_server(&mut self, m: ServerMsg) {
        match m {
            ServerMsg::HelloOk { .. } | ServerMsg::FetchDone { .. } => {}
            ServerMsg::KeyPackage { req_id, .. } | ServerMsg::GroupCreated { req_id, .. } => {
                self.replies.insert(req_id, m);
            }
            ServerMsg::Accepted { req_id, msg_id, seq, .. } => {
                if let Some(p) = self.pending.remove(&msg_id) {
                    if p.kind == Kind::Commit && self.config.merge_on_accept {
                        if let Some(st) = self.groups.get_mut(&p.req.group_id) {
                            if st.group.has_pending_commit() {
                                let _ = st.group.merge_pending_commit();
                            }
                        }
                    }
                    if p.kind == Kind::Application {
                        self.resend_waiting(&p.req.group_id).await;
                    }
                }
                self.outcomes.insert(req_id, SendOutcome::Accepted { seq });
            }
            ServerMsg::Rejected { req_id, msg_id, code, current_epoch, expected_seq } => {
                if let Some(p) = self.pending.get_mut(&msg_id) {
                    if p.kind == Kind::Application && p.req.sender_seq > 0 {
                        match code {
                            // An earlier message of ours is not in yet: wait for it, then resend in order.
                            RejectCode::OutOfOrder if p.req.sender_seq >= expected_seq => {
                                p.waiting = true;
                                return;
                            }
                            // Built on an epoch the server no longer accepts. It was never logged, so
                            // re-encrypting it (same sender_seq) cannot duplicate it; wait until we have
                            // caught up to an epoch the server accepts.
                            RejectCode::TooOld => {
                                p.defer_until = Some(current_epoch.saturating_sub(1));
                                let g = p.req.group_id.clone();
                                self.release_deferred(&g).await;
                                return;
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(p) = self.pending.remove(&msg_id) {
                    if p.kind == Kind::Commit {
                        if let Some(s) = self.groups.get_mut(&p.req.group_id) {
                            s.group.clear_pending_commit();
                        }
                    }
                }
                self.outcomes.insert(req_id, SendOutcome::Rejected(code, current_epoch));
            }
            ServerMsg::Deliver(d) => self.on_delivery(d).await,
            ServerMsg::Welcome { inbox_seq, group_id, start_seq, welcome } => {
                if inbox_seq >= self.inbox_next || self.config.optimistic {
                    self.inbox_next = inbox_seq + 1;
                    self.on_welcome(group_id, start_seq, &welcome).await;
                }
            }
        }
    }

    async fn on_welcome(&mut self, group_id: GroupId, start_seq: u64, welcome: &[u8]) {
        if self.groups.contains_key(&group_id) {
            return;
        }
        let Ok(MlsMessage::Welcome(w)) = MlsMessage::from_bytes(welcome) else { return };
        let kpb = w.secrets.iter().find_map(|s| self.key_packages.get(&s.new_member)).cloned();
        let Some(kpb) = kpb else { return };
        match Group::join(&w, &kpb, None, PskStore::default(), self.config.group.clone()) {
            Ok(g) => {
                self.key_packages.remove(&kpb.key_package.reference());
                self.groups.insert(group_id.clone(), GroupState { group: g, next_seq: start_seq, buffer: BTreeMap::new(), acked: start_seq, removed: false, next_send_seq: 1 });
                self.events.push_back(Event::Joined { group_id: group_id.clone() });
                self.raw_send(&ClientMsg::Fetch { group_id, from_seq: start_seq }).await;
            }
            Err(e) => self.events.push_back(Event::ProcessError { group_id, seq: start_seq, error: format!("join: {e}") }),
        }
    }

    /// Resend, in order, our application messages that were rejected as out of order.
    async fn resend_waiting(&mut self, group_id: &[u8]) {
        let mut w: Vec<SendReq> = self
            .pending
            .values_mut()
            .filter(|p| p.waiting && p.req.group_id == group_id)
            .map(|p| {
                p.waiting = false;
                p.req.clone()
            })
            .collect();
        w.sort_by_key(|r| r.sender_seq);
        for r in w {
            self.raw_send(&ClientMsg::Send(r)).await;
        }
    }

    /// Re-encrypt and resend deferred (too old) messages once our epoch allows it.
    async fn release_deferred(&mut self, group_id: &[u8]) {
        let Some(st) = self.groups.get_mut(group_id) else { return };
        let epoch = st.group.epoch();
        let mut ready: Vec<MsgId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.req.group_id == group_id && p.defer_until.map(|t| epoch >= t).unwrap_or(false))
            .map(|(k, _)| k.clone())
            .collect();
        ready.sort_by_key(|k| self.pending[k].req.sender_seq);
        for k in ready {
            let mut p = self.pending.remove(&k).unwrap();
            let Some(pt) = p.plaintext.clone() else { continue };
            let Ok(m) = st.group.encrypt_application(&pt, b"") else { continue };
            p.req.msg_id = new_msg_id();
            p.req.payload = m.to_bytes();
            p.defer_until = None;
            p.waiting = false;
            let req = p.req.clone();
            self.pending.insert(req.msg_id.clone(), p);
            let Some(ws) = self.ws.as_mut() else { continue };
            if ws.send(Message::Binary(ClientMsg::Send(req).to_bytes())).await.is_err() {
                self.ws = None;
            }
        }
    }

    async fn on_delivery(&mut self, d: Delivery) {
        let gid = d.group_id.clone();
        let d_gid = gid.clone();
        let ack_every = self.config.ack_every;
        let mut ack = None;
        {
            let Some(st) = self.groups.get_mut(&gid) else { return };
            if self.config.optimistic {
                // Baseline: apply in arrival order, no sequence tracking.
                Self::apply(&self.id, st, d, &mut self.events);
                return;
            }
            if d.seq < st.next_seq {
                return; // already applied
            }
            st.buffer.insert(d.seq, d);
            while let Some(next) = st.buffer.remove(&st.next_seq) {
                Self::apply(&self.id, st, next, &mut self.events);
                st.next_seq += 1;
            }
            if st.next_seq >= st.acked + ack_every {
                st.acked = st.next_seq;
                ack = Some(st.next_seq);
            }
        }
        if let Some(seq) = ack {
            self.raw_send(&ClientMsg::Ack { group_id: gid, seq }).await;
        }
        if self.pending.values().any(|p| p.defer_until.is_some()) {
            let g = d_gid;
            self.release_deferred(&g).await;
        }
    }

    fn apply(me: &[u8], st: &mut GroupState, d: Delivery, events: &mut VecDeque<Event>) {
        if st.removed {
            return;
        }
        let msg = match MlsMessage::from_bytes(&d.payload) {
            Ok(m) => m,
            Err(e) => {
                events.push_back(Event::ProcessError { group_id: d.group_id, seq: d.seq, error: format!("decode: {e}") });
                return;
            }
        };
        if d.sender == me && d.kind != Kind::Commit {
            return; // our own application message or proposal
        }
        if d.sender == me && d.kind == Kind::Commit && !st.group.has_pending_commit() {
            // Our commit, already merged (optimistic mode) or dropped after a reject.
            if st.group.epoch() > d.epoch {
                return;
            }
        }
        match st.group.process(&msg) {
            Ok(Processed::Application { data, epoch, .. }) => {
                events.push_back(Event::Message(Received { group_id: d.group_id, seq: d.seq, sender: d.sender, epoch, plaintext: data, at: Instant::now() }));
            }
            Ok(Processed::Commit(summary)) => {
                if summary.self_removed {
                    st.removed = true;
                    events.push_back(Event::Removed { group_id: d.group_id });
                } else {
                    events.push_back(Event::MembershipChanged { group_id: d.group_id, epoch: summary.new_epoch });
                }
            }
            Ok(Processed::OwnCommitMerged) => events.push_back(Event::MembershipChanged { group_id: d.group_id, epoch: st.group.epoch() }),
            Ok(Processed::Proposal { .. }) => {}
            Err(e) => events.push_back(Event::ProcessError { group_id: d.group_id, seq: d.seq, error: e.to_string() }),
        }
    }

    // ------------------------------------------------------------------
    // Requests

    fn req_id(&mut self) -> u64 {
        self.next_req += 1;
        self.next_req
    }

    async fn request(&mut self, m: ClientMsg, req_id: u64, deadline: Instant) -> Result<ServerMsg> {
        self.ensure_connected(deadline).await?;
        self.raw_send(&m).await;
        loop {
            if let Some(r) = self.replies.remove(&req_id) {
                return Ok(r);
            }
            if self.ws.is_none() {
                self.ensure_connected(deadline).await?;
                self.raw_send(&m).await;
            }
            match self.read_one(deadline).await? {
                Some(msg) => self.handle_server(msg).await,
                None => {}
            }
        }
    }

    pub async fn publish_key_packages(&mut self, n: usize) -> Result<()> {
        for _ in 0..n {
            let kpb = create_key_package(self.cs, &self.signer)?;
            let bytes = MlsMessage::KeyPackage(kpb.key_package.clone()).to_bytes();
            self.key_packages.insert(kpb.key_package.reference(), kpb);
            self.ensure_connected(Instant::now() + Duration::from_secs(10)).await?;
            self.raw_send(&ClientMsg::PublishKeyPackage { key_package: bytes }).await;
        }
        Ok(())
    }

    pub async fn fetch_key_package(&mut self, who: &[u8]) -> Result<mls::messages::KeyPackage> {
        // Publishing is fire-and-forget on the publisher's own connection, so a fetch
        // can overtake it. Retry briefly before giving up (exp3 found this race).
        let mut r = ServerMsg::KeyPackage { req_id: 0, key_package: None };
        for attempt in 0..20 {
            let req_id = self.req_id();
            r = self.request(ClientMsg::FetchKeyPackage { req_id, client_id: who.to_vec() }, req_id, Instant::now() + Duration::from_secs(10)).await?;
            if matches!(r, ServerMsg::KeyPackage { key_package: Some(_), .. }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10 * (attempt + 1))).await;
        }
        match r {
            ServerMsg::KeyPackage { key_package: Some(b), .. } => match MlsMessage::from_bytes(&b)? {
                MlsMessage::KeyPackage(kp) => Ok(kp),
                _ => Err(ClientError::Other("not a key package".into())),
            },
            _ => Err(ClientError::Other(format!("no key package for {}", String::from_utf8_lossy(who)))),
        }
    }

    pub async fn create_group(&mut self, group_id: &[u8]) -> Result<()> {
        let req_id = self.req_id();
        let r = self.request(ClientMsg::CreateGroup { req_id, group_id: group_id.to_vec() }, req_id, Instant::now() + Duration::from_secs(10)).await?;
        if !matches!(r, ServerMsg::GroupCreated { ok: true, .. }) {
            return Err(ClientError::Other("group exists".into()));
        }
        let g = Group::create(self.cs, self.signer.clone(), group_id.to_vec(), vec![], self.config.group.clone())?;
        self.groups.insert(group_id.to_vec(), GroupState { group: g, next_seq: 0, buffer: BTreeMap::new(), acked: 0, removed: false, next_send_seq: 1 });
        Ok(())
    }

    /// Submit a send and return its request id; the answer arrives via `pump`.
    pub async fn submit(&mut self, group_id: &[u8], payload: Vec<u8>, kind: Kind, add: Vec<ClientId>, remove: Vec<ClientId>, welcome: Option<Vec<u8>>) -> u64 {
        self.submit_seq(group_id, payload, kind, add, remove, welcome, 0, None).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_seq(&mut self, group_id: &[u8], payload: Vec<u8>, kind: Kind, add: Vec<ClientId>, remove: Vec<ClientId>, welcome: Option<Vec<u8>>, sender_seq: u64, plaintext: Option<Vec<u8>>) -> u64 {
        let req_id = self.req_id();
        let req = SendReq { req_id, group_id: group_id.to_vec(), msg_id: new_msg_id(), payload, add_members: add, remove_members: remove, welcome, sender_seq };
        self.pending.insert(req.msg_id.clone(), PendingSend { req: req.clone(), kind, sent_at: Instant::now(), plaintext, waiting: false, defer_until: None });
        self.raw_send(&ClientMsg::Send(req)).await;
        req_id
    }

    pub async fn await_outcome(&mut self, req_id: u64, deadline: Instant) -> Result<SendOutcome> {
        self.pump(deadline, |c| c.outcomes.contains_key(&req_id)).await?;
        Ok(self.outcomes.remove(&req_id).unwrap())
    }

    pub fn take_outcome(&mut self, req_id: u64) -> Option<SendOutcome> {
        self.outcomes.remove(&req_id)
    }

    /// Encrypt and send an application message; does not wait for the ack.
    pub async fn send_text(&mut self, group_id: &[u8], text: &[u8]) -> Result<u64> {
        let st = self.groups.get_mut(group_id).ok_or_else(|| ClientError::Other("unknown group".into()))?;
        let m = st.group.encrypt_application(text, b"")?;
        let seq = st.next_send_seq;
        st.next_send_seq += 1;
        Ok(self.submit_seq(group_id, m.to_bytes(), Kind::Application, vec![], vec![], None, seq, Some(text.to_vec())).await)
    }

    /// Wait until our log position reaches the group's current end (all our sends applied).
    pub async fn sync_group(&mut self, group_id: &[u8], deadline: Instant) -> Result<()> {
        let target = loop {
            // Ask for the log tail by fetching from our cursor; FetchDone tells us the end.
            let from = self.next_seq(group_id).unwrap_or(0);
            self.ensure_connected(deadline).await?;
            self.raw_send(&ClientMsg::Fetch { group_id: group_id.to_vec(), from_seq: from }).await;
            let mut end = None;
            while end.is_none() {
                match self.read_one(deadline).await? {
                    Some(ServerMsg::FetchDone { group_id: g, next_seq }) if g == group_id => end = Some(next_seq),
                    Some(m) => self.handle_server(m).await,
                    None => break,
                }
            }
            if let Some(e) = end {
                break e;
            }
        };
        let g = group_id.to_vec();
        self.pump(deadline, |c| c.next_seq(&g).map(|n| n >= target).unwrap_or(true)).await
    }

    /// Commit `proposals` (plus any cached ones) and keep retrying on epoch
    /// conflicts until the server accepts one. Returns the attempts it took.
    pub async fn commit_with_retry(
        &mut self,
        group_id: &[u8],
        mut make: impl FnMut(&Group) -> Vec<Proposal>,
        add: Vec<ClientId>,
        remove: Vec<ClientId>,
        deadline: Instant,
    ) -> Result<u32> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            self.sync_group(group_id, deadline).await?;
            let st = self.groups.get_mut(group_id).ok_or_else(|| ClientError::Other("unknown group".into()))?;
            let props = make(&st.group);
            let out = st.group.commit(props, CommitOptions { force_path: true, ..Default::default() })?;
            let welcome = out.welcome.as_ref().map(|w| w.to_bytes());
            let req = self.submit(group_id, out.commit.to_bytes(), Kind::Commit, add.clone(), remove.clone(), welcome).await;
            match self.await_outcome(req, deadline).await? {
                SendOutcome::Accepted { seq } => {
                    let g = group_id.to_vec();
                    self.pump(deadline, |c| c.next_seq(&g).map(|n| n > seq).unwrap_or(true)).await?;
                    return Ok(attempts);
                }
                SendOutcome::Rejected(RejectCode::StaleEpoch, _) => continue,
                SendOutcome::Rejected(c, e) => return Err(ClientError::Rejected(c, e)),
            }
        }
    }

    /// Add devices by client id: fetch a key package for each and commit.
    pub async fn add_members(&mut self, group_id: &[u8], who: &[ClientId], deadline: Instant) -> Result<u32> {
        let mut kps = Vec::new();
        for w in who {
            kps.push(self.fetch_key_package(w).await?);
        }
        self.commit_with_retry(group_id, |_| kps.iter().cloned().map(Proposal::Add).collect(), who.to_vec(), vec![], deadline).await
    }

    pub async fn remove_members(&mut self, group_id: &[u8], who: &[ClientId], deadline: Instant) -> Result<u32> {
        let who_v = who.to_vec();
        self.commit_with_retry(
            group_id,
            |g| {
                g.member_identities().into_iter().filter(|(_, id)| who_v.contains(id)).map(|(l, _)| Proposal::Remove(l)).collect()
            },
            vec![],
            who.to_vec(),
            deadline,
        )
        .await
    }

    /// Stage a commit and send it without waiting (for concurrency experiments).
    pub async fn fire_commit(&mut self, group_id: &[u8], proposals: Vec<Proposal>, add: Vec<ClientId>) -> Result<u64> {
        let st = self.groups.get_mut(group_id).ok_or_else(|| ClientError::Other("unknown group".into()))?;
        let out = st.group.commit(proposals, CommitOptions { force_path: true, ..Default::default() })?;
        let bytes = out.commit.to_bytes();
        let welcome = out.welcome.as_ref().map(|w| w.to_bytes());
        Ok(self.submit(group_id, bytes, Kind::Commit, add, vec![], welcome).await)
    }

    pub fn epoch_authenticator(&self, group_id: &[u8]) -> Option<Vec<u8>> {
        self.groups.get(group_id).filter(|s| !s.removed).map(|s| s.group.epoch_authenticator().to_vec())
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        self.events.drain(..).collect()
    }

    #[allow(dead_code)]
    fn oldest_pending(&self) -> Option<Duration> {
        self.pending.values().map(|p| p.sent_at.elapsed()).max()
    }
}
