//! The delivery service: a Tokio WebSocket server that totally orders each
//! group's messages, fences commits by epoch, fans out to every member device,
//! lets offline devices catch up by cursor, and makes sends idempotent.

use crate::store::*;
use wire::*;
use futures_util::{SinkExt, StreamExt};
use mls::codec::Codec;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// How the server treats concurrent commits. Only `Fenced` is the real design;
/// the other two exist as experiment baselines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Totally ordered log; a commit is accepted only for the group's current epoch.
    Fenced,
    /// Totally ordered log, but every commit is accepted whatever its epoch.
    OrderedUnfenced,
    /// No log order: each message is fanned out independently as it arrives.
    Relay,
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "fenced" => Ok(Mode::Fenced),
            "ordered-unfenced" => Ok(Mode::OrderedUnfenced),
            "relay" => Ok(Mode::Relay),
            _ => Err(format!("unknown mode {s}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    /// fsync the write-ahead log before acknowledging.
    pub sync_writes: bool,
    /// Honour idempotency keys. Off only to show what retries do without them.
    pub idempotent: bool,
    /// Accept application messages up to this many epochs old.
    pub max_app_epoch_lag: u64,
    /// Serve static files (the web client) from here for non-WebSocket requests.
    pub web_root: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::Fenced, sync_writes: true, idempotent: true, max_app_epoch_lag: 2, web_root: None }
    }
}

type Tx = mpsc::UnboundedSender<Vec<u8>>;

pub struct Server {
    store: Store,
    config: Config,
    groups: Mutex<HashMap<GroupId, Arc<tokio::sync::Mutex<GroupMeta>>>>,
    conns: Mutex<HashMap<ClientId, Vec<(u64, Tx)>>>,
    next_conn: AtomicU64,
    pub stats: Stats,
}

#[derive(Default)]
pub struct Stats {
    pub accepted: AtomicU64,
    pub rejected_stale: AtomicU64,
    pub duplicates: AtomicU64,
    pub delivered: AtomicU64,
}

impl Server {
    pub fn open(path: &Path, config: Config) -> anyhow::Result<Arc<Server>> {
        let store = Store::open(path, config.sync_writes)?;
        Ok(Arc::new(Server {
            store,
            config,
            groups: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            stats: Stats::default(),
        }))
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Accept connections until the listener fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, addr) = listener.accept().await?;
            let s = self.clone();
            tokio::spawn(async move {
                if let Err(e) = s.handle_conn(stream, addr).await {
                    tracing::debug!("connection {addr} ended: {e}");
                }
            });
        }
    }

    pub async fn bind(self: Arc<Self>, addr: &str) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let h = tokio::spawn(async move {
            let _ = self.serve(listener).await;
        });
        Ok((local, h))
    }

    async fn group(&self, g: &[u8]) -> anyhow::Result<Option<Arc<tokio::sync::Mutex<GroupMeta>>>> {
        if let Some(m) = self.groups.lock().unwrap().get(g) {
            return Ok(Some(m.clone()));
        }
        let Some(meta) = self.store.group_meta(g)? else { return Ok(None) };
        let mut map = self.groups.lock().unwrap();
        Ok(Some(map.entry(g.to_vec()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(meta))).clone()))
    }

    fn push(&self, client: &[u8], msg: &ServerMsg) {
        let bytes = msg.to_bytes();
        if let Some(list) = self.conns.lock().unwrap().get(client) {
            for (_, tx) in list {
                let _ = tx.send(bytes.clone());
            }
        }
    }

    async fn handle_conn(self: Arc<Self>, mut stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
        stream.set_nodelay(true).ok();
        if let Some(root) = self.config.web_root.clone() {
            if !crate::web::is_websocket(&stream).await? {
                return crate::web::serve(&mut stream, &root).await;
            }
        }
        let ws = tokio_tungstenite::accept_async(stream).await?;
        let (mut sink, mut source) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                if sink.send(Message::Binary(b.into())).await.is_err() {
                    break;
                }
            }
        });
        let conn_id = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let mut me: Option<ClientId> = None;
        let result: anyhow::Result<()> = async {
            while let Some(frame) = source.next().await {
                let data = match frame? {
                    Message::Binary(b) => b.to_vec(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                let msg = ClientMsg::from_bytes(&data)?;
                match msg {
                    ClientMsg::Hello { client_id } => {
                        self.conns.lock().unwrap().entry(client_id.clone()).or_default().push((conn_id, tx.clone()));
                        let cursors = self.store.cursors(&client_id)?.into_iter().map(|(group_id, seq)| Cursor { group_id, seq }).collect();
                        let inbox_next = self.store.inbox_next(&client_id)?;
                        let _ = tx.send(ServerMsg::HelloOk { cursors, inbox_next }.to_bytes());
                        me = Some(client_id);
                    }
                    other => {
                        let Some(id) = me.clone() else { anyhow::bail!("message before Hello") };
                        self.handle(&id, other, &tx).await?;
                    }
                }
            }
            Ok(())
        }
        .await;
        if let Some(id) = me {
            let mut conns = self.conns.lock().unwrap();
            if let Some(list) = conns.get_mut(&id) {
                list.retain(|(c, _)| *c != conn_id);
                if list.is_empty() {
                    conns.remove(&id);
                }
            }
        }
        drop(tx);
        let _ = writer.await;
        result
    }

    async fn handle(&self, me: &ClientId, msg: ClientMsg, tx: &Tx) -> anyhow::Result<()> {
        let reply = |m: ServerMsg| {
            let _ = tx.send(m.to_bytes());
        };
        match msg {
            ClientMsg::Hello { .. } => {}
            ClientMsg::PublishKeyPackage { key_package } => self.store.put_key_package(me, &key_package)?,
            ClientMsg::FetchKeyPackage { req_id, client_id } => {
                reply(ServerMsg::KeyPackage { req_id, key_package: self.store.take_key_package(&client_id)? });
            }
            ClientMsg::CreateGroup { req_id, group_id } => {
                let ok = if self.group(&group_id).await?.is_some() {
                    false
                } else {
                    let meta = GroupMeta { epoch: 0, next_seq: 0, members: vec![me.clone()], sender_seqs: vec![] };
                    self.store.create_group(&group_id, &meta)?;
                    true
                };
                reply(ServerMsg::GroupCreated { req_id, ok });
            }
            ClientMsg::Send(req) => self.handle_send(me, req, tx).await?,
            ClientMsg::Fetch { group_id, from_seq } => {
                let Some(g) = self.group(&group_id).await? else {
                    reply(ServerMsg::FetchDone { group_id, next_seq: 0 });
                    return Ok(());
                };
                // Hold the group lock so the replay and live pushes cannot interleave out of order.
                let meta = g.lock().await;
                if !meta.members.contains(me) {
                    reply(ServerMsg::FetchDone { group_id, next_seq: meta.next_seq });
                    return Ok(());
                }
                for d in self.store.read_log(&group_id, from_seq)? {
                    reply(ServerMsg::Deliver(d));
                }
                reply(ServerMsg::FetchDone { group_id, next_seq: meta.next_seq });
            }
            ClientMsg::Ack { group_id, seq } => self.store.set_cursor(me, &group_id, seq)?,
            ClientMsg::FetchInbox { from_seq } => {
                for (s, e) in self.store.read_inbox(me, from_seq)? {
                    reply(ServerMsg::Welcome { inbox_seq: s, group_id: e.group_id, start_seq: e.start_seq, welcome: e.welcome });
                }
            }
        }
        Ok(())
    }

    async fn handle_send(&self, me: &ClientId, req: SendReq, tx: &Tx) -> anyhow::Result<()> {
        let reply = |m: ServerMsg| {
            let _ = tx.send(m.to_bytes());
        };
        let rejected = |code, current_epoch| ServerMsg::Rejected { req_id: req.req_id, msg_id: req.msg_id.clone(), code, current_epoch, expected_seq: 0 };
        let header = match parse_header(&req.payload) {
            Ok(h) if h.group_id == req.group_id => h,
            _ => {
                reply(rejected(RejectCode::Malformed, 0));
                return Ok(());
            }
        };
        let Some(g) = self.group(&req.group_id).await? else {
            reply(rejected(RejectCode::UnknownGroup, 0));
            return Ok(());
        };

        if self.config.mode == Mode::Relay {
            return self.relay(me, req, header, g, tx).await;
        }

        let mut meta = g.lock().await;
        if self.config.idempotent {
            if let Some(d) = self.store.dedupe(&req.group_id, &req.msg_id)? {
                self.stats.duplicates.fetch_add(1, Ordering::Relaxed);
                reply(ServerMsg::Accepted { req_id: req.req_id, msg_id: req.msg_id, seq: d.seq, epoch: d.epoch, duplicate: true });
                return Ok(());
            }
        }
        if !meta.members.contains(me) {
            reply(rejected(RejectCode::NotMember, meta.epoch));
            return Ok(());
        }
        let fenced = self.config.mode == Mode::Fenced;
        match header.kind {
            Kind::Commit | Kind::Proposal => {
                if fenced && header.epoch != meta.epoch {
                    self.stats.rejected_stale.fetch_add(1, Ordering::Relaxed);
                    reply(rejected(RejectCode::StaleEpoch, meta.epoch));
                    return Ok(());
                }
            }
            Kind::Application => {
                if req.sender_seq > 0 {
                    let expected = meta.last_sender_seq(me) + 1;
                    if req.sender_seq != expected {
                        reply(ServerMsg::Rejected { req_id: req.req_id, msg_id: req.msg_id.clone(), code: RejectCode::OutOfOrder, current_epoch: meta.epoch, expected_seq: expected });
                        return Ok(());
                    }
                }
                if header.epoch > meta.epoch && fenced {
                    reply(rejected(RejectCode::Malformed, meta.epoch));
                    return Ok(());
                }
                if meta.epoch.saturating_sub(header.epoch) > self.config.max_app_epoch_lag {
                    reply(rejected(RejectCode::TooOld, meta.epoch));
                    return Ok(());
                }
            }
        }

        let seq = meta.next_seq;
        let mut next = meta.clone();
        next.next_seq += 1;
        if header.kind == Kind::Application && req.sender_seq > 0 {
            next.set_sender_seq(me, req.sender_seq);
        }
        let recipients = meta.members.clone();
        let mut welcomes = Vec::new();
        if header.kind == Kind::Commit {
            next.epoch = if fenced { meta.epoch + 1 } else { meta.epoch.max(header.epoch + 1) };
            next.members.retain(|m| !req.remove_members.contains(m));
            for a in &req.add_members {
                if !next.members.contains(a) {
                    next.members.push(a.clone());
                }
                if let Some(w) = &req.welcome {
                    welcomes.push((a.clone(), InboxEntry { group_id: req.group_id.clone(), start_seq: seq + 1, welcome: w.clone() }));
                }
            }
        }
        let delivery = Delivery { group_id: req.group_id.clone(), seq, sender: me.clone(), kind: header.kind, epoch: header.epoch, msg_id: req.msg_id.clone(), payload: req.payload };
        let inbox_seqs: Vec<(ClientId, u64)> = welcomes.iter().map(|(w, _)| Ok((w.clone(), self.store.inbox_next(w)?))).collect::<anyhow::Result<_>>()?;
        self.store.accept(Accept { delivery: &delivery, meta: &next, dedupe: self.config.idempotent, welcomes: welcomes.clone() })?;
        *meta = next;
        self.stats.accepted.fetch_add(1, Ordering::Relaxed);

        reply(ServerMsg::Accepted { req_id: req.req_id, msg_id: req.msg_id.clone(), seq, epoch: meta.epoch, duplicate: false });
        let out = ServerMsg::Deliver(delivery);
        for r in &recipients {
            self.push(r, &out);
            self.stats.delivered.fetch_add(1, Ordering::Relaxed);
        }
        for ((who, e), (_, inbox_seq)) in welcomes.into_iter().zip(inbox_seqs) {
            self.push(&who, &ServerMsg::Welcome { inbox_seq, group_id: e.group_id, start_seq: e.start_seq, welcome: e.welcome });
        }
        Ok(())
    }

    /// Baseline: fan out immediately with no ordering across senders.
    async fn relay(&self, me: &ClientId, req: SendReq, header: Header, g: Arc<tokio::sync::Mutex<GroupMeta>>, tx: &Tx) -> anyhow::Result<()> {
        let (seq, recipients) = {
            let mut meta = g.lock().await;
            let seq = meta.next_seq;
            meta.next_seq += 1;
            let recipients = meta.members.clone();
            if header.kind == Kind::Commit {
                meta.members.retain(|m| !req.remove_members.contains(m));
                for a in &req.add_members {
                    if !meta.members.contains(a) {
                        meta.members.push(a.clone());
                    }
                }
            }
            (seq, recipients)
        };
        let _ = tx.send(ServerMsg::Accepted { req_id: req.req_id, msg_id: req.msg_id.clone(), seq, epoch: header.epoch, duplicate: false }.to_bytes());
        let d = Delivery { group_id: req.group_id.clone(), seq, sender: me.clone(), kind: header.kind, epoch: header.epoch, msg_id: req.msg_id, payload: req.payload };
        let bytes = ServerMsg::Deliver(d).to_bytes();
        let conns: Vec<Tx> = {
            let c = self.conns.lock().unwrap();
            recipients.iter().filter_map(|r| c.get(r)).flatten().map(|(_, t)| t.clone()).collect()
        };
        for t in conns {
            let b = bytes.clone();
            // Independent fan-out workers: delivery order across senders is not fixed.
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                let _ = t.send(b);
            });
        }
        if let Some(w) = req.welcome {
            for a in &req.add_members {
                self.push(a, &ServerMsg::Welcome { inbox_seq: 0, group_id: req.group_id.clone(), start_seq: seq + 1, welcome: w.clone() });
            }
        }
        Ok(())
    }
}
