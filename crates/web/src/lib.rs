//! Browser client: the same MLS library compiled to WebAssembly, speaking the
//! delivery-service protocol. JavaScript owns the WebSocket; this crate turns
//! incoming frames into events and user actions into outgoing frames.

use mls::group::{create_key_package, CommitOptions, Group, GroupConfig, KeyPackageBundle, Processed, PskStore, Signer};
use mls::messages::{MlsMessage, Node, Proposal};
use mls::{CipherSuite, Codec};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use wasm_bindgen::prelude::*;
use wire::*;

#[derive(Clone, Debug)]
enum Intent {
    Add(GroupId, Vec<ClientId>),
    Remove(GroupId, ClientId),
    Rotate(GroupId),
}

struct GroupState {
    group: Group,
    next_seq: u64,
    buffer: BTreeMap<u64, Delivery>,
    removed: bool,
    /// Nodes re-keyed by the last commit, for the tree view.
    last_rekeyed: Vec<u32>,
}

#[wasm_bindgen]
pub struct WebClient {
    id: ClientId,
    cs: CipherSuite,
    signer: Signer,
    kpbs: HashMap<Vec<u8>, KeyPackageBundle>,
    groups: HashMap<GroupId, GroupState>,
    next_req: u64,
    /// Requests waiting for a key package reply: req_id -> (intent, key packages so far).
    kp_waits: HashMap<u64, (Intent, usize)>,
    collected: HashMap<u64, Vec<mls::messages::KeyPackage>>,
    /// Commit requests in flight: msg_id -> intent, so a lost race can be retried.
    commits: HashMap<MsgId, Intent>,
    retry: Vec<Intent>,
    out: Vec<Vec<u8>>,
    events: Vec<Value>,
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[wasm_bindgen]
impl WebClient {
    #[wasm_bindgen(constructor)]
    pub fn new(id: &str) -> WebClient {
        let cs = CipherSuite(1);
        WebClient {
            id: id.as_bytes().to_vec(),
            cs,
            signer: Signer::generate(cs, id.as_bytes()),
            kpbs: HashMap::new(),
            groups: HashMap::new(),
            next_req: 1,
            kp_waits: HashMap::new(),
            collected: HashMap::new(),
            commits: HashMap::new(),
            retry: vec![],
            out: vec![],
            events: vec![],
        }
    }

    fn emit(&mut self, v: Value) {
        self.events.push(v);
    }

    fn send(&mut self, m: ClientMsg) {
        self.out.push(m.to_bytes());
    }

    /// Frames to put on the WebSocket, in order.
    pub fn take_outgoing(&mut self) -> js_sys::Array {
        let a = js_sys::Array::new();
        for f in self.out.drain(..) {
            a.push(&js_sys::Uint8Array::from(f.as_slice()));
        }
        a
    }

    /// Events since the last call, as a JSON array.
    pub fn take_events(&mut self) -> String {
        let v = Value::Array(std::mem::take(&mut self.events));
        v.to_string()
    }

    /// Call on every (re)connect.
    pub fn hello(&mut self) {
        self.send(ClientMsg::Hello { client_id: self.id.clone() });
        let fetches: Vec<(GroupId, u64)> = self.groups.iter().filter(|(_, s)| !s.removed).map(|(g, s)| (g.clone(), s.next_seq)).collect();
        for (g, from) in fetches {
            self.send(ClientMsg::Fetch { group_id: g, from_seq: from });
        }
        self.send(ClientMsg::FetchInbox { from_seq: 0 });
    }

    pub fn publish_key_packages(&mut self, n: u32) {
        for _ in 0..n {
            let kpb = create_key_package(self.cs, &self.signer).expect("key package");
            let bytes = MlsMessage::KeyPackage(kpb.key_package.clone()).to_bytes();
            self.kpbs.insert(kpb.key_package.reference(), kpb);
            self.send(ClientMsg::PublishKeyPackage { key_package: bytes });
        }
    }

    pub fn create_group(&mut self, name: &str) {
        let gid = name.as_bytes().to_vec();
        let g = Group::create(self.cs, self.signer.clone(), gid.clone(), vec![], GroupConfig::default()).expect("create");
        self.groups.insert(gid.clone(), GroupState { group: g, next_seq: 0, buffer: BTreeMap::new(), removed: false, last_rekeyed: vec![0] });
        self.next_req += 1;
        self.send(ClientMsg::CreateGroup { req_id: self.next_req, group_id: gid });
        self.emit(json!({"type": "joined", "group": name}));
    }

    /// Invite devices (comma-separated ids): fetch their key packages, then commit.
    pub fn invite(&mut self, group: &str, who: &str) {
        let ids: Vec<ClientId> = who.split(',').map(|s| s.trim().as_bytes().to_vec()).filter(|s| !s.is_empty()).collect();
        self.start(Intent::Add(group.as_bytes().to_vec(), ids));
    }

    pub fn remove(&mut self, group: &str, who: &str) {
        self.start(Intent::Remove(group.as_bytes().to_vec(), who.as_bytes().to_vec()));
    }

    /// Empty commit with a fresh path: rotates this member's keys up to the root.
    pub fn rotate(&mut self, group: &str) {
        self.start(Intent::Rotate(group.as_bytes().to_vec()));
    }

    fn start(&mut self, intent: Intent) {
        match &intent {
            Intent::Add(_, ids) => {
                self.next_req += 1;
                let req = self.next_req;
                self.kp_waits.insert(req, (intent.clone(), ids.len()));
                self.collected.insert(req, vec![]);
                for (i, id) in ids.iter().enumerate() {
                    // One request id per key package, offset so replies can be matched.
                    let r = req * 1000 + i as u64;
                    self.send(ClientMsg::FetchKeyPackage { req_id: r, client_id: id.clone() });
                }
            }
            _ => self.commit_intent(intent, vec![]),
        }
    }

    fn commit_intent(&mut self, intent: Intent, kps: Vec<mls::messages::KeyPackage>) {
        let (gid, props, add, remove) = match &intent {
            Intent::Add(g, ids) => (g.clone(), kps.into_iter().map(Proposal::Add).collect::<Vec<_>>(), ids.clone(), vec![]),
            Intent::Remove(g, who) => {
                let Some(st) = self.groups.get(g) else { return };
                let leaves: Vec<Proposal> = st.group.member_identities().into_iter().filter(|(_, id)| id == who).map(|(l, _)| Proposal::Remove(l)).collect();
                (g.clone(), leaves, vec![], vec![who.clone()])
            }
            Intent::Rotate(g) => (g.clone(), vec![], vec![], vec![]),
        };
        let Some(st) = self.groups.get_mut(&gid) else { return };
        if st.group.has_pending_commit() {
            self.retry.push(intent);
            return;
        }
        match st.group.commit(props, CommitOptions { force_path: true, ..Default::default() }) {
            Ok(out) => {
                let msg_id = mls::crypto::random_bytes(16);
                self.commits.insert(msg_id.clone(), intent);
                self.next_req += 1;
                let req = SendReq {
                    req_id: self.next_req,
                    group_id: gid,
                    msg_id,
                    payload: out.commit.to_bytes(),
                    add_members: add,
                    remove_members: remove,
                    welcome: out.welcome.map(|w| w.to_bytes()),
                };
                self.send(ClientMsg::Send(req));
            }
            Err(e) => self.emit(json!({"type": "error", "error": e.to_string()})),
        }
    }

    pub fn send_text(&mut self, group: &str, text: &str) {
        let gid = group.as_bytes().to_vec();
        let Some(st) = self.groups.get_mut(&gid) else { return };
        match st.group.encrypt_application(text.as_bytes(), b"") {
            Ok(m) => {
                let bytes = m.to_bytes();
                let size = bytes.len();
                self.next_req += 1;
                let req = SendReq { req_id: self.next_req, group_id: gid, msg_id: mls::crypto::random_bytes(16), payload: bytes, add_members: vec![], remove_members: vec![], welcome: None };
                self.send(ClientMsg::Send(req));
                self.emit(json!({"type": "sent", "group": group, "text": text, "bytes": size}));
            }
            Err(e) => self.emit(json!({"type": "error", "error": e.to_string()})),
        }
    }

    /// Handle one frame from the server.
    pub fn on_frame(&mut self, frame: &[u8]) {
        let Ok(m) = ServerMsg::from_bytes(frame) else {
            self.emit(json!({"type": "error", "error": "bad frame"}));
            return;
        };
        match m {
            ServerMsg::KeyPackage { req_id, key_package } => {
                let base = req_id / 1000;
                if let (Some(kp), Some(list)) = (key_package, self.collected.get_mut(&base)) {
                    if let Ok(MlsMessage::KeyPackage(k)) = MlsMessage::from_bytes(&kp) {
                        list.push(k);
                    }
                } else if key_package_missing(&self.kp_waits, base) {
                    self.emit(json!({"type": "error", "error": "no key package published for that device"}));
                }
                if let Some((intent, need)) = self.kp_waits.get(&base).cloned() {
                    if self.collected.get(&base).map(|l| l.len()) == Some(need) {
                        self.kp_waits.remove(&base);
                        let kps = self.collected.remove(&base).unwrap();
                        self.commit_intent(intent, kps);
                    }
                }
            }
            ServerMsg::Accepted { msg_id, seq, duplicate, .. } => {
                if self.commits.remove(&msg_id).is_some() {
                    self.emit(json!({"type": "commit_accepted", "seq": seq, "duplicate": duplicate}));
                }
            }
            ServerMsg::Rejected { msg_id, code, current_epoch, .. } => {
                if let Some(intent) = self.commits.remove(&msg_id) {
                    let gid = match &intent {
                        Intent::Add(g, _) | Intent::Remove(g, _) | Intent::Rotate(g) => g.clone(),
                    };
                    if let Some(st) = self.groups.get_mut(&gid) {
                        st.group.clear_pending_commit();
                    }
                    self.emit(json!({"type": "commit_rejected", "code": format!("{code:?}"), "server_epoch": current_epoch,
                        "note": "another member's commit won this epoch; retrying after catching up"}));
                    if code == RejectCode::StaleEpoch {
                        self.retry.push(intent);
                    }
                }
            }
            ServerMsg::Deliver(d) => self.on_delivery(d),
            ServerMsg::Welcome { group_id, start_seq, welcome, .. } => self.on_welcome(group_id, start_seq, &welcome),
            _ => {}
        }
        self.run_retries();
    }

    fn run_retries(&mut self) {
        let pending: Vec<Intent> = std::mem::take(&mut self.retry);
        for intent in pending {
            let gid = match &intent {
                Intent::Add(g, _) | Intent::Remove(g, _) | Intent::Rotate(g) => g.clone(),
            };
            let busy = self.groups.get(&gid).map(|s| s.group.has_pending_commit()).unwrap_or(true);
            let in_flight = self.commits.values().any(|i| matches!((i, &intent), (Intent::Rotate(a), Intent::Rotate(b)) if a == b));
            if busy || in_flight {
                self.retry.push(intent);
            } else {
                self.start(intent);
            }
        }
    }

    fn on_welcome(&mut self, gid: GroupId, start_seq: u64, welcome: &[u8]) {
        if self.groups.contains_key(&gid) {
            return;
        }
        let Ok(MlsMessage::Welcome(w)) = MlsMessage::from_bytes(welcome) else { return };
        let Some(kpb) = w.secrets.iter().find_map(|s| self.kpbs.get(&s.new_member)).cloned() else { return };
        match Group::join(&w, &kpb, None, PskStore::default(), GroupConfig::default()) {
            Ok(g) => {
                self.kpbs.remove(&kpb.key_package.reference());
                self.groups.insert(gid.clone(), GroupState { group: g, next_seq: start_seq, buffer: BTreeMap::new(), removed: false, last_rekeyed: vec![] });
                self.send(ClientMsg::Fetch { group_id: gid.clone(), from_seq: start_seq });
                self.emit(json!({"type": "joined", "group": String::from_utf8_lossy(&gid), "welcome_bytes": welcome.len()}));
                // Keep one key package available for the next invite.
                self.publish_key_packages(1);
            }
            Err(e) => self.emit(json!({"type": "error", "error": format!("join: {e}")})),
        }
    }

    fn on_delivery(&mut self, d: Delivery) {
        let gid = d.group_id.clone();
        let Some(st) = self.groups.get_mut(&gid) else { return };
        if d.seq < st.next_seq {
            return;
        }
        st.buffer.insert(d.seq, d);
        let mut evs = vec![];
        while let Some(next) = st.buffer.remove(&st.next_seq) {
            st.next_seq += 1;
            apply(&self.id, st, next, &mut evs);
        }
        self.events.extend(evs);
    }

    /// JSON snapshot of every group, including the ratchet tree for the tree view.
    pub fn state(&self) -> String {
        let mut groups = vec![];
        for (gid, st) in &self.groups {
            let g = &st.group;
            let t = g.tree();
            let n = t.n_leaves();
            let mut nodes = vec![];
            for x in 0..(2 * n - 1) {
                let kind = if x % 2 == 0 { "leaf" } else { "parent" };
                let (filled, label, key) = match t.node(x) {
                    Some(Node::Leaf(l)) => (true, String::from_utf8_lossy(l.credential.identity()).to_string(), hexs(&l.encryption_key[..4])),
                    Some(Node::Parent(p)) => (true, String::new(), hexs(&p.encryption_key[..4])),
                    None => (false, String::new(), String::new()),
                };
                let mine = g.private_state().keys.contains_key(&x);
                nodes.push(json!({"index": x, "kind": kind, "filled": filled, "label": label, "key": key, "known": mine, "rekeyed": st.last_rekeyed.contains(&x)}));
            }
            groups.push(json!({
                "group": String::from_utf8_lossy(gid), "epoch": g.epoch(), "removed": st.removed,
                "epoch_authenticator": hexs(&g.epoch_authenticator()[..6]),
                "members": g.member_identities().into_iter().map(|(l, id)| json!({"leaf": l, "id": String::from_utf8_lossy(&id)})).collect::<Vec<_>>(),
                "own_leaf": g.own_leaf(), "n_leaves": n, "nodes": nodes, "log_position": st.next_seq,
            }));
        }
        json!({"id": String::from_utf8_lossy(&self.id), "groups": groups}).to_string()
    }
}

fn key_package_missing(waits: &HashMap<u64, (Intent, usize)>, base: u64) -> bool {
    waits.contains_key(&base)
}

fn apply(me: &[u8], st: &mut GroupState, d: Delivery, evs: &mut Vec<Value>) {
    if st.removed {
        return;
    }
    let Ok(msg) = MlsMessage::from_bytes(&d.payload) else { return };
    let group = String::from_utf8_lossy(&d.group_id).to_string();
    let sender = String::from_utf8_lossy(&d.sender).to_string();
    if d.sender == me && d.kind != Kind::Commit {
        return;
    }
    if d.sender == me && !st.group.has_pending_commit() && st.group.epoch() > d.epoch {
        return;
    }
    let before: Vec<Option<Vec<u8>>> = (0..(2 * st.group.tree().n_leaves() - 1)).map(|x| st.group.tree().node(x).map(|n| n.encryption_key().to_vec())).collect();
    match st.group.process(&msg) {
        Ok(Processed::Application { data, epoch, .. }) => {
            evs.push(json!({"type": "message", "group": group, "from": sender, "text": String::from_utf8_lossy(&data), "epoch": epoch, "seq": d.seq, "bytes": d.payload.len()}));
        }
        Ok(Processed::Commit(s)) => {
            if s.self_removed {
                st.removed = true;
                evs.push(json!({"type": "removed", "group": group, "by": sender}));
                return;
            }
            evs.push(json!({"type": "commit", "group": group, "from": sender, "epoch": s.new_epoch, "added": s.added, "removed": s.removed, "bytes": d.payload.len()}));
        }
        Ok(Processed::OwnCommitMerged) => {
            evs.push(json!({"type": "commit", "group": group, "from": sender, "epoch": st.group.epoch(), "own": true, "bytes": d.payload.len()}));
        }
        Ok(Processed::Proposal { .. }) => {}
        Err(e) => evs.push(json!({"type": "error", "group": group, "seq": d.seq, "error": e.to_string()})),
    }
    let t = st.group.tree();
    st.last_rekeyed = (0..(2 * t.n_leaves() - 1))
        .filter(|x| {
            let now = t.node(*x).map(|n| n.encryption_key().to_vec());
            now.is_some() && before.get(*x as usize).cloned().flatten() != now
        })
        .collect();
}
