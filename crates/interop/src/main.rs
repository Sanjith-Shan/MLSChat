//! MLSChat behind the `mlswg/mls-implementations` interop harness: a gRPC
//! server implementing the MLSClient service, driven by the official Go
//! test-runner alongside other implementations' clients.
//!
//! Usage: mlschat-interop [--port 50052]

use mls::group::*;
use mls::messages::*;
use mls::tree::RatchetTree;
use mls::{CipherSuite, Codec};
use mls_interop_proto::mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_interop_proto::mls_client::*;
use std::collections::HashMap;
use std::sync::Mutex;
use tonic::{Request, Response, Status};

struct Entry {
    group: Group,
    /// Proposal messages we sent, by bytes, with their references.
    own: HashMap<Vec<u8>, ProposalRef>,
}

#[derive(Default)]
struct State {
    next_id: u32,
    groups: HashMap<u32, Entry>,
    txs: HashMap<u32, (KeyPackageBundle, PskStore)>,
    signers: HashMap<u32, (CipherSuite, Signer)>,
}

impl State {
    fn id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }
}

#[derive(Default)]
struct Server {
    st: Mutex<State>,
}

fn err<E: std::fmt::Display>(e: E) -> Status {
    Status::aborted(e.to_string())
}

fn config(encrypt: bool) -> GroupConfig {
    GroupConfig { encrypt_handshake: encrypt, ratchet_tree_extension: true, external_pub_extension: true, max_past_epochs: 2, ..Default::default() }
}

fn suite(cs: u32) -> Result<CipherSuite, Status> {
    let c = CipherSuite(cs as u16);
    if !c.is_supported() {
        return Err(Status::invalid_argument("unsupported cipher suite"));
    }
    Ok(c)
}

fn tree_opt(cs: CipherSuite, b: &[u8]) -> Result<Option<RatchetTree>, Status> {
    if b.is_empty() {
        Ok(None)
    } else {
        Ok(Some(RatchetTree::from_bytes(cs, b).map_err(err)?))
    }
}

fn leaf_of(g: &Group, identity: &[u8]) -> Result<u32, Status> {
    g.member_identities().into_iter().find(|(_, id)| id == identity).map(|(l, _)| l).ok_or_else(|| Status::invalid_argument("no member with that identity"))
}

fn exts(v: &[mls_interop_proto::mls_client::Extension]) -> Vec<mls::messages::Extension> {
    v.iter().map(|e| mls::messages::Extension { extension_type: e.extension_type as u16, extension_data: e.extension_data.clone() }).collect()
}

fn psk_id_external(cs: CipherSuite, id: &[u8]) -> PreSharedKeyId {
    PreSharedKeyId { psk: Psk::External { psk_id: id.to_vec() }, psk_nonce: mls::crypto::random_bytes(cs.nh()) }
}

/// Turn a by-value proposal description into a proposal.
fn by_value(g: &Group, d: &ProposalDescription) -> Result<Proposal, Status> {
    match String::from_utf8_lossy(&d.proposal_type).as_ref() {
        "add" => match MlsMessage::from_bytes(&d.key_package).map_err(err)? {
            MlsMessage::KeyPackage(kp) => Ok(Proposal::Add(kp)),
            _ => Err(Status::invalid_argument("not a key package")),
        },
        "remove" => Ok(Proposal::Remove(leaf_of(g, &d.removed_id)?)),
        "externalPSK" => Ok(Proposal::PreSharedKey(psk_id_external(g.cs, &d.psk_id))),
        "resumptionPSK" => Ok(Proposal::PreSharedKey(g.resumption_psk_id(d.epoch_id))),
        "groupContextExtensions" => Ok(Proposal::GroupContextExtensions(exts(&d.extensions))),
        other => Err(Status::unimplemented(format!("by-value proposal type {other}"))),
    }
}

/// Process proposal messages given by reference; returns their references.
fn take_proposals(e: &mut Entry, msgs: &[Vec<u8>]) -> Result<Vec<ProposalRef>, Status> {
    let mut refs = vec![];
    for b in msgs {
        if let Some(r) = e.own.get(b) {
            refs.push(r.clone());
            continue;
        }
        let m = MlsMessage::from_bytes(b).map_err(err)?;
        match e.group.process(&m).map_err(err)? {
            Processed::Proposal { reference, .. } => refs.push(reference),
            _ => return Err(Status::invalid_argument("not a proposal")),
        }
    }
    Ok(refs)
}

macro_rules! entry {
    ($st:expr, $id:expr) => {
        $st.groups.get_mut(&$id).ok_or_else(|| Status::invalid_argument("unknown state_id"))?
    };
}

type R<T> = Result<Response<T>, Status>;

#[tonic::async_trait]
impl MlsClient for Server {
    async fn name(&self, _: Request<NameRequest>) -> R<NameResponse> {
        Ok(Response::new(NameResponse { name: "MLSChat".into() }))
    }

    async fn supported_ciphersuites(&self, _: Request<SupportedCiphersuitesRequest>) -> R<SupportedCiphersuitesResponse> {
        Ok(Response::new(SupportedCiphersuitesResponse { ciphersuites: mls::crypto::SUPPORTED_SUITES.iter().map(|s| *s as u32).collect() }))
    }

    async fn create_group(&self, r: Request<CreateGroupRequest>) -> R<CreateGroupResponse> {
        let r = r.into_inner();
        let cs = suite(r.cipher_suite)?;
        let g = Group::create(cs, Signer::generate(cs, &r.identity), r.group_id, vec![], config(r.encrypt_handshake)).map_err(err)?;
        let mut st = self.st.lock().unwrap();
        let id = st.id();
        st.groups.insert(id, Entry { group: g, own: HashMap::new() });
        Ok(Response::new(CreateGroupResponse { state_id: id }))
    }

    async fn create_key_package(&self, r: Request<CreateKeyPackageRequest>) -> R<CreateKeyPackageResponse> {
        let r = r.into_inner();
        let cs = suite(r.cipher_suite)?;
        let kpb = create_key_package(cs, &Signer::generate(cs, &r.identity)).map_err(err)?;
        let resp = CreateKeyPackageResponse {
            transaction_id: 0,
            key_package: MlsMessage::KeyPackage(kpb.key_package.clone()).to_bytes(),
            init_priv: kpb.init_priv.clone(),
            encryption_priv: kpb.encryption_priv.clone(),
            signature_priv: kpb.signer.signature_priv.clone(),
        };
        let mut st = self.st.lock().unwrap();
        let id = st.id();
        st.txs.insert(id, (kpb, PskStore::default()));
        Ok(Response::new(CreateKeyPackageResponse { transaction_id: id, ..resp }))
    }

    async fn join_group(&self, r: Request<JoinGroupRequest>) -> R<JoinGroupResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let (kpb, psks) = st.txs.get(&r.transaction_id).cloned().ok_or_else(|| Status::invalid_argument("unknown transaction"))?;
        let MlsMessage::Welcome(w) = MlsMessage::from_bytes(&r.welcome).map_err(err)? else { return Err(Status::invalid_argument("not a welcome")) };
        let tree = tree_opt(kpb.key_package.cipher_suite, &r.ratchet_tree)?;
        let g = Group::join(&w, &kpb, tree, psks, config(r.encrypt_handshake)).map_err(err)?;
        let ea = g.epoch_authenticator().to_vec();
        let id = st.id();
        st.groups.insert(id, Entry { group: g, own: HashMap::new() });
        Ok(Response::new(JoinGroupResponse { state_id: id, epoch_authenticator: ea }))
    }

    async fn external_join(&self, r: Request<ExternalJoinRequest>) -> R<ExternalJoinResponse> {
        let r = r.into_inner();
        let MlsMessage::GroupInfo(gi) = MlsMessage::from_bytes(&r.group_info).map_err(err)? else { return Err(Status::invalid_argument("not a group info")) };
        let cs = gi.group_context.cipher_suite;
        let tree = tree_opt(cs, &r.ratchet_tree)?;
        let prior = if r.remove_prior {
            let t = match &tree {
                Some(t) => t.clone(),
                None => RatchetTree::from_bytes(cs, &find_extension(&gi.extensions, ext_type::RATCHET_TREE).ok_or_else(|| Status::invalid_argument("no tree"))?.extension_data).map_err(err)?,
            };
            t.find_leaf(|l| l.credential.identity() == r.identity.as_slice())
        } else {
            None
        };
        let mut store = PskStore::default();
        let mut ids = vec![];
        for p in &r.psks {
            store.external.insert(p.psk_id.clone(), p.psk_secret.clone());
            ids.push(psk_id_external(cs, &p.psk_id));
        }
        let (g, commit) = Group::join_external_with_psks(&gi, tree, Signer::generate(cs, &r.identity), prior, ids, store, config(r.encrypt_handshake)).map_err(err)?;
        let ea = g.epoch_authenticator().to_vec();
        let mut st = self.st.lock().unwrap();
        let id = st.id();
        st.groups.insert(id, Entry { group: g, own: HashMap::new() });
        Ok(Response::new(ExternalJoinResponse { state_id: id, commit: commit.to_bytes(), epoch_authenticator: ea }))
    }

    async fn group_info(&self, r: Request<GroupInfoRequest>) -> R<GroupInfoResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        let gi = e.group.group_info(!r.external_tree, true).map_err(err)?;
        let tree = if r.external_tree { e.group.tree().to_bytes() } else { vec![] };
        Ok(Response::new(GroupInfoResponse { group_info: MlsMessage::GroupInfo(gi).to_bytes(), ratchet_tree: tree }))
    }

    async fn state_auth(&self, r: Request<StateAuthRequest>) -> R<StateAuthResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        Ok(Response::new(StateAuthResponse { state_auth_secret: e.group.epoch_authenticator().to_vec() }))
    }

    async fn export(&self, r: Request<ExportRequest>) -> R<ExportResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        let s = e.group.export_secret(&r.label, &r.context, r.key_length as usize).map_err(err)?;
        Ok(Response::new(ExportResponse { exported_secret: s }))
    }

    async fn protect(&self, r: Request<ProtectRequest>) -> R<ProtectResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        let m = e.group.encrypt_application(&r.plaintext, &r.authenticated_data).map_err(err)?;
        Ok(Response::new(ProtectResponse { ciphertext: m.to_bytes() }))
    }

    async fn unprotect(&self, r: Request<UnprotectRequest>) -> R<UnprotectResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        let m = MlsMessage::from_bytes(&r.ciphertext).map_err(err)?;
        match e.group.process(&m).map_err(err)? {
            Processed::Application { data, authenticated_data, .. } => Ok(Response::new(UnprotectResponse { authenticated_data, plaintext: data })),
            _ => Err(Status::invalid_argument("not an application message")),
        }
    }

    async fn store_psk(&self, r: Request<StorePskRequest>) -> R<StorePskResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let id = r.state_or_transaction_id;
        if let Some(e) = st.groups.get_mut(&id) {
            e.group.psks.external.insert(r.psk_id, r.psk_secret);
        } else if let Some((_, p)) = st.txs.get_mut(&id) {
            p.external.insert(r.psk_id, r.psk_secret);
        } else {
            return Err(Status::invalid_argument("unknown state or transaction"));
        }
        Ok(Response::new(StorePskResponse {}))
    }

    async fn add_proposal(&self, r: Request<AddProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        let MlsMessage::KeyPackage(kp) = MlsMessage::from_bytes(&r.key_package).map_err(err)? else { return Err(Status::invalid_argument("not a key package")) };
        self.propose(r.state_id, |_| Ok(Proposal::Add(kp)))
    }

    async fn update_proposal(&self, r: Request<UpdateProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        let (m, rf) = e.group.propose_update().map_err(err)?;
        let b = m.to_bytes();
        e.own.insert(b.clone(), rf);
        Ok(Response::new(ProposalResponse { proposal: b }))
    }

    async fn remove_proposal(&self, r: Request<RemoveProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        self.propose(r.state_id, |g| Ok(Proposal::Remove(leaf_of(g, &r.removed_id)?)))
    }

    async fn external_psk_proposal(&self, r: Request<ExternalPskProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        self.propose(r.state_id, |g| Ok(Proposal::PreSharedKey(psk_id_external(g.cs, &r.psk_id))))
    }

    async fn resumption_psk_proposal(&self, r: Request<ResumptionPskProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        self.propose(r.state_id, |g| Ok(Proposal::PreSharedKey(g.resumption_psk_id(r.epoch_id))))
    }

    async fn group_context_extensions_proposal(&self, r: Request<GroupContextExtensionsProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        self.propose(r.state_id, |_| Ok(Proposal::GroupContextExtensions(exts(&r.extensions))))
    }

    async fn commit(&self, r: Request<CommitRequest>) -> R<CommitResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        let refs = take_proposals(e, &r.by_reference)?;
        let mut extra = vec![];
        for d in &r.by_value {
            extra.push(by_value(&e.group, d)?);
        }
        e.group.config.ratchet_tree_extension = !r.external_tree;
        let out = e.group.commit(extra, CommitOptions { force_path: r.force_path, by_reference: Some(refs), ..Default::default() }).map_err(err)?;
        e.group.config.ratchet_tree_extension = true;
        let tree = if r.external_tree { e.group.pending_state().map(|g| g.tree().to_bytes()).unwrap_or_default() } else { vec![] };
        if let Some(p) = e.group.pending_state() {
            // The staged state should keep including the tree for later GroupInfos.
            let _ = p;
        }
        Ok(Response::new(CommitResponse { commit: out.commit.to_bytes(), welcome: out.welcome.map(|w| w.to_bytes()).unwrap_or_default(), ratchet_tree: tree }))
    }

    async fn handle_commit(&self, r: Request<HandleCommitRequest>) -> R<HandleCommitResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        take_proposals(e, &r.proposal)?;
        let m = MlsMessage::from_bytes(&r.commit).map_err(err)?;
        e.group.process(&m).map_err(err)?;
        e.own.clear();
        Ok(Response::new(HandleCommitResponse { state_id: r.state_id, epoch_authenticator: e.group.epoch_authenticator().to_vec() }))
    }

    async fn handle_pending_commit(&self, r: Request<HandlePendingCommitRequest>) -> R<HandleCommitResponse> {
        let r = r.into_inner();
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, r.state_id);
        e.group.merge_pending_commit().map_err(err)?;
        e.group.config.ratchet_tree_extension = true;
        e.own.clear();
        Ok(Response::new(HandleCommitResponse { state_id: r.state_id, epoch_authenticator: e.group.epoch_authenticator().to_vec() }))
    }

    async fn re_init_proposal(&self, _: Request<ReInitProposalRequest>) -> R<ProposalResponse> {
        Err(Status::unimplemented("reinit is not implemented in MLSChat"))
    }
    async fn re_init_commit(&self, _: Request<CommitRequest>) -> R<CommitResponse> {
        Err(Status::unimplemented("reinit is not implemented in MLSChat"))
    }
    async fn handle_pending_re_init_commit(&self, _: Request<HandlePendingCommitRequest>) -> R<HandleReInitCommitResponse> {
        Err(Status::unimplemented("reinit is not implemented in MLSChat"))
    }
    async fn handle_re_init_commit(&self, _: Request<HandleCommitRequest>) -> R<HandleReInitCommitResponse> {
        Err(Status::unimplemented("reinit is not implemented in MLSChat"))
    }
    async fn re_init_welcome(&self, _: Request<ReInitWelcomeRequest>) -> R<CreateSubgroupResponse> {
        Err(Status::unimplemented("reinit is not implemented in MLSChat"))
    }
    async fn handle_re_init_welcome(&self, _: Request<HandleReInitWelcomeRequest>) -> R<JoinGroupResponse> {
        Err(Status::unimplemented("reinit is not implemented in MLSChat"))
    }
    async fn create_branch(&self, _: Request<CreateBranchRequest>) -> R<CreateSubgroupResponse> {
        Err(Status::unimplemented("branch is not implemented in MLSChat"))
    }
    async fn handle_branch(&self, _: Request<HandleBranchRequest>) -> R<HandleBranchResponse> {
        Err(Status::unimplemented("branch is not implemented in MLSChat"))
    }

    async fn new_member_add_proposal(&self, r: Request<NewMemberAddProposalRequest>) -> R<NewMemberAddProposalResponse> {
        let r = r.into_inner();
        let MlsMessage::GroupInfo(gi) = MlsMessage::from_bytes(&r.group_info).map_err(err)? else { return Err(Status::invalid_argument("not a group info")) };
        let cs = gi.group_context.cipher_suite;
        let kpb = create_key_package(cs, &Signer::generate(cs, &r.identity)).map_err(err)?;
        let m = new_member_add_proposal(&gi.group_context, &kpb).map_err(err)?;
        let resp = NewMemberAddProposalResponse {
            transaction_id: 0,
            proposal: m.to_bytes(),
            init_priv: kpb.init_priv.clone(),
            encryption_priv: kpb.encryption_priv.clone(),
            signature_priv: kpb.signer.signature_priv.clone(),
        };
        let mut st = self.st.lock().unwrap();
        let id = st.id();
        st.txs.insert(id, (kpb, PskStore::default()));
        Ok(Response::new(NewMemberAddProposalResponse { transaction_id: id, ..resp }))
    }

    async fn create_external_signer(&self, r: Request<CreateExternalSignerRequest>) -> R<CreateExternalSignerResponse> {
        let r = r.into_inner();
        let cs = suite(r.cipher_suite)?;
        let s = Signer::generate(cs, &r.identity);
        let es = ExternalSender { signature_key: s.signature_pub.clone(), credential: s.credential.clone() };
        let mut st = self.st.lock().unwrap();
        let id = st.id();
        st.signers.insert(id, (cs, s));
        Ok(Response::new(CreateExternalSignerResponse { signer_id: id, external_sender: es.to_bytes() }))
    }

    async fn add_external_signer(&self, r: Request<AddExternalSignerRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        let es = ExternalSender::from_bytes(&r.external_sender).map_err(err)?;
        self.propose(r.state_id, |g| {
            let mut list = match find_extension(&g.context().extensions, ext_type::EXTERNAL_SENDERS) {
                Some(e) => Vec::<ExternalSender>::from_bytes(&e.extension_data).map_err(err)?,
                None => vec![],
            };
            list.push(es.clone());
            let ext = mls::messages::Extension { extension_type: ext_type::EXTERNAL_SENDERS, extension_data: list.to_bytes() };
            Ok(Proposal::GroupContextExtensions(g.extensions_with(ext)))
        })
    }

    async fn external_signer_proposal(&self, r: Request<ExternalSignerProposalRequest>) -> R<ProposalResponse> {
        let r = r.into_inner();
        let MlsMessage::GroupInfo(gi) = MlsMessage::from_bytes(&r.group_info).map_err(err)? else { return Err(Status::invalid_argument("not a group info")) };
        let (cs, signer) = self.st.lock().unwrap().signers.get(&r.signer_id).cloned().ok_or_else(|| Status::invalid_argument("unknown signer"))?;
        let d = r.description.ok_or_else(|| Status::invalid_argument("no description"))?;
        let ctx = &gi.group_context;
        let tree = match tree_opt(cs, &r.ratchet_tree)? {
            Some(t) => t,
            None => RatchetTree::from_bytes(cs, &find_extension(&gi.extensions, ext_type::RATCHET_TREE).ok_or_else(|| Status::invalid_argument("no tree"))?.extension_data).map_err(err)?,
        };
        let p = match String::from_utf8_lossy(&d.proposal_type).as_ref() {
            "add" => match MlsMessage::from_bytes(&d.key_package).map_err(err)? {
                MlsMessage::KeyPackage(kp) => Proposal::Add(kp),
                _ => return Err(Status::invalid_argument("not a key package")),
            },
            "remove" => Proposal::Remove(tree.find_leaf(|l| l.credential.identity() == d.removed_id.as_slice()).ok_or_else(|| Status::invalid_argument("no such member"))?),
            "externalPSK" => Proposal::PreSharedKey(psk_id_external(cs, &d.psk_id)),
            "groupContextExtensions" => Proposal::GroupContextExtensions(exts(&d.extensions)),
            other => return Err(Status::unimplemented(format!("external {other} proposal"))),
        };
        let m = external_proposal(cs, ctx, r.signer_index, &signer.signature_priv, p).map_err(err)?;
        Ok(Response::new(ProposalResponse { proposal: m.to_bytes() }))
    }

    async fn free(&self, r: Request<FreeRequest>) -> R<FreeResponse> {
        let r = r.into_inner();
        self.st.lock().unwrap().groups.remove(&r.state_id);
        Ok(Response::new(FreeResponse {}))
    }
}

impl Server {
    fn propose(&self, state_id: u32, make: impl FnOnce(&Group) -> Result<Proposal, Status>) -> R<ProposalResponse> {
        let mut st = self.st.lock().unwrap();
        let e = entry!(st, state_id);
        let p = make(&e.group)?;
        let (m, rf) = e.group.propose(p).map_err(err)?;
        let b = m.to_bytes();
        e.own.insert(b.clone(), rf);
        Ok(Response::new(ProposalResponse { proposal: b }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut port = 50052u16;
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--port") {
        port = args[i + 1].parse()?;
    }
    let addr = format!("[::1]:{port}").parse()?;
    println!("mlschat-interop listening on {addr}");
    tonic::transport::Server::builder().add_service(MlsClientServer::new(Server::default())).serve(addr).await?;
    Ok(())
}
