//! Differential test against OpenMLS.
//!
//! A randomized session builds one group whose members are a random mix of
//! MLSChat and OpenMLS clients. Every message crosses the boundary as bytes.
//! After every epoch change, every member must hold the same epoch
//! authenticator and the same exported secret, and every application message
//! must decrypt to what was sent. Any disagreement fails the session.

use mls::group::{CommitOptions, Group, GroupConfig, KeyPackageBundle, Processed, PskStore, Signer};
use mls::messages::{MlsMessage, Proposal as MProposal};
use mls::{CipherSuite, Codec};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// Small deterministic PRNG so a failing session can be replayed from its seed.
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xD1B54A32D192ED03)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

pub enum Member {
    Ours { name: String, group: Group },
    Theirs { name: String, provider: OpenMlsRustCrypto, signer: SignatureKeyPair, group: MlsGroup },
}

/// A member that has published a key package but not joined yet.
pub enum Pending {
    Ours { name: String, kpb: KeyPackageBundle },
    Theirs { name: String, provider: OpenMlsRustCrypto, signer: SignatureKeyPair, kp: openmls::prelude::KeyPackageBundle },
}

fn their_cs(cs: CipherSuite) -> Ciphersuite {
    match cs.0 {
        1 => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        2 => Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        3 => Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        x => panic!("OpenMLS does not support suite {x}"),
    }
}

pub const OPENMLS_SUITES: [u16; 3] = [1, 2, 3];

fn their_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(2)
        .build()
}

fn our_config() -> GroupConfig {
    GroupConfig { ratchet_tree_extension: true, ..Default::default() }
}

pub fn new_pending(cs: CipherSuite, name: &str, ours: bool) -> Pending {
    if ours {
        let signer = Signer::generate(cs, name.as_bytes());
        Pending::Ours { name: name.into(), kpb: mls::group::create_key_package(cs, &signer).unwrap() }
    } else {
        let provider = OpenMlsRustCrypto::default();
        let tcs = their_cs(cs);
        let signer = SignatureKeyPair::new(tcs.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let cred = CredentialWithKey { credential: BasicCredential::new(name.as_bytes().to_vec()).into(), signature_key: signer.to_public_vec().into() };
        let kp = openmls::prelude::KeyPackage::builder().build(tcs, &provider, &signer, cred).unwrap();
        Pending::Theirs { name: name.into(), provider, signer, kp }
    }
}

impl Pending {
    pub fn key_package_bytes(&self) -> Vec<u8> {
        match self {
            Pending::Ours { kpb, .. } => kpb.key_package.to_bytes(),
            Pending::Theirs { kp, .. } => kp.key_package().tls_serialize_detached().unwrap(),
        }
    }
    pub fn name(&self) -> &str {
        match self {
            Pending::Ours { name, .. } | Pending::Theirs { name, .. } => name,
        }
    }
    pub fn join(self, welcome: &[u8]) -> Result<Member, String> {
        match self {
            Pending::Ours { name, kpb } => {
                let MlsMessage::Welcome(w) = MlsMessage::from_bytes(welcome).map_err(|e| e.to_string())? else { return Err("not welcome".into()) };
                let g = Group::join(&w, &kpb, None, PskStore::default(), our_config()).map_err(|e| format!("{name} join: {e}"))?;
                Ok(Member::Ours { name, group: g })
            }
            Pending::Theirs { name, provider, signer, kp: _ } => {
                let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| e.to_string())?;
                let MlsMessageBodyIn::Welcome(w) = msg.extract() else { return Err("not welcome".into()) };
                let staged = StagedWelcome::new_from_welcome(&provider, &their_join_config(), w, None).map_err(|e| format!("{name} staged join: {e:?}"))?;
                let group = staged.into_group(&provider).map_err(|e| format!("{name} join: {e:?}"))?;
                Ok(Member::Theirs { name, provider, signer, group })
            }
        }
    }
}

/// What a member produced for the others to process.
pub struct Outgoing {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

impl Member {
    pub fn name(&self) -> &str {
        match self {
            Member::Ours { name, .. } | Member::Theirs { name, .. } => name,
        }
    }
    pub fn is_ours(&self) -> bool {
        matches!(self, Member::Ours { .. })
    }

    pub fn create(cs: CipherSuite, name: &str, ours: bool) -> Member {
        if ours {
            let g = Group::create(cs, Signer::generate(cs, name.as_bytes()), b"differential".to_vec(), vec![], our_config()).unwrap();
            Member::Ours { name: name.into(), group: g }
        } else {
            let provider = OpenMlsRustCrypto::default();
            let tcs = their_cs(cs);
            let signer = SignatureKeyPair::new(tcs.signature_algorithm()).unwrap();
            signer.store(provider.storage()).unwrap();
            let cred = CredentialWithKey { credential: BasicCredential::new(name.as_bytes().to_vec()).into(), signature_key: signer.to_public_vec().into() };
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(tcs)
                .use_ratchet_tree_extension(true)
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .max_past_epochs(2)
                .build();
            let group = MlsGroup::new_with_group_id(&provider, &signer, &cfg, GroupId::from_slice(b"differential"), cred).unwrap();
            Member::Theirs { name: name.into(), provider, signer, group }
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            Member::Ours { group, .. } => group.epoch(),
            Member::Theirs { group, .. } => group.epoch().as_u64(),
        }
    }

    pub fn epoch_authenticator(&self) -> Vec<u8> {
        match self {
            Member::Ours { group, .. } => group.epoch_authenticator().to_vec(),
            Member::Theirs { group, .. } => group.epoch_authenticator().as_slice().to_vec(),
        }
    }

    pub fn exported(&self) -> Vec<u8> {
        match self {
            Member::Ours { group, .. } => group.export_secret("differential", b"ctx", 32).unwrap(),
            Member::Theirs { group, provider, .. } => group.export_secret(provider.crypto(), "differential", b"ctx", 32).unwrap(),
        }
    }

    /// Leaf index of the member with this identity.
    pub fn leaf_of(&self, identity: &str) -> Option<u32> {
        match self {
            Member::Ours { group, .. } => group.member_identities().into_iter().find(|(_, id)| id == identity.as_bytes()).map(|(l, _)| l),
            Member::Theirs { group, .. } => group.members().find(|m| m.credential.serialized_content() == identity.as_bytes()).map(|m| m.index.u32()),
        }
    }

    pub fn member_count(&self) -> usize {
        match self {
            Member::Ours { group, .. } => group.tree().member_count(),
            Member::Theirs { group, .. } => group.members().count(),
        }
    }

    /// Commit adds (key packages as bytes), removes (leaf indices), or nothing (path only).
    pub fn commit(&mut self, adds: &[Vec<u8>], removes: &[u32]) -> Result<Outgoing, String> {
        match self {
            Member::Ours { group, .. } => {
                let mut props = vec![];
                for kp in adds {
                    let kp = match MlsMessage::from_bytes(kp) {
                        Ok(MlsMessage::KeyPackage(k)) => k,
                        _ => mls::messages::KeyPackage::from_bytes(kp).map_err(|e| e.to_string())?,
                    };
                    props.push(MProposal::Add(kp));
                }
                for r in removes {
                    props.push(MProposal::Remove(*r));
                }
                let out = group.commit(props, CommitOptions { force_path: true, ..Default::default() }).map_err(|e| e.to_string())?;
                group.merge_pending_commit().map_err(|e| e.to_string())?;
                Ok(Outgoing { commit: out.commit.to_bytes(), welcome: out.welcome.map(|w| w.to_bytes()) })
            }
            Member::Theirs { group, provider, signer, .. } => {
                let mut kps = vec![];
                for kp in adds {
                    let k = KeyPackageIn::tls_deserialize_exact(kp.as_slice()).map_err(|e| e.to_string())?;
                    kps.push(k.validate(provider.crypto(), ProtocolVersion::Mls10).map_err(|e| format!("validate kp: {e:?}"))?);
                }
                let mut b = group.commit_builder().force_self_update(true).propose_adds(kps);
                b = b.propose_removals(removes.iter().map(|r| LeafNodeIndex::new(*r)));
                let bundle = b
                    .load_psks(provider.storage())
                    .map_err(|e| format!("{e:?}"))?
                    .build(provider.rand(), provider.crypto(), signer, |_| true)
                    .map_err(|e| format!("build commit: {e:?}"))?
                    .stage_commit(provider)
                    .map_err(|e| format!("stage: {e:?}"))?;
                let (commit, welcome, _gi) = bundle.into_messages();
                group.merge_pending_commit(provider).map_err(|e| format!("{e:?}"))?;
                Ok(Outgoing { commit: commit.tls_serialize_detached().unwrap(), welcome: welcome.map(|w| w.tls_serialize_detached().unwrap()) })
            }
        }
    }

    /// Process a handshake or application message; returns application plaintext if any.
    pub fn process(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match self {
            Member::Ours { group, name } => {
                let m = MlsMessage::from_bytes(bytes).map_err(|e| e.to_string())?;
                match group.process(&m).map_err(|e| format!("{name}: {e}"))? {
                    Processed::Application { data, .. } => Ok(Some(data)),
                    _ => Ok(None),
                }
            }
            Member::Theirs { group, provider, name, .. } => {
                let m = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| e.to_string())?;
                let pm = m.try_into_protocol_message().map_err(|e| format!("{e:?}"))?;
                let processed = group.process_message(provider, pm).map_err(|e| format!("{name}: {e:?}"))?;
                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(a) => Ok(Some(a.into_bytes())),
                    ProcessedMessageContent::StagedCommitMessage(sc) => {
                        group.merge_staged_commit(provider, *sc).map_err(|e| format!("{e:?}"))?;
                        Ok(None)
                    }
                    ProcessedMessageContent::ProposalMessage(p) => {
                        group.store_pending_proposal(provider.storage(), *p).map_err(|e| format!("{e:?}"))?;
                        Ok(None)
                    }
                    _ => Ok(None),
                }
            }
        }
    }

    pub fn send(&mut self, text: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Member::Ours { group, .. } => Ok(group.encrypt_application(text, b"").map_err(|e| e.to_string())?.to_bytes()),
            Member::Theirs { group, provider, signer, .. } => {
                Ok(group.create_message(provider, signer, text).map_err(|e| format!("{e:?}"))?.tls_serialize_detached().unwrap())
            }
        }
    }

    pub fn is_active(&self) -> bool {
        match self {
            Member::Ours { group, .. } => group.is_active(),
            Member::Theirs { group, .. } => group.is_active(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SessionReport {
    pub seed: u64,
    pub suite: u16,
    pub epochs: u64,
    pub ops: usize,
    pub commits_by_ours: usize,
    pub commits_by_theirs: usize,
    pub messages: usize,
    pub max_members: usize,
    pub agreed: bool,
    pub error: Option<String>,
}

/// Run one randomized mixed-implementation session.
pub fn run_session(seed: u64, cs: CipherSuite, ops: usize) -> SessionReport {
    let mut rep = SessionReport { seed, suite: cs.0, ops, ..Default::default() };
    match session(seed, cs, ops, &mut rep) {
        Ok(()) => rep.agreed = true,
        Err(e) => rep.error = Some(e),
    }
    rep
}

fn check_agreement(members: &[Member]) -> Result<(), String> {
    let a = members[0].epoch_authenticator();
    let x = members[0].exported();
    for m in &members[1..] {
        if m.epoch() != members[0].epoch() {
            return Err(format!("epoch: {} at {} vs {} at {}", m.name(), m.epoch(), members[0].name(), members[0].epoch()));
        }
        if m.epoch_authenticator() != a {
            return Err(format!("epoch authenticator differs between {} and {}", members[0].name(), m.name()));
        }
        if m.exported() != x {
            return Err(format!("exported secret differs between {} and {}", members[0].name(), m.name()));
        }
    }
    Ok(())
}

fn session(seed: u64, cs: CipherSuite, ops: usize, rep: &mut SessionReport) -> Result<(), String> {
    let mut rng = Rng::new(seed);
    let mut next_id = 0;
    let mut fresh = |rng: &mut Rng| {
        next_id += 1;
        let ours = rng.below(2) == 0;
        (format!("{}{}", if ours { "ours" } else { "theirs" }, next_id), ours)
    };
    let (n0, o0) = fresh(&mut rng);
    let mut members = vec![Member::create(cs, &n0, o0)];
    for _ in 0..ops {
        let op = rng.below(10);
        let committer = rng.below(members.len());
        let committer_is_ours = members[committer].is_ours();
        let out;
        if op < 4 || members.len() < 3 {
            // Add one or two members.
            let k = 1 + rng.below(2);
            let pend: Vec<Pending> = (0..k).map(|_| {
                let (n, o) = fresh(&mut rng);
                new_pending(cs, &n, o)
            }).collect();
            let kps: Vec<Vec<u8>> = pend.iter().map(|p| p.key_package_bytes()).collect();
            out = members[committer].commit(&kps, &[])?;
            for (i, m) in members.iter_mut().enumerate() {
                if i != committer {
                    m.process(&out.commit)?;
                }
            }
            let w = out.welcome.clone().ok_or("add commit without welcome")?;
            for p in pend {
                members.push(p.join(&w)?);
            }
        } else if op < 6 {
            // Remove someone other than the committer.
            let mut victim = rng.below(members.len());
            if victim == committer {
                victim = (victim + 1) % members.len();
            }
            let name = members[victim].name().to_string();
            let leaf = members[committer].leaf_of(&name).ok_or("victim not found")?;
            out = members[committer].commit(&[], &[leaf])?;
            for (i, m) in members.iter_mut().enumerate() {
                if i != committer {
                    m.process(&out.commit)?;
                }
            }
            if members[victim].is_active() {
                return Err(format!("{name} still active after removal"));
            }
            members.remove(victim);
        } else if op < 8 {
            // Empty commit with a fresh path.
            out = members[committer].commit(&[], &[])?;
            for (i, m) in members.iter_mut().enumerate() {
                if i != committer {
                    m.process(&out.commit)?;
                }
            }
        } else {
            // Application messages from a random member to everyone.
            let s = rng.below(members.len());
            let text = format!("seed {seed} msg {} from {}", rep.messages, members[s].name()).into_bytes();
            let ct = members[s].send(&text)?;
            for (i, m) in members.iter_mut().enumerate() {
                if i != s {
                    let got = m.process(&ct)?;
                    if got.as_deref() != Some(text.as_slice()) {
                        return Err(format!("{} decrypted the wrong plaintext", m.name()));
                    }
                }
            }
            rep.messages += 1;
            continue;
        }
        if committer_is_ours {
            rep.commits_by_ours += 1;
        } else {
            rep.commits_by_theirs += 1;
        }
        rep.max_members = rep.max_members.max(members.len());
        check_agreement(&members)?;
        rep.epochs = members[0].epoch();
    }
    Ok(())
}
