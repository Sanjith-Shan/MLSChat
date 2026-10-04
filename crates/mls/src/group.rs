//! Group state machine (RFC 9420 sections 11 and 12): creating a group, key
//! packages, proposals, commits (with and without a path), Welcome, external
//! commits, PSKs, and application messages.
//!
//! A commit is staged, not applied: `commit` returns the outgoing messages and
//! keeps the next epoch in `pending`. The caller merges it only once the
//! delivery service has accepted the commit for this epoch, and discards it if
//! another member's commit won. This is the client half of epoch fencing.

use crate::codec::Codec;
use crate::crypto::{random_bytes, CipherSuite};
use crate::error::{proto, Error, Result};
use crate::framing;
use crate::key_schedule::{self as ks, EpochSecrets};
use crate::messages::*;
use crate::secret_tree::SecretTree;
use crate::tree::RatchetTree;
use crate::tree_math::{self as tm, LeafIndex};
use crate::treekem::{self, TreePrivate};
use std::collections::{HashMap, HashSet, VecDeque};

/// How many past epochs' resumption PSKs a member keeps.
pub const RESUMPTION_WINDOW: u64 = 64;

/// A member's long-term signing identity.
#[derive(Clone, Debug)]
pub struct Signer {
    pub signature_priv: Vec<u8>,
    pub signature_pub: Vec<u8>,
    pub credential: Credential,
}

impl Signer {
    pub fn generate(cs: CipherSuite, identity: &[u8]) -> Self {
        let (signature_priv, signature_pub) = cs.signature_keypair();
        Signer { signature_priv, signature_pub, credential: Credential::Basic(identity.to_vec()) }
    }
}

/// A KeyPackage with its private keys.
#[derive(Clone, Debug)]
pub struct KeyPackageBundle {
    pub key_package: KeyPackage,
    pub init_priv: Vec<u8>,
    pub encryption_priv: Vec<u8>,
    pub signer: Signer,
}

pub fn default_capabilities(cs: CipherSuite) -> Capabilities {
    Capabilities {
        versions: vec![MLS10],
        cipher_suites: vec![cs.0],
        extensions: vec![],
        proposals: vec![],
        credentials: vec![credential_type::BASIC, credential_type::X509],
    }
}

pub fn create_key_package(cs: CipherSuite, signer: &Signer) -> Result<KeyPackageBundle> {
    create_key_package_with(cs, signer, default_capabilities(cs), vec![], vec![])
}

pub fn create_key_package_with(
    cs: CipherSuite,
    signer: &Signer,
    capabilities: Capabilities,
    leaf_extensions: Vec<Extension>,
    kp_extensions: Vec<Extension>,
) -> Result<KeyPackageBundle> {
    let (init_priv, init_pub) = cs.generate_keypair();
    let (encryption_priv, encryption_pub) = cs.generate_keypair();
    let mut leaf = LeafNode {
        encryption_key: encryption_pub,
        signature_key: signer.signature_pub.clone(),
        credential: signer.credential.clone(),
        capabilities,
        leaf_node_source: LeafNodeSource::KeyPackage(Lifetime { not_before: 0, not_after: u64::MAX }),
        extensions: leaf_extensions,
        signature: vec![],
    };
    leaf.sign(cs, &signer.signature_priv, None)?;
    let mut kp = KeyPackage { version: MLS10, cipher_suite: cs, init_key: init_pub, leaf_node: leaf, extensions: kp_extensions, signature: vec![] };
    kp.signature = cs.sign_with_label(&signer.signature_priv, "KeyPackageTBS", &kp.tbs())?;
    Ok(KeyPackageBundle { key_package: kp, init_priv, encryption_priv, signer: signer.clone() })
}

#[derive(Clone, Debug)]
pub struct GroupConfig {
    /// Send proposals and commits as PrivateMessage instead of PublicMessage.
    pub encrypt_handshake: bool,
    /// Zero padding added to every PrivateMessage.
    pub padding: usize,
    /// How many past epochs keep keys for late application messages.
    pub max_past_epochs: usize,
    /// Put the ratchet tree in GroupInfo (and so in Welcome).
    pub ratchet_tree_extension: bool,
    /// Put external_pub in GroupInfo so outsiders can join by external commit.
    pub external_pub_extension: bool,
}

impl Default for GroupConfig {
    fn default() -> Self {
        GroupConfig { encrypt_handshake: false, padding: 0, max_past_epochs: 2, ratchet_tree_extension: true, external_pub_extension: false }
    }
}

/// External and resumption pre-shared keys known to this client.
#[derive(Clone, Debug, Default)]
pub struct PskStore {
    pub external: HashMap<Vec<u8>, Vec<u8>>,
    /// (group_id, epoch) -> resumption_psk
    pub resumption: HashMap<(Vec<u8>, u64), Vec<u8>>,
}

impl PskStore {
    fn resolve(&self, id: &PreSharedKeyId) -> Result<Vec<u8>> {
        match &id.psk {
            Psk::External { psk_id } => self.external.get(psk_id).cloned().ok_or_else(|| Error::Protocol("unknown external PSK".into())),
            Psk::Resumption { psk_group_id, psk_epoch, .. } => self
                .resumption
                .get(&(psk_group_id.clone(), *psk_epoch))
                .cloned()
                .ok_or_else(|| Error::Protocol(format!("unknown resumption PSK for epoch {psk_epoch}"))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CachedProposal {
    pub reference: ProposalRef,
    pub proposal: Proposal,
    pub sender: Sender,
}

#[derive(Clone, Debug)]
struct PastEpoch {
    epoch: u64,
    context: GroupContext,
    secret_tree: SecretTree,
    sender_data_secret: Vec<u8>,
    /// The tree of that epoch (nodes are shared, so this is cheap to keep).
    tree: RatchetTree,
}

/// What processing a message did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Processed {
    Application { sender: LeafIndex, data: Vec<u8>, authenticated_data: Vec<u8>, epoch: u64 },
    Proposal { sender: Sender, reference: ProposalRef, proposal: Proposal },
    Commit(CommitSummary),
    /// Our own staged commit came back from the delivery service and was merged.
    OwnCommitMerged,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommitSummary {
    pub sender: Option<LeafIndex>,
    pub new_epoch: u64,
    pub added: Vec<LeafIndex>,
    pub removed: Vec<LeafIndex>,
    pub updated: Vec<LeafIndex>,
    pub self_removed: bool,
    pub reinit: Option<ReInit>,
}

/// Messages produced by a commit.
#[derive(Clone, Debug)]
pub struct CommitOutput {
    pub commit: MlsMessage,
    pub welcome: Option<MlsMessage>,
    /// Signed GroupInfo for the new epoch; built only when a Welcome needs it.
    pub group_info: Option<GroupInfo>,
    /// Bytes of the UpdatePath carried in the commit, zero without a path.
    pub path_bytes: usize,
}

#[derive(Clone, Debug, Default)]
pub struct CommitOptions {
    /// Include an UpdatePath even when the proposals don't require one.
    pub force_path: bool,
    /// Commit only these cached proposals by reference (None = all of them).
    pub by_reference: Option<Vec<ProposalRef>>,
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Group {
    pub cs: CipherSuite,
    context: GroupContext,
    tree: RatchetTree,
    private: TreePrivate,
    secrets: EpochSecrets,
    secret_tree: SecretTree,
    interim_transcript_hash: Vec<u8>,
    signer: Signer,
    proposals: Vec<CachedProposal>,
    /// Encryption private keys for our own pending Update proposals, by reference.
    own_updates: HashMap<ProposalRef, Vec<u8>>,
    pending: Option<Box<(Group, Vec<u8>)>>,
    pub psks: PskStore,
    past: VecDeque<PastEpoch>,
    pub config: GroupConfig,
    active: bool,
    reinit: Option<ReInit>,
}

/// Proposals gathered for a commit, each with its sender.
type ProposalList = Vec<(Proposal, Sender, Option<ProposalRef>)>;

struct Applied {
    added: Vec<(LeafIndex, KeyPackage)>,
    removed: Vec<LeafIndex>,
    updated: Vec<LeafIndex>,
    psk_ids: Vec<PreSharedKeyId>,
    external_init: Option<Vec<u8>>,
    reinit: Option<ReInit>,
    path_required: bool,
}

impl Group {
    // ------------------------------------------------------------------
    // Accessors

    pub fn epoch(&self) -> u64 {
        self.context.epoch
    }
    pub fn group_id(&self) -> &[u8] {
        &self.context.group_id
    }
    pub fn context(&self) -> &GroupContext {
        &self.context
    }
    pub fn tree(&self) -> &RatchetTree {
        &self.tree
    }
    pub fn own_leaf(&self) -> LeafIndex {
        self.private.leaf
    }
    pub fn epoch_authenticator(&self) -> &[u8] {
        &self.secrets.epoch_authenticator
    }
    pub fn export_secret(&self, label: &str, context: &[u8], len: usize) -> Result<Vec<u8>> {
        self.secrets.export(self.cs, label, context, len)
    }
    pub fn is_active(&self) -> bool {
        self.active
    }
    pub fn pending_reinit(&self) -> Option<&ReInit> {
        self.reinit.as_ref()
    }
    pub fn has_pending_commit(&self) -> bool {
        self.pending.is_some()
    }
    /// The staged next-epoch state of our pending commit.
    pub fn pending_state(&self) -> Option<&Group> {
        self.pending.as_ref().map(|p| &p.0)
    }
    pub fn signer(&self) -> &Signer {
        &self.signer
    }
    pub fn cached_proposals(&self) -> &[CachedProposal] {
        &self.proposals
    }
    pub fn resumption_psk(&self) -> &[u8] {
        &self.secrets.resumption_psk
    }
    pub fn member_identities(&self) -> Vec<(LeafIndex, Vec<u8>)> {
        self.tree.members().map(|(i, l)| (i, l.credential.identity().to_vec())).collect()
    }
    pub fn private_state(&self) -> &TreePrivate {
        &self.private
    }

    // ------------------------------------------------------------------
    // Creation and joining

    /// Create a one-member group at epoch 0.
    pub fn create(cs: CipherSuite, signer: Signer, group_id: Vec<u8>, extensions: Vec<Extension>, config: GroupConfig) -> Result<Group> {
        cs.check()?;
        let (enc_priv, enc_pub) = cs.generate_keypair();
        let mut leaf = LeafNode {
            encryption_key: enc_pub,
            signature_key: signer.signature_pub.clone(),
            credential: signer.credential.clone(),
            capabilities: default_capabilities(cs),
            leaf_node_source: LeafNodeSource::KeyPackage(Lifetime { not_before: 0, not_after: u64::MAX }),
            extensions: vec![],
            signature: vec![],
        };
        leaf.sign(cs, &signer.signature_priv, None)?;
        Self::create_with_leaf(cs, signer, group_id, extensions, config, leaf, enc_priv)
    }

    pub fn create_with_leaf(
        cs: CipherSuite,
        signer: Signer,
        group_id: Vec<u8>,
        extensions: Vec<Extension>,
        config: GroupConfig,
        leaf: LeafNode,
        enc_priv: Vec<u8>,
    ) -> Result<Group> {
        let tree = RatchetTree::new(cs, leaf);
        let context = GroupContext {
            version: MLS10,
            cipher_suite: cs,
            group_id,
            epoch: 0,
            tree_hash: tree.root_tree_hash(),
            confirmed_transcript_hash: vec![],
            extensions,
        };
        let init = random_bytes(cs.nh());
        let commit_secret = random_bytes(cs.nh());
        let secrets = ks::derive(cs, &init, Some(&commit_secret), None, &context.to_bytes())?;
        let tag = cs.mac(&secrets.confirmation_key, &context.confirmed_transcript_hash);
        let interim = ks::interim_transcript_hash(cs, &context.confirmed_transcript_hash, &tag);
        let secret_tree = SecretTree::new(cs, &secrets.encryption_secret, tree.n_leaves());
        let mut g = Group {
            cs,
            context,
            tree,
            private: TreePrivate::new(0, enc_priv),
            secrets,
            secret_tree,
            interim_transcript_hash: interim,
            signer,
            proposals: vec![],
            own_updates: HashMap::new(),
            pending: None,
            psks: PskStore::default(),
            past: VecDeque::new(),
            config,
            active: true,
            reinit: None,
        };
        g.remember_resumption();
        Ok(g)
    }

    fn remember_resumption(&mut self) {
        let (g, e) = (self.context.group_id.clone(), self.context.epoch);
        self.psks.resumption.insert((g.clone(), e), self.secrets.resumption_psk.clone());
        // Keep a bounded window of this group's past resumption PSKs.
        self.psks.resumption.retain(|(gg, ee), _| *gg != g || *ee + RESUMPTION_WINDOW > e);
    }

    /// Join from a Welcome (RFC 9420 section 12.4.3.1).
    pub fn join(welcome: &Welcome, kpb: &KeyPackageBundle, ratchet_tree: Option<RatchetTree>, psks: PskStore, config: GroupConfig) -> Result<Group> {
        let cs = welcome.cipher_suite;
        cs.check()?;
        if kpb.key_package.cipher_suite != cs {
            return proto("Welcome cipher suite does not match key package");
        }
        let kp_ref = kpb.key_package.reference();
        let egs = welcome
            .secrets
            .iter()
            .find(|s| s.new_member == kp_ref)
            .ok_or_else(|| Error::Protocol("Welcome has no secrets for this key package".into()))?;
        let gs_bytes = cs.decrypt_with_label(
            &kpb.init_priv,
            "Welcome",
            &welcome.encrypted_group_info,
            &egs.encrypted_group_secrets.kem_output,
            &egs.encrypted_group_secrets.ciphertext,
        )?;
        let gs = GroupSecrets::from_bytes(&gs_bytes)?;
        let psk_list: Vec<(PreSharedKeyId, Vec<u8>)> = gs.psks.iter().map(|id| Ok((id.clone(), psks.resolve(id)?))).collect::<Result<_>>()?;
        let psk_secret = ks::psk_secret(cs, &psk_list)?;
        let zero = vec![0u8; cs.nh()];
        let member = cs.extract(&gs.joiner_secret, psk_secret.as_deref().unwrap_or(&zero));
        let welcome_secret = cs.derive_secret(&member, "welcome")?;
        let (wk, wn) = ks::welcome_key_nonce(cs, &welcome_secret)?;
        let gi_bytes = cs.open(&wk, &wn, &[], &welcome.encrypted_group_info)?;
        let gi = GroupInfo::from_bytes(&gi_bytes)?;
        let ctx = gi.group_context.clone();
        if ctx.cipher_suite != cs || ctx.version != MLS10 {
            return proto("GroupInfo suite or version mismatch");
        }

        let tree = match ratchet_tree {
            Some(t) => t,
            None => {
                let ext = find_extension(&gi.extensions, ext_type::RATCHET_TREE)
                    .ok_or_else(|| Error::Protocol("no ratchet tree supplied or in GroupInfo".into()))?;
                RatchetTree::from_bytes(cs, &ext.extension_data)?
            }
        };
        let signer_leaf = tree.leaf(gi.signer).ok_or_else(|| Error::Protocol("GroupInfo signer is not a member".into()))?;
        cs.verify_with_label(&signer_leaf.signature_key, "GroupInfoTBS", &gi.tbs(), &gi.signature)?;
        if tree.root_tree_hash() != ctx.tree_hash {
            return proto("ratchet tree hash does not match GroupContext");
        }
        validate_tree(&tree, &ctx.group_id)?;

        let me = tree
            .find_leaf(|l| *l == kpb.key_package.leaf_node)
            .ok_or_else(|| Error::Protocol("own leaf not found in tree".into()))?;
        let mut private = TreePrivate::new(me, kpb.encryption_priv.clone());
        if let Some(ps) = &gs.path_secret {
            let lca = tm::common_ancestor(tm::leaf_to_node(me), tm::leaf_to_node(gi.signer));
            let fdp = tree.filtered_direct_path(gi.signer);
            let start = fdp.iter().position(|n| *n == lca).ok_or_else(|| Error::Protocol("path secret node not on signer's path".into()))?;
            private.install_path_secrets(cs, &fdp[start..], ps.path_secret.clone())?;
        }
        private.consistent_with(cs, &tree)?;

        let secrets = ks::from_joiner(cs, &gs.joiner_secret, psk_secret.as_deref(), &ctx.to_bytes())?;
        if !cs.verify_mac(&secrets.confirmation_key, &ctx.confirmed_transcript_hash, &gi.confirmation_tag) {
            return proto("Welcome confirmation tag mismatch");
        }
        let interim = ks::interim_transcript_hash(cs, &ctx.confirmed_transcript_hash, &gi.confirmation_tag);
        let secret_tree = SecretTree::new(cs, &secrets.encryption_secret, tree.n_leaves());
        let mut g = Group {
            cs,
            context: ctx,
            tree,
            private,
            secrets,
            secret_tree,
            interim_transcript_hash: interim,
            signer: kpb.signer.clone(),
            proposals: vec![],
            own_updates: HashMap::new(),
            pending: None,
            psks,
            past: VecDeque::new(),
            config,
            active: true,
            reinit: None,
        };
        g.remember_resumption();
        Ok(g)
    }

    // ------------------------------------------------------------------
    // GroupInfo

    pub fn group_info(&self, with_tree: bool, with_external_pub: bool) -> Result<GroupInfo> {
        let mut extensions = Vec::new();
        if with_tree {
            extensions.push(Extension { extension_type: ext_type::RATCHET_TREE, extension_data: self.tree.to_bytes() });
        }
        if with_external_pub {
            let (_, pk) = self.secrets.external_pub(self.cs)?;
            extensions.push(Extension { extension_type: ext_type::EXTERNAL_PUB, extension_data: ExternalPub { external_pub: pk }.to_bytes() });
        }
        let confirmation_tag = self.cs.mac(&self.secrets.confirmation_key, &self.context.confirmed_transcript_hash);
        let mut gi = GroupInfo { group_context: self.context.clone(), extensions, confirmation_tag, signer: self.private.leaf, signature: vec![] };
        gi.signature = self.cs.sign_with_label(&self.signer.signature_priv, "GroupInfoTBS", &gi.tbs())?;
        Ok(gi)
    }

    // ------------------------------------------------------------------
    // Framing helpers

    fn frame(&mut self, content: Content, authenticated_data: Vec<u8>, encrypt: bool, confirmation_tag: Option<Vec<u8>>) -> Result<(AuthenticatedContent, MlsMessage)> {
        let fc = FramedContent {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender: Sender::Member(self.private.leaf),
            authenticated_data,
            content,
        };
        let wf = if encrypt { WireFormat::PrivateMessage } else { WireFormat::PublicMessage };
        let ac = framing::sign_content(self.cs, &self.signer.signature_priv, wf, fc, Some(&self.context), confirmation_tag)?;
        let msg = self.protect(&ac)?;
        Ok((ac, msg))
    }

    fn protect(&mut self, ac: &AuthenticatedContent) -> Result<MlsMessage> {
        Ok(match ac.wire_format {
            WireFormat::PrivateMessage => MlsMessage::Private(framing::encrypt_private(
                self.cs,
                ac,
                &mut self.secret_tree,
                &self.secrets.sender_data_secret,
                self.config.padding,
            )?),
            _ => MlsMessage::Public(framing::to_public(self.cs, ac.clone(), Some(&self.context), Some(&self.secrets.membership_key))?),
        })
    }

    fn proposal_ref(&self, ac: &AuthenticatedContent) -> ProposalRef {
        self.cs.ref_hash("MLS 1.0 Proposal Reference", &ac.to_bytes())
    }

    /// Encrypt application data for the current epoch.
    pub fn encrypt_application(&mut self, data: &[u8], authenticated_data: &[u8]) -> Result<MlsMessage> {
        if !self.active {
            return proto("group is not active");
        }
        if self.pending.is_some() {
            // Sending is still allowed in the current epoch while a commit is staged.
        }
        let (_, msg) = self.frame(Content::Application(data.to_vec()), authenticated_data.to_vec(), true, None)?;
        Ok(msg)
    }

    // ------------------------------------------------------------------
    // Proposals

    /// Send a proposal and cache it for the next commit.
    pub fn propose(&mut self, proposal: Proposal) -> Result<(MlsMessage, ProposalRef)> {
        let (ac, msg) = self.frame(Content::Proposal(proposal.clone()), vec![], self.config.encrypt_handshake, None)?;
        let r = self.proposal_ref(&ac);
        self.proposals.push(CachedProposal { reference: r.clone(), proposal, sender: Sender::Member(self.private.leaf) });
        Ok((msg, r))
    }

    pub fn propose_add(&mut self, kp: KeyPackage) -> Result<(MlsMessage, ProposalRef)> {
        self.propose(Proposal::Add(kp))
    }

    pub fn propose_remove(&mut self, leaf: LeafIndex) -> Result<(MlsMessage, ProposalRef)> {
        self.propose(Proposal::Remove(leaf))
    }

    /// Propose replacing our own leaf with a fresh encryption key.
    pub fn propose_update(&mut self) -> Result<(MlsMessage, ProposalRef)> {
        let (sk, pk) = self.cs.generate_keypair();
        let mut leaf = self.tree.leaf(self.private.leaf).unwrap().clone();
        leaf.encryption_key = pk;
        leaf.leaf_node_source = LeafNodeSource::Update;
        leaf.sign(self.cs, &self.signer.signature_priv, Some((&self.context.group_id, self.private.leaf)))?;
        let (msg, r) = self.propose(Proposal::Update(leaf))?;
        self.own_updates.insert(r.clone(), sk);
        Ok((msg, r))
    }

    // ------------------------------------------------------------------
    // Applying proposals (shared by commit creation and processing)

    fn validate_key_package(&self, kp: &KeyPackage) -> Result<()> {
        if kp.version != MLS10 || kp.cipher_suite != self.cs {
            return proto("key package version or suite mismatch");
        }
        kp.verify()?;
        if !matches!(kp.leaf_node.leaf_node_source, LeafNodeSource::KeyPackage(_)) {
            return proto("key package leaf source must be key_package");
        }
        kp.leaf_node.verify(self.cs, None)?;
        if kp.init_key == kp.leaf_node.encryption_key {
            return proto("init key equals encryption key");
        }
        self.validate_leaf_capabilities(&kp.leaf_node)
    }

    fn validate_leaf_capabilities(&self, ln: &LeafNode) -> Result<()> {
        let caps = &ln.capabilities;
        if !caps.cipher_suites.contains(&self.cs.0) || !caps.versions.contains(&MLS10) {
            return proto("leaf does not support group suite or version");
        }
        for e in &ln.extensions {
            if e.extension_type > 5 && !caps.extensions.contains(&e.extension_type) {
                return proto("leaf uses an extension it does not list");
            }
        }
        if let Some(rc) = find_extension(&self.context.extensions, ext_type::REQUIRED_CAPABILITIES) {
            let rc = RequiredCapabilities::from_bytes(&rc.extension_data)?;
            check_required(&rc, caps)?;
        }
        Ok(())
    }

    /// Apply a validated proposal list to `self` (which is the next-epoch state).
    fn apply_proposals(&mut self, list: &ProposalList, committer: Sender) -> Result<Applied> {
        let mut a = Applied { added: vec![], removed: vec![], updated: vec![], psk_ids: vec![], external_init: None, reinit: None, path_required: list.is_empty() };
        let mut removed_set = HashSet::new();
        let mut updated_set = HashSet::new();
        let mut gce_seen = false;
        let mut psk_seen = HashSet::new();
        let n = list.len();
        // Validation pass (RFC 9420 section 12.2).
        for (p, s, _) in list {
            match p {
                Proposal::Update(_) => {
                    let Sender::Member(l) = s else { return proto("Update from non-member") };
                    if *s == committer {
                        return proto("commit includes committer's own Update");
                    }
                    if !updated_set.insert(*l) {
                        return proto("two Updates for one leaf");
                    }
                    a.path_required = true;
                }
                Proposal::Remove(l) => {
                    if self.tree.leaf(*l).is_none() {
                        return proto(format!("Remove of non-member leaf {l}"));
                    }
                    if !removed_set.insert(*l) {
                        return proto("duplicate Remove");
                    }
                    a.path_required = true;
                }
                Proposal::GroupContextExtensions(_) => {
                    if gce_seen {
                        return proto("two GroupContextExtensions proposals");
                    }
                    gce_seen = true;
                    a.path_required = true;
                }
                Proposal::ExternalInit(_) => {
                    if committer != Sender::NewMemberCommit {
                        return proto("ExternalInit outside an external commit");
                    }
                    a.path_required = true;
                }
                Proposal::ReInit(_) => {
                    if n != 1 {
                        return proto("ReInit must be the only proposal");
                    }
                }
                Proposal::PreSharedKey(id) => {
                    if !psk_seen.insert(id.to_bytes()) {
                        return proto("duplicate PSK proposal");
                    }
                }
                Proposal::Add(_) => {}
            }
        }
        if updated_set.intersection(&removed_set).next().is_some() {
            return proto("Update and Remove for the same leaf");
        }
        if let Sender::Member(c) = committer {
            if removed_set.contains(&c) {
                return proto("committer removes itself");
            }
        }

        // Application order: GroupContextExtensions, Update, Remove, Add, PSK.
        for (p, _, _) in list {
            if let Proposal::GroupContextExtensions(exts) = p {
                for (_, ln) in self.tree.members() {
                    for e in exts {
                        if e.extension_type > 5 && !ln.capabilities.extensions.contains(&e.extension_type) {
                            return proto("member does not support new group context extension");
                        }
                    }
                    if let Some(rc) = find_extension(exts, ext_type::REQUIRED_CAPABILITIES) {
                        check_required(&RequiredCapabilities::from_bytes(&rc.extension_data)?, &ln.capabilities)?;
                    }
                }
                self.context.extensions = exts.clone();
            }
        }
        for (p, s, r) in list {
            if let (Proposal::Update(ln), Sender::Member(l)) = (p, s) {
                if !matches!(ln.leaf_node_source, LeafNodeSource::Update) {
                    return proto("Update leaf source must be update");
                }
                ln.verify(self.cs, Some((&self.context.group_id, *l)))?;
                self.validate_leaf_capabilities(ln)?;
                if self.tree.has_encryption_key(&ln.encryption_key) {
                    return proto("Update reuses an encryption key");
                }
                self.tree.update_leaf(*l, ln.clone())?;
                a.updated.push(*l);
                if *l == self.private.leaf {
                    let sk = r.as_ref().and_then(|r| self.own_updates.get(r)).ok_or_else(|| Error::Protocol("own Update committed but key unknown".into()))?;
                    self.private.keys.insert(tm::leaf_to_node(*l), sk.clone());
                }
            }
        }
        for (p, _, _) in list {
            if let Proposal::Remove(l) = p {
                self.tree.remove_leaf(*l)?;
                a.removed.push(*l);
            }
        }
        for (p, _, _) in list {
            if let Proposal::Add(kp) = p {
                self.validate_key_package(kp)?;
                if self.tree.has_encryption_key(&kp.leaf_node.encryption_key) || self.tree.has_signature_key(&kp.leaf_node.signature_key) {
                    return proto("Add reuses a key already in the tree");
                }
                let l = self.tree.add_leaf(kp.leaf_node.clone());
                a.added.push((l, kp.clone()));
            }
        }
        for (p, _, _) in list {
            match p {
                Proposal::PreSharedKey(id) => a.psk_ids.push(id.clone()),
                Proposal::ExternalInit(k) => a.external_init = Some(k.clone()),
                Proposal::ReInit(r) => a.reinit = Some(r.clone()),
                _ => {}
            }
        }
        if !a.removed.is_empty() || !a.updated.is_empty() {
            self.private.prune(self.cs, &self.tree);
        }
        Ok(a)
    }

    fn psk_secret_for(&self, ids: &[PreSharedKeyId]) -> Result<Option<Vec<u8>>> {
        let list: Vec<(PreSharedKeyId, Vec<u8>)> = ids.iter().map(|id| Ok((id.clone(), self.psks.resolve(id)?))).collect::<Result<_>>()?;
        ks::psk_secret(self.cs, &list)
    }

    /// Move `next` (which holds the old epoch's secrets) to the new epoch.
    fn advance(&mut self, ac: &AuthenticatedContent, init_secret: &[u8], commit_secret: Option<&[u8]>, psk_secret: Option<&[u8]>) -> Result<Vec<u8>> {
        let cs = self.cs;
        let confirmed = ks::confirmed_transcript_hash(cs, &self.interim_transcript_hash, ac);
        self.context.epoch += 1;
        self.context.tree_hash = self.tree.root_tree_hash();
        self.context.confirmed_transcript_hash = confirmed;
        let secrets = ks::derive(cs, init_secret, commit_secret, psk_secret, &self.context.to_bytes())?;
        let tag = cs.mac(&secrets.confirmation_key, &self.context.confirmed_transcript_hash);
        self.interim_transcript_hash = ks::interim_transcript_hash(cs, &self.context.confirmed_transcript_hash, &tag);
        self.secret_tree = SecretTree::new(cs, &secrets.encryption_secret, self.tree.n_leaves());
        self.secrets = secrets;
        self.proposals.clear();
        self.own_updates.clear();
        self.remember_resumption();
        Ok(tag)
    }

    fn archive_epoch(&self) -> PastEpoch {
        PastEpoch {
            epoch: self.context.epoch,
            context: self.context.clone(),
            secret_tree: self.secret_tree.clone(),
            sender_data_secret: self.secrets.sender_data_secret.clone(),
            tree: self.tree.clone(),
        }
    }

    fn push_past(&mut self, p: PastEpoch) {
        if self.config.max_past_epochs == 0 {
            return;
        }
        self.past.push_back(p);
        while self.past.len() > self.config.max_past_epochs {
            self.past.pop_front();
        }
    }

    // ------------------------------------------------------------------
    // Commit creation

    /// Stage a commit of the cached proposals plus `extra` (by value).
    pub fn commit(&mut self, extra: Vec<Proposal>, opts: CommitOptions) -> Result<CommitOutput> {
        if !self.active {
            return proto("group is not active");
        }
        let me = Sender::Member(self.private.leaf);
        let mut list: ProposalList = Vec::new();
        for cp in &self.proposals {
            if let Some(sel) = &opts.by_reference {
                if !sel.contains(&cp.reference) {
                    continue;
                }
            }
            // A committer never commits its own Update; it refreshes its leaf with the path instead.
            if matches!(cp.proposal, Proposal::Update(_)) && cp.sender == me {
                continue;
            }
            list.push((cp.proposal.clone(), cp.sender, Some(cp.reference.clone())));
        }
        // Drop by-reference proposals that conflict (e.g. Remove of a leaf already removed).
        let mut seen_remove = HashSet::new();
        list.retain(|(p, _, _)| match p {
            Proposal::Remove(l) => self.tree.leaf(*l).is_some() && *l != self.private.leaf && seen_remove.insert(*l),
            _ => true,
        });
        for p in extra {
            list.push((p, me, None));
        }

        let mut next = self.clone();
        next.pending = None;
        let applied = next.apply_proposals(&list, me)?;
        let use_path = opts.force_path || applied.path_required;
        let excluded: HashSet<LeafIndex> = applied.added.iter().map(|(l, _)| *l).collect();

        let mut path_secrets = Vec::new();
        let mut path_bytes = 0;
        let (commit_secret, update_path) = if use_path {
            let (leaf_priv, leaf_pub) = self.cs.generate_keypair();
            let mut leaf = next.tree.leaf(self.private.leaf).unwrap().clone();
            leaf.encryption_key = leaf_pub;
            let gid = next.context.group_id.clone();
            let ctx_src = next.clone_context_source();
            let g = treekem::generate(
                &mut next.tree,
                &mut next.private,
                self.private.leaf,
                leaf,
                leaf_priv,
                &self.signer.signature_priv,
                &gid,
                &excluded,
                |t| ctx_src.provisional(t),
            )?;
            path_secrets = g.path_secrets;
            path_bytes = g.update_path.to_bytes().len();
            (Some(g.commit_secret), Some(g.update_path))
        } else {
            (None, None)
        };

        let proposals: Vec<ProposalOrRef> = list
            .iter()
            .map(|(p, _, r)| match r {
                Some(r) => ProposalOrRef::Reference(r.clone()),
                None => ProposalOrRef::Proposal(p.clone()),
            })
            .collect();
        let commit = Commit { proposals, path: update_path };
        let fc = FramedContent {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender: me,
            authenticated_data: opts.authenticated_data.clone(),
            content: Content::Commit(commit),
        };
        let wf = if self.config.encrypt_handshake { WireFormat::PrivateMessage } else { WireFormat::PublicMessage };
        let mut ac = framing::sign_content(self.cs, &self.signer.signature_priv, wf, fc, Some(&self.context), None)?;

        let psk_secret = next.psk_secret_for(&applied.psk_ids)?;
        let init = self.secrets.init_secret.clone();
        next.past.clear();
        let tag = next.advance(&ac, &init, commit_secret.as_deref(), psk_secret.as_deref())?;
        ac.auth.confirmation_tag = Some(tag);
        let msg = self.protect(&ac)?;
        next.reinit = applied.reinit.clone();
        if applied.reinit.is_some() {
            next.active = false;
        }

        // Past epochs: the staged state keeps ours plus the current one.
        let mut past = self.past.clone();
        if self.config.max_past_epochs > 0 {
            past.push_back(self.archive_epoch());
        }
        next.past = past;
        while next.past.len() > next.config.max_past_epochs {
            next.past.pop_front();
        }

        // Signing a GroupInfo means serializing the whole tree, which is O(n);
        // do it only when a Welcome needs one (exp1 caught this, see BUG_LOG).
        let (welcome, group_info) = if applied.added.is_empty() {
            (None, None)
        } else {
            let gi = next.group_info(next.config.ratchet_tree_extension, next.config.external_pub_extension)?;
            (Some(MlsMessage::Welcome(next.build_welcome(&gi, &applied, &path_secrets)?)), Some(gi))
        };
        let bytes = msg.to_bytes();
        self.pending = Some(Box::new((next, bytes)));
        Ok(CommitOutput { commit: msg, welcome, group_info, path_bytes })
    }

    fn clone_context_source(&self) -> ContextSource {
        ContextSource { cs: self.cs, context: self.context.clone() }
    }

    fn build_welcome(&self, gi: &GroupInfo, applied: &Applied, path_secrets: &[(u32, Vec<u8>)]) -> Result<Welcome> {
        let cs = self.cs;
        let (wk, wn) = ks::welcome_key_nonce(cs, &self.secrets.welcome_secret)?;
        let encrypted_group_info = cs.seal(&wk, &wn, &[], &gi.to_bytes())?;
        let me = tm::leaf_to_node(self.private.leaf);
        let mut secrets = Vec::new();
        for (l, kp) in &applied.added {
            let path_secret = if path_secrets.is_empty() {
                None
            } else {
                let lca = tm::common_ancestor(me, tm::leaf_to_node(*l));
                path_secrets.iter().find(|(n, _)| *n == lca).map(|(_, s)| PathSecret { path_secret: s.clone() })
            };
            let gs = GroupSecrets { joiner_secret: self.secrets.joiner_secret.clone(), path_secret, psks: applied.psk_ids.clone() };
            let (kem_output, ciphertext) = cs.encrypt_with_label(&kp.init_key, "Welcome", &encrypted_group_info, &gs.to_bytes())?;
            secrets.push(EncryptedGroupSecrets { new_member: kp.reference(), encrypted_group_secrets: HpkeCiphertext { kem_output, ciphertext } });
        }
        Ok(Welcome { cipher_suite: cs, secrets, encrypted_group_info })
    }

    /// Apply our staged commit after the delivery service accepted it.
    pub fn merge_pending_commit(&mut self) -> Result<()> {
        let p = self.pending.take().ok_or_else(|| Error::Protocol("no pending commit".into()))?;
        *self = p.0;
        Ok(())
    }

    /// Drop our staged commit (another commit won the epoch).
    pub fn clear_pending_commit(&mut self) {
        self.pending = None;
    }

    // ------------------------------------------------------------------
    // Processing incoming messages

    pub fn process(&mut self, msg: &MlsMessage) -> Result<Processed> {
        if let Some(p) = &self.pending {
            if p.1 == msg.to_bytes() {
                self.merge_pending_commit()?;
                return Ok(Processed::OwnCommitMerged);
            }
        }
        let (gid, epoch) = match msg {
            MlsMessage::Public(p) => (&p.content.group_id, p.content.epoch),
            MlsMessage::Private(p) => (&p.group_id, p.epoch),
            _ => return proto("not a group message"),
        };
        if *gid != self.context.group_id {
            return proto("message for another group");
        }
        if epoch != self.context.epoch {
            if let MlsMessage::Private(pm) = msg {
                if pm.content_type == ContentType::Application {
                    return self.process_past_application(pm);
                }
            }
            return Err(Error::WrongEpoch { got: epoch, want: self.context.epoch });
        }
        if !self.active {
            return proto("group is not active");
        }
        let ac = match msg {
            MlsMessage::Public(pm) => framing::from_public(self.cs, pm, Some(&self.context), Some(&self.secrets.membership_key))?,
            MlsMessage::Private(pm) => framing::decrypt_private(self.cs, pm, &mut self.secret_tree, &self.secrets.sender_data_secret)?,
            _ => unreachable!(),
        };
        self.verify_sender_signature(&ac)?;
        match &ac.content.content {
            Content::Application(data) => {
                let Sender::Member(l) = ac.content.sender else { return proto("application from non-member") };
                Ok(Processed::Application { sender: l, data: data.clone(), authenticated_data: ac.content.authenticated_data.clone(), epoch })
            }
            Content::Proposal(p) => {
                self.check_proposal_sender(p, ac.content.sender)?;
                let r = self.proposal_ref(&ac);
                if self.proposals.iter().any(|c| c.reference == r) {
                    return Ok(Processed::Proposal { sender: ac.content.sender, reference: r, proposal: p.clone() });
                }
                self.proposals.push(CachedProposal { reference: r.clone(), proposal: p.clone(), sender: ac.content.sender });
                Ok(Processed::Proposal { sender: ac.content.sender, reference: r, proposal: p.clone() })
            }
            Content::Commit(_) => self.process_commit(&ac).map(Processed::Commit),
        }
    }

    fn check_proposal_sender(&self, p: &Proposal, s: Sender) -> Result<()> {
        match s {
            Sender::Member(_) => Ok(()),
            Sender::External(_) => match p {
                Proposal::Add(_) | Proposal::Remove(_) | Proposal::PreSharedKey(_) | Proposal::ReInit(_) | Proposal::GroupContextExtensions(_) => Ok(()),
                _ => proto("proposal type not allowed from external sender"),
            },
            Sender::NewMemberProposal => match p {
                Proposal::Add(_) => Ok(()),
                _ => proto("new member may only propose Add"),
            },
            Sender::NewMemberCommit => proto("proposal with new_member_commit sender"),
        }
    }

    fn verify_sender_signature(&self, ac: &AuthenticatedContent) -> Result<()> {
        let key: Vec<u8> = match ac.content.sender {
            Sender::Member(l) => self.tree.leaf(l).ok_or_else(|| Error::Protocol(format!("sender leaf {l} is blank")))?.signature_key.clone(),
            Sender::External(i) => {
                let ext = find_extension(&self.context.extensions, ext_type::EXTERNAL_SENDERS).ok_or_else(|| Error::Protocol("no external senders configured".into()))?;
                let list = Vec::<ExternalSender>::from_bytes(&ext.extension_data)?;
                list.get(i as usize).ok_or_else(|| Error::Protocol("unknown external sender".into()))?.signature_key.clone()
            }
            Sender::NewMemberProposal => match &ac.content.content {
                Content::Proposal(Proposal::Add(kp)) => kp.leaf_node.signature_key.clone(),
                _ => return proto("new_member_proposal must carry an Add"),
            },
            Sender::NewMemberCommit => match &ac.content.content {
                Content::Commit(c) => c.path.as_ref().ok_or_else(|| Error::Protocol("external commit without path".into()))?.leaf_node.signature_key.clone(),
                _ => return proto("new_member_commit must carry a Commit"),
            },
        };
        framing::verify_content_signature(self.cs, ac, Some(&self.context), &key)
    }

    fn process_past_application(&mut self, pm: &PrivateMessage) -> Result<Processed> {
        let cs = self.cs;
        let past = self.past.iter_mut().find(|p| p.epoch == pm.epoch).ok_or(Error::WrongEpoch { got: pm.epoch, want: self.context.epoch })?;
        let ac = framing::decrypt_private(cs, pm, &mut past.secret_tree, &past.sender_data_secret)?;
        let Sender::Member(l) = ac.content.sender else { return proto("application from non-member") };
        let key = past.tree.leaf(l).ok_or_else(|| Error::Protocol("sender unknown in past epoch".into()))?.signature_key.clone();
        framing::verify_content_signature(cs, &ac, Some(&past.context), &key)?;
        let Content::Application(data) = &ac.content.content else { return proto("not application") };
        Ok(Processed::Application { sender: l, data: data.clone(), authenticated_data: ac.content.authenticated_data.clone(), epoch: pm.epoch })
    }

    fn process_commit(&mut self, ac: &AuthenticatedContent) -> Result<CommitSummary> {
        let cs = self.cs;
        let Content::Commit(commit) = &ac.content.content else { unreachable!() };
        let sender = ac.content.sender;
        if let Sender::Member(l) = sender {
            if l == self.private.leaf {
                return proto("cannot process own commit without a pending state");
            }
        }
        if matches!(sender, Sender::External(_) | Sender::NewMemberProposal) {
            return proto("commit from invalid sender type");
        }
        // Resolve proposals.
        let mut list: ProposalList = Vec::new();
        for por in &commit.proposals {
            match por {
                ProposalOrRef::Proposal(p) => {
                    if matches!(p, Proposal::Update(_)) {
                        return proto("Update proposal by value");
                    }
                    list.push((p.clone(), sender, None));
                }
                ProposalOrRef::Reference(r) => {
                    let cp = self.proposals.iter().find(|c| &c.reference == r).ok_or_else(|| Error::Protocol("unknown proposal reference".into()))?;
                    list.push((cp.proposal.clone(), cp.sender, Some(r.clone())));
                }
            }
        }
        if sender == Sender::NewMemberCommit {
            let inits = list.iter().filter(|(p, _, _)| matches!(p, Proposal::ExternalInit(_))).count();
            if inits != 1 {
                return proto("external commit needs exactly one ExternalInit");
            }
            for (p, _, r) in &list {
                match p {
                    Proposal::ExternalInit(_) | Proposal::PreSharedKey(_) if r.is_none() => {}
                    Proposal::Remove(_) if r.is_none() => {}
                    _ => return proto("external commit carries a disallowed proposal"),
                }
            }
        }

        let mut next = self.clone();
        next.pending = None;
        let applied = next.apply_proposals(&list, sender)?;
        if applied.path_required && commit.path.is_none() {
            return proto("commit requires a path");
        }
        let removed_self = applied.removed.contains(&self.private.leaf);

        // Locate the committer's leaf.
        let committer = match sender {
            Sender::Member(l) => l,
            Sender::NewMemberCommit => {
                let path = commit.path.as_ref().unwrap();
                next.tree.add_leaf(path.leaf_node.clone())
            }
            _ => unreachable!(),
        };
        if let Sender::Member(l) = sender {
            if next.tree.leaf(l).is_none() {
                return proto("committer is not a member");
            }
        }

        let excluded: HashSet<LeafIndex> = applied.added.iter().map(|(l, _)| *l).collect();
        let mut commit_secret = None;
        if let Some(path) = &commit.path {
            if path.leaf_node.encryption_key != next.tree.leaf(committer).map(|l| l.encryption_key.clone()).unwrap_or_default()
                && next.tree.has_encryption_key(&path.leaf_node.encryption_key)
            {
                return proto("UpdatePath reuses an encryption key");
            }
            next.validate_leaf_capabilities(&path.leaf_node)?;
            let gid = next.context.group_id.clone();
            let src = next.clone_context_source();
            if removed_self {
                treekem::merge_public(&mut next.tree, committer, path, &gid)?;
            } else {
                let (cs_secret, _) = treekem::process(&mut next.tree, &mut next.private, committer, path, &gid, &excluded, |t| src.provisional(t))?;
                commit_secret = Some(cs_secret);
            }
        }

        let summary = CommitSummary {
            sender: Some(committer),
            new_epoch: self.context.epoch + 1,
            added: applied.added.iter().map(|(l, _)| *l).collect(),
            removed: applied.removed.clone(),
            updated: applied.updated.clone(),
            self_removed: removed_self,
            reinit: applied.reinit.clone(),
        };
        if removed_self {
            self.active = false;
            self.pending = None;
            return Ok(summary);
        }

        let init_secret = match &applied.external_init {
            Some(kem_output) => {
                let (ext_priv, _) = self.secrets.external_pub(cs)?;
                cs.hpke().receive_export(&ext_priv, kem_output, &[], b"MLS 1.0 external init secret", cs.nh())?
            }
            None => self.secrets.init_secret.clone(),
        };
        let psk_secret = next.psk_secret_for(&applied.psk_ids)?;
        let tag = next.advance(ac, &init_secret, commit_secret.as_deref(), psk_secret.as_deref())?;
        let got = ac.auth.confirmation_tag.as_ref().ok_or_else(|| Error::Protocol("commit without confirmation tag".into()))?;
        if &tag != got {
            return proto("confirmation tag mismatch");
        }
        next.reinit = applied.reinit;
        if next.reinit.is_some() {
            next.active = false;
        }
        next.past = self.past.clone();
        if self.config.max_past_epochs > 0 {
            next.push_past(self.archive_epoch());
        }
        *self = next;
        Ok(summary)
    }

    // ------------------------------------------------------------------
    // External commit (RFC 9420 section 12.4.3.2)

    /// Join a group from its GroupInfo by external commit. Returns the new
    /// group state and the commit to send.
    pub fn join_external(
        gi: &GroupInfo,
        ratchet_tree: Option<RatchetTree>,
        signer: Signer,
        remove_prior: Option<LeafIndex>,
        psks: PskStore,
        config: GroupConfig,
    ) -> Result<(Group, MlsMessage)> {
        Self::join_external_with_psks(gi, ratchet_tree, signer, remove_prior, vec![], psks, config)
    }

    /// External commit that also injects PSKs (each id must resolve in `psks`).
    pub fn join_external_with_psks(
        gi: &GroupInfo,
        ratchet_tree: Option<RatchetTree>,
        signer: Signer,
        remove_prior: Option<LeafIndex>,
        psk_ids: Vec<PreSharedKeyId>,
        psks: PskStore,
        config: GroupConfig,
    ) -> Result<(Group, MlsMessage)> {
        let ctx = gi.group_context.clone();
        let cs = ctx.cipher_suite;
        cs.check()?;
        let tree = match ratchet_tree {
            Some(t) => t,
            None => RatchetTree::from_bytes(
                cs,
                &find_extension(&gi.extensions, ext_type::RATCHET_TREE).ok_or_else(|| Error::Protocol("no ratchet tree".into()))?.extension_data,
            )?,
        };
        let signer_leaf = tree.leaf(gi.signer).ok_or_else(|| Error::Protocol("GroupInfo signer not a member".into()))?;
        cs.verify_with_label(&signer_leaf.signature_key, "GroupInfoTBS", &gi.tbs(), &gi.signature)?;
        if tree.root_tree_hash() != ctx.tree_hash {
            return proto("tree hash mismatch");
        }
        validate_tree(&tree, &ctx.group_id)?;
        let ep = ExternalPub::from_bytes(
            &find_extension(&gi.extensions, ext_type::EXTERNAL_PUB).ok_or_else(|| Error::Protocol("no external_pub".into()))?.extension_data,
        )?;
        let (kem_output, init_secret) = cs.hpke().send_export(&ep.external_pub, &[], b"MLS 1.0 external init secret", cs.nh())?;
        let interim = ks::interim_transcript_hash(cs, &ctx.confirmed_transcript_hash, &gi.confirmation_tag);

        let mut proposals = vec![Proposal::ExternalInit(kem_output)];
        if let Some(l) = remove_prior {
            proposals.push(Proposal::Remove(l));
        }
        for id in psk_ids {
            proposals.push(Proposal::PreSharedKey(id));
        }
        // A provisional state at the current epoch, with throwaway secrets that are never used.
        let dummy = ks::from_joiner(cs, &vec![0u8; cs.nh()], None, &ctx.to_bytes())?;
        let mut g = Group {
            cs,
            context: ctx,
            secret_tree: SecretTree::new(cs, &dummy.encryption_secret, tree.n_leaves()),
            tree,
            private: TreePrivate::default(),
            secrets: dummy,
            interim_transcript_hash: interim,
            signer: signer.clone(),
            proposals: vec![],
            own_updates: HashMap::new(),
            pending: None,
            psks,
            past: VecDeque::new(),
            config,
            active: true,
            reinit: None,
        };
        let list: ProposalList = proposals.iter().map(|p| (p.clone(), Sender::NewMemberCommit, None)).collect();
        let applied = g.apply_proposals(&list, Sender::NewMemberCommit)?;

        let (enc_priv, enc_pub) = cs.generate_keypair();
        let mut leaf = LeafNode {
            encryption_key: enc_pub.clone(),
            signature_key: signer.signature_pub.clone(),
            credential: signer.credential.clone(),
            capabilities: default_capabilities(cs),
            leaf_node_source: LeafNodeSource::Commit(vec![]),
            extensions: vec![],
            signature: vec![],
        };
        leaf.sign(cs, &signer.signature_priv, None)?; // placeholder until the index is known
        let me = g.tree.add_leaf(leaf.clone());
        g.private = TreePrivate::new(me, enc_priv.clone());
        let gid = g.context.group_id.clone();
        let src = g.clone_context_source();
        let gen = treekem::generate(&mut g.tree, &mut g.private, me, leaf, enc_priv, &signer.signature_priv, &gid, &HashSet::new(), |t| src.provisional(t))?;

        let commit = Commit { proposals: proposals.into_iter().map(ProposalOrRef::Proposal).collect(), path: Some(gen.update_path) };
        let fc = FramedContent { group_id: gid, epoch: g.context.epoch, sender: Sender::NewMemberCommit, authenticated_data: vec![], content: Content::Commit(commit) };
        let mut ac = framing::sign_content(cs, &signer.signature_priv, WireFormat::PublicMessage, fc, Some(&g.context), None)?;
        let psk_secret = g.psk_secret_for(&applied.psk_ids)?;
        let tag = g.advance(&ac, &init_secret, Some(&gen.commit_secret), psk_secret.as_deref())?;
        ac.auth.confirmation_tag = Some(tag);
        let pm = PublicMessage { content: ac.content, auth: ac.auth, membership_tag: None };
        Ok((g, MlsMessage::Public(pm)))
    }
}

/// Builds the provisional GroupContext used to encrypt UpdatePath secrets.
struct ContextSource {
    cs: CipherSuite,
    context: GroupContext,
}

impl ContextSource {
    fn provisional(&self, tree: &RatchetTree) -> GroupContext {
        GroupContext {
            version: MLS10,
            cipher_suite: self.cs,
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch + 1,
            tree_hash: tree.root_tree_hash(),
            confirmed_transcript_hash: self.context.confirmed_transcript_hash.clone(),
            extensions: self.context.extensions.clone(),
        }
    }
}

fn check_required(rc: &RequiredCapabilities, caps: &Capabilities) -> Result<()> {
    for e in &rc.extension_types {
        if *e > 5 && !caps.extensions.contains(e) {
            return proto("member lacks a required extension");
        }
    }
    for p in &rc.proposal_types {
        if *p > 7 && !caps.proposals.contains(p) {
            return proto("member lacks a required proposal type");
        }
    }
    for c in &rc.credential_types {
        if !caps.credentials.contains(c) {
            return proto("member lacks a required credential type");
        }
    }
    Ok(())
}

/// Validate a tree received when joining (RFC 9420 section 12.4.3.1, step 6).
pub fn validate_tree(tree: &RatchetTree, group_id: &[u8]) -> Result<()> {
    tree.verify_parent_hashes()?;
    let mut enc = HashSet::new();
    let mut sig = HashSet::new();
    for (l, ln) in tree.members() {
        ln.verify(tree.cs, Some((group_id, l)))?;
        if !enc.insert(ln.encryption_key.clone()) || !sig.insert(ln.signature_key.clone()) {
            return proto("duplicate key in ratchet tree");
        }
    }
    for x in 0..(2 * tree.n_leaves() - 1) {
        if let Some(Node::Parent(p)) = tree.node(x) {
            if !enc.insert(p.encryption_key.clone()) {
                return proto("duplicate encryption key in ratchet tree");
            }
            for u in &p.unmerged_leaves {
                if tree.leaf(*u).is_none() || !tm::leaves_under(x).contains(u) {
                    return proto("bad unmerged leaf");
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "sim")]
impl Group {
    /// Experiment helper: this group's state as seen by another member whose
    /// signing key and leaf HPKE key the harness generated. Every member shares
    /// the public tree and epoch secrets, so a commit produced from this view is
    /// byte-for-byte a commit that member could have produced. Only the
    /// committer's own leaf key is needed to build a commit. Not for real use.
    pub fn impersonate(&self, leaf: LeafIndex, signer: Signer, leaf_priv: Vec<u8>) -> Group {
        let mut g = self.clone();
        g.private = TreePrivate::new(leaf, leaf_priv);
        g.signer = signer;
        g.pending = None;
        g.proposals.clear();
        g.own_updates.clear();
        g
    }

    /// Size in bytes of the serialized public ratchet tree.
    pub fn tree_bytes(&self) -> usize {
        self.tree.to_bytes().len()
    }
}

impl Group {
    /// Whether this handshake or application message was sent by us.
    pub fn is_own_message(&self, msg: &MlsMessage) -> bool {
        match msg {
            MlsMessage::Public(p) => p.content.sender == Sender::Member(self.private.leaf),
            MlsMessage::Private(p) if p.epoch == self.context.epoch => framing::decrypt_sender_data(self.cs, p, &self.secrets.sender_data_secret)
                .map(|sd| sd.leaf_index == self.private.leaf)
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Reference of a proposal message we sent or cached, if known.
    pub fn cached_reference_of(&self, p: &Proposal) -> Option<ProposalRef> {
        self.proposals.iter().find(|c| &c.proposal == p).map(|c| c.reference.clone())
    }

    /// Add an extension to the group context extensions (for a GroupContextExtensions proposal).
    pub fn extensions_with(&self, add: Extension) -> Vec<Extension> {
        let mut v: Vec<Extension> = self.context.extensions.iter().filter(|e| e.extension_type != add.extension_type).cloned().collect();
        v.push(add);
        v
    }

    /// Resumption PSK id for one of this group's past epochs.
    pub fn resumption_psk_id(&self, epoch: u64) -> PreSharedKeyId {
        PreSharedKeyId {
            psk: Psk::Resumption { usage: ResumptionPskUsage::Application, psk_group_id: self.context.group_id.clone(), psk_epoch: epoch },
            psk_nonce: random_bytes(self.cs.nh()),
        }
    }
}

/// A proposal from an external sender listed in the group's external_senders
/// extension (RFC 9420 section 12.1.8), as a PublicMessage.
pub fn external_proposal(cs: CipherSuite, ctx: &GroupContext, sender_index: u32, signature_priv: &[u8], proposal: Proposal) -> Result<MlsMessage> {
    let fc = FramedContent {
        group_id: ctx.group_id.clone(),
        epoch: ctx.epoch,
        sender: Sender::External(sender_index),
        authenticated_data: vec![],
        content: Content::Proposal(proposal),
    };
    let ac = framing::sign_content(cs, signature_priv, WireFormat::PublicMessage, fc, None, None)?;
    Ok(MlsMessage::Public(PublicMessage { content: ac.content, auth: ac.auth, membership_tag: None }))
}

/// A would-be member proposing its own Add (sender new_member_proposal).
pub fn new_member_add_proposal(ctx: &GroupContext, kpb: &KeyPackageBundle) -> Result<MlsMessage> {
    let fc = FramedContent {
        group_id: ctx.group_id.clone(),
        epoch: ctx.epoch,
        sender: Sender::NewMemberProposal,
        authenticated_data: vec![],
        content: Content::Proposal(Proposal::Add(kpb.key_package.clone())),
    };
    let ac = framing::sign_content(ctx.cipher_suite, &kpb.signer.signature_priv, WireFormat::PublicMessage, fc, None, None)?;
    Ok(MlsMessage::Public(PublicMessage { content: ac.content, auth: ac.auth, membership_tag: None }))
}
