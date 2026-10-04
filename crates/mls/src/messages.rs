//! Wire structures from RFC 9420, with their TLS encodings.

use crate::codec::{Codec, CodecError, Reader, Result};
use crate::crypto::CipherSuite;
use crate::{impl_codec, impl_codec_enum};

pub type HpkePublicKey = Vec<u8>;
pub type SignaturePublicKey = Vec<u8>;
pub type ProposalRef = Vec<u8>;
pub type KeyPackageRef = Vec<u8>;

pub const MLS10: u16 = 1;

// ---------------------------------------------------------------------------
// Basic enums

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    Application,
    Proposal,
    Commit,
}
impl_codec_enum!(ContentType: u8 { Application = 1, Proposal = 2, Commit = 3 });

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFormat {
    PublicMessage,
    PrivateMessage,
    Welcome,
    GroupInfo,
    KeyPackage,
}
impl_codec_enum!(WireFormat: u16 { PublicMessage = 1, PrivateMessage = 2, Welcome = 3, GroupInfo = 4, KeyPackage = 5 });

pub mod ext_type {
    pub const APPLICATION_ID: u16 = 1;
    pub const RATCHET_TREE: u16 = 2;
    pub const REQUIRED_CAPABILITIES: u16 = 3;
    pub const EXTERNAL_PUB: u16 = 4;
    pub const EXTERNAL_SENDERS: u16 = 5;
}

pub mod proposal_type {
    pub const ADD: u16 = 1;
    pub const UPDATE: u16 = 2;
    pub const REMOVE: u16 = 3;
    pub const PSK: u16 = 4;
    pub const REINIT: u16 = 5;
    pub const EXTERNAL_INIT: u16 = 6;
    pub const GROUP_CONTEXT_EXTENSIONS: u16 = 7;
}

pub mod credential_type {
    pub const BASIC: u16 = 1;
    pub const X509: u16 = 2;
}

// ---------------------------------------------------------------------------
// Credentials, capabilities, extensions

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub cert_data: Vec<u8>,
}
impl_codec!(Certificate { cert_data });

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    Basic(Vec<u8>),
    X509(Vec<Certificate>),
}

impl Credential {
    pub fn credential_type(&self) -> u16 {
        match self {
            Credential::Basic(_) => credential_type::BASIC,
            Credential::X509(_) => credential_type::X509,
        }
    }
    pub fn identity(&self) -> &[u8] {
        match self {
            Credential::Basic(id) => id,
            Credential::X509(c) => c.first().map(|c| c.cert_data.as_slice()).unwrap_or(&[]),
        }
    }
}

impl Codec for Credential {
    fn encode(&self, out: &mut Vec<u8>) {
        self.credential_type().encode(out);
        match self {
            Credential::Basic(id) => id.encode(out),
            Credential::X509(c) => c.encode(out),
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match u16::decode(r)? {
            credential_type::BASIC => Ok(Credential::Basic(Codec::decode(r)?)),
            credential_type::X509 => Ok(Credential::X509(Codec::decode(r)?)),
            t => Err(CodecError::BadEnum(t as u64, "CredentialType")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
}
impl_codec!(Capabilities { versions, cipher_suites, extensions, proposals, credentials });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64,
}
impl_codec!(Lifetime { not_before, not_after });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}
impl_codec!(Extension { extension_type, extension_data });

pub fn find_extension(exts: &[Extension], t: u16) -> Option<&Extension> {
    exts.iter().find(|e| e.extension_type == t)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredCapabilities {
    pub extension_types: Vec<u16>,
    pub proposal_types: Vec<u16>,
    pub credential_types: Vec<u16>,
}
impl_codec!(RequiredCapabilities { extension_types, proposal_types, credential_types });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalSender {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}
impl_codec!(ExternalSender { signature_key, credential });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalPub {
    pub external_pub: HpkePublicKey,
}
impl_codec!(ExternalPub { external_pub });

// ---------------------------------------------------------------------------
// Leaf nodes and key packages

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafNodeSource {
    KeyPackage(Lifetime),
    Update,
    Commit(Vec<u8>),
}

impl Codec for LeafNodeSource {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            LeafNodeSource::KeyPackage(l) => {
                1u8.encode(out);
                l.encode(out)
            }
            LeafNodeSource::Update => 2u8.encode(out),
            LeafNodeSource::Commit(ph) => {
                3u8.encode(out);
                ph.encode(out)
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match u8::decode(r)? {
            1 => Ok(LeafNodeSource::KeyPackage(Lifetime::decode(r)?)),
            2 => Ok(LeafNodeSource::Update),
            3 => Ok(LeafNodeSource::Commit(Codec::decode(r)?)),
            t => Err(CodecError::BadEnum(t as u64, "LeafNodeSource")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNode {
    pub encryption_key: HpkePublicKey,
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
}
impl_codec!(LeafNode { encryption_key, signature_key, credential, capabilities, leaf_node_source, extensions, signature });

impl LeafNode {
    /// LeafNodeTBS. `group` is (group_id, leaf_index) for update and commit sources.
    pub fn tbs(&self, group: Option<(&[u8], u32)>) -> Vec<u8> {
        let mut out = Vec::new();
        self.encryption_key.encode(&mut out);
        self.signature_key.encode(&mut out);
        self.credential.encode(&mut out);
        self.capabilities.encode(&mut out);
        self.leaf_node_source.encode(&mut out);
        self.extensions.encode(&mut out);
        match self.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => {}
            _ => {
                let (gid, li) = group.unwrap_or((&[], 0));
                gid.to_vec().encode(&mut out);
                li.encode(&mut out);
            }
        }
        out
    }

    pub fn sign(&mut self, cs: CipherSuite, sk: &[u8], group: Option<(&[u8], u32)>) -> crate::crypto::CResult<()> {
        self.signature = cs.sign_with_label(sk, "LeafNodeTBS", &self.tbs(group))?;
        Ok(())
    }

    pub fn verify(&self, cs: CipherSuite, group: Option<(&[u8], u32)>) -> crate::crypto::CResult<()> {
        cs.verify_with_label(&self.signature_key, "LeafNodeTBS", &self.tbs(group), &self.signature)
    }

    pub fn parent_hash(&self) -> Option<&[u8]> {
        match &self.leaf_node_source {
            LeafNodeSource::Commit(ph) => Some(ph),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackage {
    pub version: u16,
    pub cipher_suite: CipherSuite,
    pub init_key: HpkePublicKey,
    pub leaf_node: LeafNode,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
}
impl_codec!(KeyPackage { version, cipher_suite, init_key, leaf_node, extensions, signature });

impl KeyPackage {
    pub fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.version.encode(&mut out);
        self.cipher_suite.encode(&mut out);
        self.init_key.encode(&mut out);
        self.leaf_node.encode(&mut out);
        self.extensions.encode(&mut out);
        out
    }
    pub fn reference(&self) -> KeyPackageRef {
        self.cipher_suite.ref_hash("MLS 1.0 KeyPackage Reference", &self.to_bytes())
    }
    pub fn verify(&self) -> crate::crypto::CResult<()> {
        let cs = self.cipher_suite;
        cs.verify_with_label(&self.leaf_node.signature_key, "KeyPackageTBS", &self.tbs(), &self.signature)
    }
}

// ---------------------------------------------------------------------------
// Ratchet tree nodes

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentNode {
    pub encryption_key: HpkePublicKey,
    pub parent_hash: Vec<u8>,
    pub unmerged_leaves: Vec<u32>,
}
impl_codec!(ParentNode { encryption_key, parent_hash, unmerged_leaves });

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Leaf(LeafNode),
    Parent(ParentNode),
}

impl Node {
    pub fn encryption_key(&self) -> &[u8] {
        match self {
            Node::Leaf(l) => &l.encryption_key,
            Node::Parent(p) => &p.encryption_key,
        }
    }
}

impl Codec for Node {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Node::Leaf(l) => {
                1u8.encode(out);
                l.encode(out)
            }
            Node::Parent(p) => {
                2u8.encode(out);
                p.encode(out)
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match u8::decode(r)? {
            1 => Ok(Node::Leaf(LeafNode::decode(r)?)),
            2 => Ok(Node::Parent(ParentNode::decode(r)?)),
            t => Err(CodecError::BadEnum(t as u64, "NodeType")),
        }
    }
}

/// `optional<Node> ratchet_tree<V>` as carried in the ratchet_tree extension.
pub type RatchetTreeNodes = Vec<Option<Node>>;

// ---------------------------------------------------------------------------
// Pre-shared keys

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumptionPskUsage {
    Application,
    Reinit,
    Branch,
}
impl_codec_enum!(ResumptionPskUsage: u8 { Application = 1, Reinit = 2, Branch = 3 });

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Psk {
    External { psk_id: Vec<u8> },
    Resumption { usage: ResumptionPskUsage, psk_group_id: Vec<u8>, psk_epoch: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreSharedKeyId {
    pub psk: Psk,
    pub psk_nonce: Vec<u8>,
}

impl Codec for PreSharedKeyId {
    fn encode(&self, out: &mut Vec<u8>) {
        match &self.psk {
            Psk::External { psk_id } => {
                1u8.encode(out);
                psk_id.encode(out)
            }
            Psk::Resumption { usage, psk_group_id, psk_epoch } => {
                2u8.encode(out);
                usage.encode(out);
                psk_group_id.encode(out);
                psk_epoch.encode(out);
            }
        }
        self.psk_nonce.encode(out);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let psk = match u8::decode(r)? {
            1 => Psk::External { psk_id: Codec::decode(r)? },
            2 => Psk::Resumption { usage: Codec::decode(r)?, psk_group_id: Codec::decode(r)?, psk_epoch: Codec::decode(r)? },
            t => return Err(CodecError::BadEnum(t as u64, "PSKType")),
        };
        Ok(PreSharedKeyId { psk, psk_nonce: Codec::decode(r)? })
    }
}

// ---------------------------------------------------------------------------
// Proposals and commits

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReInit {
    pub group_id: Vec<u8>,
    pub version: u16,
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<Extension>,
}
impl_codec!(ReInit { group_id, version, cipher_suite, extensions });

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal {
    Add(KeyPackage),
    Update(LeafNode),
    Remove(u32),
    PreSharedKey(PreSharedKeyId),
    ReInit(ReInit),
    ExternalInit(Vec<u8>),
    GroupContextExtensions(Vec<Extension>),
}

impl Proposal {
    pub fn proposal_type(&self) -> u16 {
        use proposal_type::*;
        match self {
            Proposal::Add(_) => ADD,
            Proposal::Update(_) => UPDATE,
            Proposal::Remove(_) => REMOVE,
            Proposal::PreSharedKey(_) => PSK,
            Proposal::ReInit(_) => REINIT,
            Proposal::ExternalInit(_) => EXTERNAL_INIT,
            Proposal::GroupContextExtensions(_) => GROUP_CONTEXT_EXTENSIONS,
        }
    }
}

impl Codec for Proposal {
    fn encode(&self, out: &mut Vec<u8>) {
        self.proposal_type().encode(out);
        match self {
            Proposal::Add(kp) => kp.encode(out),
            Proposal::Update(ln) => ln.encode(out),
            Proposal::Remove(i) => i.encode(out),
            Proposal::PreSharedKey(p) => p.encode(out),
            Proposal::ReInit(r) => r.encode(out),
            Proposal::ExternalInit(k) => k.encode(out),
            Proposal::GroupContextExtensions(e) => e.encode(out),
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        use proposal_type::*;
        Ok(match u16::decode(r)? {
            ADD => Proposal::Add(Codec::decode(r)?),
            UPDATE => Proposal::Update(Codec::decode(r)?),
            REMOVE => Proposal::Remove(Codec::decode(r)?),
            PSK => Proposal::PreSharedKey(Codec::decode(r)?),
            REINIT => Proposal::ReInit(Codec::decode(r)?),
            EXTERNAL_INIT => Proposal::ExternalInit(Codec::decode(r)?),
            GROUP_CONTEXT_EXTENSIONS => Proposal::GroupContextExtensions(Codec::decode(r)?),
            t => return Err(CodecError::BadEnum(t as u64, "ProposalType")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalOrRef {
    Proposal(Proposal),
    Reference(ProposalRef),
}

impl Codec for ProposalOrRef {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ProposalOrRef::Proposal(p) => {
                1u8.encode(out);
                p.encode(out)
            }
            ProposalOrRef::Reference(r) => {
                2u8.encode(out);
                r.encode(out)
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match u8::decode(r)? {
            1 => Ok(ProposalOrRef::Proposal(Codec::decode(r)?)),
            2 => Ok(ProposalOrRef::Reference(Codec::decode(r)?)),
            t => Err(CodecError::BadEnum(t as u64, "ProposalOrRefType")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeCiphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
impl_codec!(HpkeCiphertext { kem_output, ciphertext });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePathNode {
    pub encryption_key: HpkePublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}
impl_codec!(UpdatePathNode { encryption_key, encrypted_path_secret });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePath {
    pub leaf_node: LeafNode,
    pub nodes: Vec<UpdatePathNode>,
}
impl_codec!(UpdatePath { leaf_node, nodes });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}
impl_codec!(Commit { proposals, path });

// ---------------------------------------------------------------------------
// Framing

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Member(u32),
    External(u32),
    NewMemberProposal,
    NewMemberCommit,
}

impl Codec for Sender {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Sender::Member(i) => {
                1u8.encode(out);
                i.encode(out)
            }
            Sender::External(i) => {
                2u8.encode(out);
                i.encode(out)
            }
            Sender::NewMemberProposal => 3u8.encode(out),
            Sender::NewMemberCommit => 4u8.encode(out),
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(match u8::decode(r)? {
            1 => Sender::Member(Codec::decode(r)?),
            2 => Sender::External(Codec::decode(r)?),
            3 => Sender::NewMemberProposal,
            4 => Sender::NewMemberCommit,
            t => return Err(CodecError::BadEnum(t as u64, "SenderType")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}

impl Content {
    pub fn content_type(&self) -> ContentType {
        match self {
            Content::Application(_) => ContentType::Application,
            Content::Proposal(_) => ContentType::Proposal,
            Content::Commit(_) => ContentType::Commit,
        }
    }
    /// Encode only the body selected by the content type.
    pub fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Content::Application(a) => a.encode(out),
            Content::Proposal(p) => p.encode(out),
            Content::Commit(c) => c.encode(out),
        }
    }
    pub fn decode_body(ct: ContentType, r: &mut Reader) -> Result<Self> {
        Ok(match ct {
            ContentType::Application => Content::Application(Codec::decode(r)?),
            ContentType::Proposal => Content::Proposal(Codec::decode(r)?),
            ContentType::Commit => Content::Commit(Codec::decode(r)?),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedContent {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub authenticated_data: Vec<u8>,
    pub content: Content,
}

impl Codec for FramedContent {
    fn encode(&self, out: &mut Vec<u8>) {
        self.group_id.encode(out);
        self.epoch.encode(out);
        self.sender.encode(out);
        self.authenticated_data.encode(out);
        self.content.content_type().encode(out);
        self.content.encode_body(out);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let group_id = Codec::decode(r)?;
        let epoch = Codec::decode(r)?;
        let sender = Codec::decode(r)?;
        let authenticated_data = Codec::decode(r)?;
        let ct = ContentType::decode(r)?;
        let content = Content::decode_body(ct, r)?;
        Ok(FramedContent { group_id, epoch, sender, authenticated_data, content })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedContentAuthData {
    pub signature: Vec<u8>,
    /// Present exactly when the content is a commit.
    pub confirmation_tag: Option<Vec<u8>>,
}

impl FramedContentAuthData {
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.signature.encode(out);
        if let Some(t) = &self.confirmation_tag {
            t.encode(out);
        }
    }
    pub fn decode(ct: ContentType, r: &mut Reader) -> Result<Self> {
        let signature = Codec::decode(r)?;
        let confirmation_tag = if ct == ContentType::Commit { Some(Codec::decode(r)?) } else { None };
        Ok(FramedContentAuthData { signature, confirmation_tag })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupContext {
    pub version: u16,
    pub cipher_suite: CipherSuite,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
}
impl_codec!(GroupContext { version, cipher_suite, group_id, epoch, tree_hash, confirmed_transcript_hash, extensions });

/// FramedContentTBS. `context` is required for member and new_member_commit senders.
pub fn framed_content_tbs(wire_format: WireFormat, content: &FramedContent, context: Option<&GroupContext>) -> Vec<u8> {
    let mut out = Vec::new();
    MLS10.encode(&mut out);
    wire_format.encode(&mut out);
    content.encode(&mut out);
    match content.sender {
        Sender::Member(_) | Sender::NewMemberCommit => {
            context.expect("group context required for member senders").encode(&mut out)
        }
        _ => {}
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedContent {
    pub wire_format: WireFormat,
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
}

impl Codec for AuthenticatedContent {
    fn encode(&self, out: &mut Vec<u8>) {
        self.wire_format.encode(out);
        self.content.encode(out);
        self.auth.encode(out);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let wire_format = Codec::decode(r)?;
        let content = FramedContent::decode(r)?;
        let auth = FramedContentAuthData::decode(content.content.content_type(), r)?;
        Ok(AuthenticatedContent { wire_format, content, auth })
    }
}

impl AuthenticatedContent {
    /// Input to the confirmed transcript hash: wire format, content, signature.
    pub fn confirmed_transcript_input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.wire_format.encode(&mut out);
        self.content.encode(&mut out);
        self.auth.signature.encode(&mut out);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicMessage {
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
    pub membership_tag: Option<Vec<u8>>,
}

impl Codec for PublicMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        self.content.encode(out);
        self.auth.encode(out);
        if let Some(t) = &self.membership_tag {
            t.encode(out);
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let content = FramedContent::decode(r)?;
        let auth = FramedContentAuthData::decode(content.content.content_type(), r)?;
        let membership_tag = if matches!(content.sender, Sender::Member(_)) { Some(Codec::decode(r)?) } else { None };
        Ok(PublicMessage { content, auth, membership_tag })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
impl_codec!(PrivateMessage { group_id, epoch, content_type, authenticated_data, encrypted_sender_data, ciphertext });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderData {
    pub leaf_index: u32,
    pub generation: u32,
    pub reuse_guard: [u8; 4],
}

impl Codec for SenderData {
    fn encode(&self, out: &mut Vec<u8>) {
        self.leaf_index.encode(out);
        self.generation.encode(out);
        out.extend_from_slice(&self.reuse_guard);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let leaf_index = Codec::decode(r)?;
        let generation = Codec::decode(r)?;
        let reuse_guard = r.take(4)?.try_into().unwrap();
        Ok(SenderData { leaf_index, generation, reuse_guard })
    }
}

// ---------------------------------------------------------------------------
// Group info and welcome

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_context: GroupContext,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Vec<u8>,
    pub signer: u32,
    pub signature: Vec<u8>,
}
impl_codec!(GroupInfo { group_context, extensions, confirmation_tag, signer, signature });

impl GroupInfo {
    pub fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.group_context.encode(&mut out);
        self.extensions.encode(&mut out);
        self.confirmation_tag.encode(&mut out);
        self.signer.encode(&mut out);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathSecret {
    pub path_secret: Vec<u8>,
}
impl_codec!(PathSecret { path_secret });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSecrets {
    pub joiner_secret: Vec<u8>,
    pub path_secret: Option<PathSecret>,
    pub psks: Vec<PreSharedKeyId>,
}
impl_codec!(GroupSecrets { joiner_secret, path_secret, psks });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
}
impl_codec!(EncryptedGroupSecrets { new_member, encrypted_group_secrets });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub cipher_suite: CipherSuite,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: Vec<u8>,
}
impl_codec!(Welcome { cipher_suite, secrets, encrypted_group_info });

// ---------------------------------------------------------------------------
// MLSMessage

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsMessage {
    Public(PublicMessage),
    Private(PrivateMessage),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}

impl MlsMessage {
    pub fn wire_format(&self) -> WireFormat {
        match self {
            MlsMessage::Public(_) => WireFormat::PublicMessage,
            MlsMessage::Private(_) => WireFormat::PrivateMessage,
            MlsMessage::Welcome(_) => WireFormat::Welcome,
            MlsMessage::GroupInfo(_) => WireFormat::GroupInfo,
            MlsMessage::KeyPackage(_) => WireFormat::KeyPackage,
        }
    }
    pub fn epoch(&self) -> Option<u64> {
        match self {
            MlsMessage::Public(p) => Some(p.content.epoch),
            MlsMessage::Private(p) => Some(p.epoch),
            _ => None,
        }
    }
    pub fn group_id(&self) -> Option<&[u8]> {
        match self {
            MlsMessage::Public(p) => Some(&p.content.group_id),
            MlsMessage::Private(p) => Some(&p.group_id),
            _ => None,
        }
    }
}

impl Codec for MlsMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        MLS10.encode(out);
        self.wire_format().encode(out);
        match self {
            MlsMessage::Public(m) => m.encode(out),
            MlsMessage::Private(m) => m.encode(out),
            MlsMessage::Welcome(m) => m.encode(out),
            MlsMessage::GroupInfo(m) => m.encode(out),
            MlsMessage::KeyPackage(m) => m.encode(out),
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let v = u16::decode(r)?;
        if v != MLS10 {
            return Err(CodecError::BadEnum(v as u64, "ProtocolVersion"));
        }
        Ok(match WireFormat::decode(r)? {
            WireFormat::PublicMessage => MlsMessage::Public(Codec::decode(r)?),
            WireFormat::PrivateMessage => MlsMessage::Private(Codec::decode(r)?),
            WireFormat::Welcome => MlsMessage::Welcome(Codec::decode(r)?),
            WireFormat::GroupInfo => MlsMessage::GroupInfo(Codec::decode(r)?),
            WireFormat::KeyPackage => MlsMessage::KeyPackage(Codec::decode(r)?),
        })
    }
}
