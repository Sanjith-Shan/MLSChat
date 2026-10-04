//! Client/server protocol, carried in binary WebSocket frames and encoded with
//! the same TLS presentation codec as MLS itself.
//!
//! The server reads only MLS framing headers (group id, epoch, content type),
//! never message contents, which it cannot decrypt.

use mls::codec::{Codec, CodecError, Reader, Result};

pub type ClientId = Vec<u8>;
pub type GroupId = Vec<u8>;
/// Client-chosen idempotency key: resending the same id never appends twice.
pub type MsgId = Vec<u8>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

impl Codec for Kind {
    fn encode(&self, out: &mut Vec<u8>) {
        (*self as u8).encode(out)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(match u8::decode(r)? {
            1 => Kind::Application,
            2 => Kind::Proposal,
            3 => Kind::Commit,
            x => return Err(CodecError::BadEnum(x as u64, "Kind")),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectCode {
    /// Commit or proposal for an epoch that is not the group's current epoch.
    StaleEpoch = 1,
    NotMember = 2,
    UnknownGroup = 3,
    GroupExists = 4,
    Malformed = 5,
    /// Application message from an epoch too old to be decrypted.
    TooOld = 6,
}

impl Codec for RejectCode {
    fn encode(&self, out: &mut Vec<u8>) {
        (*self as u8).encode(out)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(match u8::decode(r)? {
            1 => RejectCode::StaleEpoch,
            2 => RejectCode::NotMember,
            3 => RejectCode::UnknownGroup,
            4 => RejectCode::GroupExists,
            5 => RejectCode::Malformed,
            6 => RejectCode::TooOld,
            x => return Err(CodecError::BadEnum(x as u64, "RejectCode")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendReq {
    pub req_id: u64,
    pub group_id: GroupId,
    pub msg_id: MsgId,
    /// Serialized MLSMessage (PublicMessage or PrivateMessage).
    pub payload: Vec<u8>,
    /// Devices added by this commit; they receive `welcome`.
    pub add_members: Vec<ClientId>,
    /// Devices removed by this commit; they stop receiving fan-out after it.
    pub remove_members: Vec<ClientId>,
    pub welcome: Option<Vec<u8>>,
}
mls::impl_codec!(SendReq { req_id, group_id, msg_id, payload, add_members, remove_members, welcome });

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMsg {
    Hello { client_id: ClientId },
    PublishKeyPackage { key_package: Vec<u8> },
    FetchKeyPackage { req_id: u64, client_id: ClientId },
    CreateGroup { req_id: u64, group_id: GroupId },
    Send(SendReq),
    /// Replay the group log from `from_seq` (inclusive).
    Fetch { group_id: GroupId, from_seq: u64 },
    /// Persist that this device has processed the log up to `seq`.
    Ack { group_id: GroupId, seq: u64 },
    /// Replay this device's inbox (Welcomes) from `from_seq`.
    FetchInbox { from_seq: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub group_id: GroupId,
    pub seq: u64,
    pub sender: ClientId,
    pub kind: Kind,
    pub epoch: u64,
    pub msg_id: MsgId,
    pub payload: Vec<u8>,
}
mls::impl_codec!(Delivery { group_id, seq, sender, kind, epoch, msg_id, payload });

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMsg {
    /// Handshake reply with the device's stored cursors: (group, last acked seq).
    HelloOk { cursors: Vec<Cursor>, inbox_next: u64 },
    KeyPackage { req_id: u64, key_package: Option<Vec<u8>> },
    GroupCreated { req_id: u64, ok: bool },
    Accepted { req_id: u64, msg_id: MsgId, seq: u64, epoch: u64, duplicate: bool },
    Rejected { req_id: u64, msg_id: MsgId, code: RejectCode, current_epoch: u64 },
    Deliver(Delivery),
    /// Log replay finished; `next_seq` is one past the last entry.
    FetchDone { group_id: GroupId, next_seq: u64 },
    /// A Welcome; the joiner reads the group log from `start_seq`.
    Welcome { inbox_seq: u64, group_id: GroupId, start_seq: u64, welcome: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub group_id: GroupId,
    pub seq: u64,
}
mls::impl_codec!(Cursor { group_id, seq });

impl Codec for ClientMsg {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ClientMsg::Hello { client_id } => {
                1u8.encode(out);
                client_id.encode(out);
            }
            ClientMsg::PublishKeyPackage { key_package } => {
                2u8.encode(out);
                key_package.encode(out);
            }
            ClientMsg::FetchKeyPackage { req_id, client_id } => {
                3u8.encode(out);
                req_id.encode(out);
                client_id.encode(out);
            }
            ClientMsg::CreateGroup { req_id, group_id } => {
                4u8.encode(out);
                req_id.encode(out);
                group_id.encode(out);
            }
            ClientMsg::Send(s) => {
                5u8.encode(out);
                s.encode(out);
            }
            ClientMsg::Fetch { group_id, from_seq } => {
                6u8.encode(out);
                group_id.encode(out);
                from_seq.encode(out);
            }
            ClientMsg::Ack { group_id, seq } => {
                7u8.encode(out);
                group_id.encode(out);
                seq.encode(out);
            }
            ClientMsg::FetchInbox { from_seq } => {
                8u8.encode(out);
                from_seq.encode(out);
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(match u8::decode(r)? {
            1 => ClientMsg::Hello { client_id: Codec::decode(r)? },
            2 => ClientMsg::PublishKeyPackage { key_package: Codec::decode(r)? },
            3 => ClientMsg::FetchKeyPackage { req_id: Codec::decode(r)?, client_id: Codec::decode(r)? },
            4 => ClientMsg::CreateGroup { req_id: Codec::decode(r)?, group_id: Codec::decode(r)? },
            5 => ClientMsg::Send(Codec::decode(r)?),
            6 => ClientMsg::Fetch { group_id: Codec::decode(r)?, from_seq: Codec::decode(r)? },
            7 => ClientMsg::Ack { group_id: Codec::decode(r)?, seq: Codec::decode(r)? },
            8 => ClientMsg::FetchInbox { from_seq: Codec::decode(r)? },
            x => return Err(CodecError::BadEnum(x as u64, "ClientMsg")),
        })
    }
}

impl Codec for ServerMsg {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ServerMsg::HelloOk { cursors, inbox_next } => {
                1u8.encode(out);
                cursors.encode(out);
                inbox_next.encode(out);
            }
            ServerMsg::KeyPackage { req_id, key_package } => {
                2u8.encode(out);
                req_id.encode(out);
                key_package.encode(out);
            }
            ServerMsg::GroupCreated { req_id, ok } => {
                3u8.encode(out);
                req_id.encode(out);
                (*ok as u8).encode(out);
            }
            ServerMsg::Accepted { req_id, msg_id, seq, epoch, duplicate } => {
                4u8.encode(out);
                req_id.encode(out);
                msg_id.encode(out);
                seq.encode(out);
                epoch.encode(out);
                (*duplicate as u8).encode(out);
            }
            ServerMsg::Rejected { req_id, msg_id, code, current_epoch } => {
                5u8.encode(out);
                req_id.encode(out);
                msg_id.encode(out);
                code.encode(out);
                current_epoch.encode(out);
            }
            ServerMsg::Deliver(d) => {
                6u8.encode(out);
                d.encode(out);
            }
            ServerMsg::FetchDone { group_id, next_seq } => {
                7u8.encode(out);
                group_id.encode(out);
                next_seq.encode(out);
            }
            ServerMsg::Welcome { inbox_seq, group_id, start_seq, welcome } => {
                8u8.encode(out);
                inbox_seq.encode(out);
                group_id.encode(out);
                start_seq.encode(out);
                welcome.encode(out);
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let bool8 = |r: &mut Reader| -> Result<bool> {
            match u8::decode(r)? {
                0 => Ok(false),
                1 => Ok(true),
                x => Err(CodecError::BadEnum(x as u64, "bool")),
            }
        };
        Ok(match u8::decode(r)? {
            1 => ServerMsg::HelloOk { cursors: Codec::decode(r)?, inbox_next: Codec::decode(r)? },
            2 => ServerMsg::KeyPackage { req_id: Codec::decode(r)?, key_package: Codec::decode(r)? },
            3 => ServerMsg::GroupCreated { req_id: Codec::decode(r)?, ok: bool8(r)? },
            4 => ServerMsg::Accepted {
                req_id: Codec::decode(r)?,
                msg_id: Codec::decode(r)?,
                seq: Codec::decode(r)?,
                epoch: Codec::decode(r)?,
                duplicate: bool8(r)?,
            },
            5 => ServerMsg::Rejected { req_id: Codec::decode(r)?, msg_id: Codec::decode(r)?, code: Codec::decode(r)?, current_epoch: Codec::decode(r)? },
            6 => ServerMsg::Deliver(Codec::decode(r)?),
            7 => ServerMsg::FetchDone { group_id: Codec::decode(r)?, next_seq: Codec::decode(r)? },
            8 => ServerMsg::Welcome { inbox_seq: Codec::decode(r)?, group_id: Codec::decode(r)?, start_seq: Codec::decode(r)?, welcome: Codec::decode(r)? },
            x => return Err(CodecError::BadEnum(x as u64, "ServerMsg")),
        })
    }
}

/// The routing header the server reads from an MLSMessage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub group_id: GroupId,
    pub epoch: u64,
    pub kind: Kind,
}

/// Parse only the framing header of a PublicMessage or PrivateMessage.
pub fn parse_header(payload: &[u8]) -> Result<Header> {
    use mls::messages::{ContentType, MlsMessage};
    let m = MlsMessage::from_bytes(payload)?;
    let (group_id, epoch, ct) = match &m {
        MlsMessage::Public(p) => (p.content.group_id.clone(), p.content.epoch, p.content.content.content_type()),
        MlsMessage::Private(p) => (p.group_id.clone(), p.epoch, p.content_type),
        _ => return Err(CodecError::Invalid("not a group message")),
    };
    let kind = match ct {
        ContentType::Application => Kind::Application,
        ContentType::Proposal => Kind::Proposal,
        ContentType::Commit => Kind::Commit,
    };
    Ok(Header { group_id, epoch, kind })
}
