//! An implementation of the Messaging Layer Security protocol (RFC 9420),
//! written from the RFC and checked against the `mlswg/mls-implementations`
//! test vectors. Not audited. Do not use it to protect real conversations.

pub mod codec;
pub mod crypto;
pub mod tree_math;

pub use codec::{Codec, CodecError, Reader};
pub use crypto::CipherSuite;
