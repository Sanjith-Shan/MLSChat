//! An implementation of the Messaging Layer Security protocol (RFC 9420),
//! written from the RFC and checked against the `mlswg/mls-implementations`
//! test vectors. Not audited. Do not use it to protect real conversations.

pub mod codec;
pub mod crypto;
pub mod error;
pub mod framing;
pub mod group;
pub mod key_schedule;
pub mod secret_tree;
pub mod messages;
pub mod tree;
pub mod tree_math;
pub mod treekem;

pub use codec::{Codec, CodecError, Reader};
pub use crypto::CipherSuite;
pub use error::{Error, Result};
pub use group::{CommitOptions, CommitOutput, Group, GroupConfig, KeyPackageBundle, Processed, PskStore, Signer};
