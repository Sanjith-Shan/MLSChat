use crate::codec::CodecError;
use crate::crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("message for epoch {got}, group is at epoch {want}")]
    WrongEpoch { got: u64, want: u64 },
    #[error("generation {0} already used or too far in the past")]
    GenerationGone(u32),
    #[error("generation {0} too far ahead")]
    GenerationTooFar(u32),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn proto<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(msg.into()))
}

#[macro_export]
macro_rules! ensure_proto {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            return Err($crate::error::Error::Protocol(format!($($arg)*)));
        }
    };
}
