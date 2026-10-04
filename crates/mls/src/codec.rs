//! TLS presentation language encoding as used by MLS (RFC 9420 section 2.1).
//!
//! Vectors carry a variable-length length prefix (the QUIC-style varint from
//! RFC 9000 section 16, restricted to 1, 2 or 4 bytes). Optional values carry a
//! one-byte presence flag.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid varint prefix")]
    BadVarint,
    #[error("varint not minimally encoded")]
    NonMinimalVarint,
    #[error("invalid enum value {0} for {1}")]
    BadEnum(u64, &'static str),
    #[error("invalid optional presence byte {0}")]
    BadOptional(u8),
    #[error("{0} trailing bytes")]
    Trailing(usize),
    #[error("vector length {0} does not fit its contents")]
    BadLength(usize),
    #[error("{0}")]
    Invalid(&'static str),
}

pub type Result<T> = std::result::Result<T, CodecError>;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(CodecError::Eof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn peek_u8(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(CodecError::Eof)
    }
    /// Bytes consumed between `start` and the current position.
    pub fn since(&self, start: usize) -> &'a [u8] {
        &self.buf[start..self.pos]
    }
    pub fn finish(&self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(CodecError::Trailing(self.remaining()));
        }
        Ok(())
    }
}

/// Encode a length with the MLS variable-length integer (1, 2 or 4 bytes).
pub fn write_varint(out: &mut Vec<u8>, n: usize) {
    if n < 1 << 6 {
        out.push(n as u8);
    } else if n < 1 << 14 {
        out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes());
    } else if n < 1 << 30 {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    } else {
        panic!("vector too long for MLS varint: {n}");
    }
}

pub fn read_varint(r: &mut Reader) -> Result<usize> {
    let first = r.take(1)?[0];
    let prefix = first >> 6;
    let v = match prefix {
        0 => (first & 0x3f) as usize,
        1 => {
            let b = r.take(1)?[0];
            let v = (((first & 0x3f) as usize) << 8) | b as usize;
            if v < 1 << 6 {
                return Err(CodecError::NonMinimalVarint);
            }
            v
        }
        2 => {
            let b = r.take(3)?;
            let v = (((first & 0x3f) as usize) << 24)
                | ((b[0] as usize) << 16)
                | ((b[1] as usize) << 8)
                | b[2] as usize;
            if v < 1 << 14 {
                return Err(CodecError::NonMinimalVarint);
            }
            v
        }
        _ => return Err(CodecError::BadVarint),
    };
    Ok(v)
}

pub trait Codec: Sized {
    fn encode(&self, out: &mut Vec<u8>);
    fn decode(r: &mut Reader) -> Result<Self>;

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
    /// Decode the whole buffer, rejecting trailing bytes.
    fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let v = Self::decode(&mut r)?;
        r.finish()?;
        Ok(v)
    }

    // Hooks so that Vec<u8> encodes as a byte string instead of element by element.
    #[doc(hidden)]
    fn encode_slice(items: &[Self], out: &mut Vec<u8>) {
        for i in items {
            i.encode(out);
        }
    }
    #[doc(hidden)]
    fn decode_vec(r: &mut Reader, len: usize) -> Result<Vec<Self>> {
        let body = r.take(len)?;
        let mut sub = Reader::new(body);
        let mut v = Vec::new();
        while !sub.is_empty() {
            v.push(Self::decode(&mut sub)?);
        }
        Ok(v)
    }
}

impl Codec for u8 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(r.take(1)?[0])
    }
    fn encode_slice(items: &[Self], out: &mut Vec<u8>) {
        out.extend_from_slice(items);
    }
    fn decode_vec(r: &mut Reader, len: usize) -> Result<Vec<Self>> {
        Ok(r.take(len)?.to_vec())
    }
}

macro_rules! impl_uint {
    ($t:ty, $n:expr) => {
        impl Codec for $t {
            fn encode(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn decode(r: &mut Reader) -> Result<Self> {
                let b = r.take($n)?;
                Ok(<$t>::from_be_bytes(b.try_into().unwrap()))
            }
        }
    };
}
impl_uint!(u16, 2);
impl_uint!(u32, 4);
impl_uint!(u64, 8);

impl<T: Codec> Codec for Vec<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        T::encode_slice(self, &mut body);
        write_varint(out, body.len());
        out.extend_from_slice(&body);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let len = read_varint(r)?;
        T::decode_vec(r, len)
    }
}

impl<T: Codec> Codec for Option<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode(out);
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match r.take(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(T::decode(r)?)),
            b => Err(CodecError::BadOptional(b)),
        }
    }
}

impl<T: Codec> Codec for Box<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        (**self).encode(out)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Box::new(T::decode(r)?))
    }
}

/// Encode a byte string with a varint length prefix.
pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varint(out, b.len());
    out.extend_from_slice(b);
}

/// Implement `Codec` for a struct by encoding its fields in order.
#[macro_export]
macro_rules! impl_codec {
    ($name:ident { $($field:ident),* $(,)? }) => {
        impl $crate::codec::Codec for $name {
            fn encode(&self, out: &mut Vec<u8>) {
                $( $crate::codec::Codec::encode(&self.$field, out); )*
            }
            fn decode(r: &mut $crate::codec::Reader) -> $crate::codec::Result<Self> {
                Ok($name { $( $field: $crate::codec::Codec::decode(r)?, )* })
            }
        }
    };
}

/// Implement `Codec` for a fieldless enum carried as an integer.
#[macro_export]
macro_rules! impl_codec_enum {
    ($name:ident : $repr:ty { $($variant:ident = $val:expr),* $(,)? }) => {
        impl $crate::codec::Codec for $name {
            fn encode(&self, out: &mut Vec<u8>) {
                let v: $repr = match self { $( $name::$variant => $val, )* };
                $crate::codec::Codec::encode(&v, out);
            }
            fn decode(r: &mut $crate::codec::Reader) -> $crate::codec::Result<Self> {
                let v = <$repr as $crate::codec::Codec>::decode(r)?;
                match v {
                    $( x if x == $val => Ok($name::$variant), )*
                    other => Err($crate::codec::CodecError::BadEnum(other as u64, stringify!($name))),
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn varint_roundtrip(n in 0usize..(1 << 30)) {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            let mut r = Reader::new(&v);
            prop_assert_eq!(read_varint(&mut r).unwrap(), n);
            prop_assert!(r.is_empty());
        }

        #[test]
        fn bytes_roundtrip(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let enc = b.to_bytes();
            prop_assert_eq!(Vec::<u8>::from_bytes(&enc).unwrap(), b);
        }
    }

    #[test]
    fn rejects_non_minimal_and_reserved() {
        assert_eq!(read_varint(&mut Reader::new(&[0x40, 0x01])), Err(CodecError::NonMinimalVarint));
        assert_eq!(read_varint(&mut Reader::new(&[0xc0, 0, 0, 0])), Err(CodecError::BadVarint));
    }
}
