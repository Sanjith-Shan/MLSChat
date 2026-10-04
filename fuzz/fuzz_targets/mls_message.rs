//! Any MLSMessage that decodes must re-encode to exactly the same bytes
//! (the codec accepts only canonical encodings), and decoding must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mls::messages::*;
use mls::Codec;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = MlsMessage::from_bytes(data) {
        assert_eq!(m.to_bytes(), data, "non-canonical MLSMessage accepted");
    }
    if let Ok(c) = Commit::from_bytes(data) {
        assert_eq!(c.to_bytes(), data);
    }
    if let Ok(g) = GroupSecrets::from_bytes(data) {
        assert_eq!(g.to_bytes(), data);
    }
});
