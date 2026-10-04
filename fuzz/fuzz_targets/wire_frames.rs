//! The server parses every client frame and the MLS header inside sends.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mls::Codec;
use wire::*;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = ClientMsg::from_bytes(data) {
        assert_eq!(m.to_bytes(), data);
        if let ClientMsg::Send(s) = m {
            let _ = parse_header(&s.payload);
        }
    }
    if let Ok(m) = ServerMsg::from_bytes(data) {
        assert_eq!(m.to_bytes(), data);
    }
    let _ = parse_header(data);
});
