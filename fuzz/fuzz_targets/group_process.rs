//! A member processing arbitrary bytes as a group message must return an error,
//! never panic and never change its epoch.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mls::group::*;
use mls::messages::MlsMessage;
use mls::{CipherSuite, Codec};
use std::sync::OnceLock;

fn base() -> &'static Group {
    static G: OnceLock<Group> = OnceLock::new();
    G.get_or_init(|| {
        let cs = CipherSuite(1);
        let mut a = Group::create(cs, Signer::generate(cs, b"a"), b"fuzz".to_vec(), vec![], GroupConfig::default()).unwrap();
        let kp = create_key_package(cs, &Signer::generate(cs, b"b")).unwrap();
        a.commit(vec![mls::messages::Proposal::Add(kp.key_package)], CommitOptions::default()).unwrap();
        a.merge_pending_commit().unwrap();
        a
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = MlsMessage::from_bytes(data) {
        let mut g = base().clone();
        let e = g.epoch();
        if g.process(&m).is_err() {
            assert_eq!(g.epoch(), e);
        }
    }
});
