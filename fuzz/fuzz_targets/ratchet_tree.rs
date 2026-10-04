//! A received ratchet tree is attacker-controlled (Welcome, GroupInfo). Parsing
//! and validating it must never panic, whatever it contains.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mls::tree::RatchetTree;
use mls::CipherSuite;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = RatchetTree::from_bytes(CipherSuite(1), data) {
        let _ = t.root_tree_hash();
        let _ = t.verify_parent_hashes();
        let _ = mls::group::validate_tree(&t, b"group");
        for x in 0..(2 * t.n_leaves() - 1) {
            let _ = t.resolution(x);
        }
        for (l, _) in t.members().collect::<Vec<_>>() {
            let _ = t.filtered_direct_path(l);
        }
    }
});
