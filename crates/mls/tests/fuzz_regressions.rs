//! Inputs that crashed a fuzz target once, kept so they stay fixed.

use mls::tree::RatchetTree;
use mls::CipherSuite;

#[test]
fn ratchet_tree_with_out_of_range_unmerged_leaf_is_rejected() {
    // Found by cargo-fuzz (ratchet_tree target): an unmerged leaf index such as
    // 0x80000001 overflowed leaf-to-node math. It must be a parse error now.
    let b = include_bytes!("data/fuzz-ratchet-tree-unmerged-overflow.bin");
    assert!(RatchetTree::from_bytes(CipherSuite(1), b).is_err());
}
