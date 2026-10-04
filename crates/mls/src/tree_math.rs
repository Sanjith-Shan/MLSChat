//! Array-based left-balanced binary tree math (RFC 9420 section 4.2 and appendix C).
//!
//! Leaves sit at even node indices, parents at odd ones. A tree with `n` leaves
//! (always a power of two in a ratchet tree) has `2n - 1` nodes.

pub type NodeIndex = u32;
pub type LeafIndex = u32;

pub fn log2(x: u32) -> u32 {
    if x == 0 {
        0
    } else {
        31 - x.leading_zeros()
    }
}

/// Number of trailing one bits: the height of a node above the leaves.
pub fn level(x: NodeIndex) -> u32 {
    x.trailing_ones()
}

pub fn node_width(n_leaves: u32) -> u32 {
    if n_leaves == 0 {
        0
    } else {
        2 * (n_leaves - 1) + 1
    }
}

pub fn root(n_leaves: u32) -> NodeIndex {
    let w = node_width(n_leaves);
    (1u32 << log2(w)) - 1
}

pub fn leaf_to_node(l: LeafIndex) -> NodeIndex {
    l * 2
}

pub fn node_to_leaf(x: NodeIndex) -> LeafIndex {
    debug_assert!(x % 2 == 0);
    x / 2
}

pub fn is_leaf(x: NodeIndex) -> bool {
    x % 2 == 0
}

pub fn left(x: NodeIndex) -> Option<NodeIndex> {
    let k = level(x);
    if k == 0 {
        None
    } else {
        Some(x ^ (1 << (k - 1)))
    }
}

pub fn right(x: NodeIndex) -> Option<NodeIndex> {
    let k = level(x);
    if k == 0 {
        None
    } else {
        Some(x ^ (3 << (k - 1)))
    }
}

pub fn parent(x: NodeIndex, n_leaves: u32) -> Option<NodeIndex> {
    if x == root(n_leaves) {
        return None;
    }
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    Some((x | (1 << k)) ^ (b << (k + 1)))
}

pub fn sibling(x: NodeIndex, n_leaves: u32) -> Option<NodeIndex> {
    let p = parent(x, n_leaves)?;
    if x < p {
        right(p)
    } else {
        left(p)
    }
}

/// Ancestors of `x` from its parent up to and including the root.
pub fn direct_path(x: NodeIndex, n_leaves: u32) -> Vec<NodeIndex> {
    let r = root(n_leaves);
    let mut d = Vec::new();
    if x == r {
        return d;
    }
    let mut cur = x;
    while cur != r {
        cur = parent(cur, n_leaves).expect("non-root has parent");
        d.push(cur);
    }
    d
}

/// Siblings of `x` and of each node on its direct path, excluding the root.
pub fn copath(x: NodeIndex, n_leaves: u32) -> Vec<NodeIndex> {
    let r = root(n_leaves);
    if x == r {
        return Vec::new();
    }
    let mut d = vec![x];
    d.extend(direct_path(x, n_leaves));
    d.pop(); // root
    d.into_iter().map(|y| sibling(y, n_leaves).unwrap()).collect()
}

/// Whether `x` lies in the subtree rooted at `ancestor` (inclusive).
pub fn is_in_subtree(ancestor: NodeIndex, x: NodeIndex) -> bool {
    let k = level(ancestor);
    let lo = ancestor - ((1 << k) - 1);
    let hi = ancestor + ((1 << k) - 1);
    x >= lo && x <= hi
}

/// Lowest common ancestor of two nodes.
pub fn common_ancestor(x: NodeIndex, y: NodeIndex) -> NodeIndex {
    let mut k = level(x).max(level(y));
    loop {
        // The level-k node whose subtree contains x.
        let a = ((x >> (k + 1)) << (k + 1)) | ((1 << k) - 1);
        if is_in_subtree(a, x) && is_in_subtree(a, y) {
            return a;
        }
        k += 1;
    }
}

/// Leaf indices covered by the subtree rooted at `x`.
pub fn leaves_under(x: NodeIndex) -> std::ops::Range<LeafIndex> {
    let k = level(x);
    let lo = x - ((1 << k) - 1);
    let hi = x + ((1 << k) - 1);
    (lo / 2)..(hi / 2 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_tree() {
        // 4 leaves: nodes 0..6, root 3.
        assert_eq!(root(4), 3);
        assert_eq!(direct_path(0, 4), vec![1, 3]);
        assert_eq!(copath(0, 4), vec![2, 5]);
        assert_eq!(common_ancestor(0, 6), 3);
        assert_eq!(common_ancestor(0, 2), 1);
        assert_eq!(common_ancestor(4, 6), 5);
        assert_eq!(leaves_under(3), 0..4);
        assert_eq!(leaves_under(5), 2..4);
    }
}
