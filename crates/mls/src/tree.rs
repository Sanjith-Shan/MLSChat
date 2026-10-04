//! The ratchet tree (RFC 9420 section 7): node storage, resolution, tree hash,
//! parent hash, and the structural edits made by Add, Update and Remove.

use crate::codec::Codec;
use crate::crypto::CipherSuite;
use crate::error::{proto, Result};
use crate::messages::*;
use crate::tree_math::{self as tm, LeafIndex, NodeIndex};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct RatchetTree {
    pub cs: CipherSuite,
    /// Always `node_width(n_leaves)` entries, with `n_leaves` a power of two.
    /// Nodes are shared so cloning a tree (which every commit does) is cheap.
    nodes: Vec<Option<Arc<Node>>>,
    hash_cache: RefCell<Vec<Option<Arc<[u8]>>>>,
}

impl PartialEq for RatchetTree {
    fn eq(&self, o: &Self) -> bool {
        self.cs == o.cs && self.nodes == o.nodes
    }
}

impl RatchetTree {
    pub fn new(cs: CipherSuite, first: LeafNode) -> Self {
        RatchetTree { cs, nodes: vec![Some(Arc::new(Node::Leaf(first)))], hash_cache: RefCell::new(vec![None]) }
    }

    /// Build from the (possibly truncated) `ratchet_tree` extension encoding.
    pub fn from_nodes(cs: CipherSuite, mut list: RatchetTreeNodes) -> Result<Self> {
        if list.is_empty() {
            return proto("empty ratchet tree");
        }
        if list.last().unwrap().is_none() {
            return proto("ratchet tree ends in a blank node");
        }
        if list.len() % 2 == 0 {
            return proto("ratchet tree has an even number of nodes");
        }
        for (i, n) in list.iter().enumerate() {
            match n {
                Some(Node::Leaf(_)) if i % 2 == 1 => return proto("leaf node at a parent position"),
                Some(Node::Parent(_)) if i % 2 == 0 => return proto("parent node at a leaf position"),
                _ => {}
            }
        }
        let leaves = (list.len() as u32 + 1) / 2;
        let n = leaves.next_power_of_two();
        list.resize(tm::node_width(n) as usize, None);
        let w = list.len();
        let nodes = list.into_iter().map(|n| n.map(Arc::new)).collect();
        Ok(RatchetTree { cs, nodes, hash_cache: RefCell::new(vec![None; w]) })
    }

    pub fn from_bytes(cs: CipherSuite, b: &[u8]) -> Result<Self> {
        Self::from_nodes(cs, RatchetTreeNodes::from_bytes(b)?)
    }

    /// Truncated node list for the `ratchet_tree` extension.
    pub fn to_nodes(&self) -> RatchetTreeNodes {
        let mut v: RatchetTreeNodes = self.nodes.iter().map(|n| n.as_deref().cloned()).collect();
        while matches!(v.last(), Some(None)) {
            v.pop();
        }
        v
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_nodes().to_bytes()
    }

    pub fn n_leaves(&self) -> u32 {
        (self.nodes.len() as u32 + 1) / 2
    }

    pub fn root(&self) -> NodeIndex {
        tm::root(self.n_leaves())
    }

    pub fn node(&self, x: NodeIndex) -> Option<&Node> {
        self.nodes.get(x as usize).and_then(|n| n.as_deref())
    }

    pub fn is_blank(&self, x: NodeIndex) -> bool {
        self.node(x).is_none()
    }

    pub fn leaf(&self, l: LeafIndex) -> Option<&LeafNode> {
        match self.node(tm::leaf_to_node(l)) {
            Some(Node::Leaf(ln)) => Some(ln),
            _ => None,
        }
    }

    pub fn parent_node(&self, x: NodeIndex) -> Option<&ParentNode> {
        match self.node(x) {
            Some(Node::Parent(p)) => Some(p),
            _ => None,
        }
    }

    /// Indices and contents of every non-blank leaf.
    pub fn members(&self) -> impl Iterator<Item = (LeafIndex, &LeafNode)> {
        (0..self.n_leaves()).filter_map(move |l| self.leaf(l).map(|ln| (l, ln)))
    }

    pub fn member_count(&self) -> usize {
        self.members().count()
    }

    fn invalidate(&self, x: NodeIndex) {
        let mut c = self.hash_cache.borrow_mut();
        let n = self.n_leaves();
        c[x as usize] = None;
        for p in tm::direct_path(x, n) {
            c[p as usize] = None;
        }
    }

    pub fn set_node(&mut self, x: NodeIndex, node: Option<Node>) {
        self.nodes[x as usize] = node.map(Arc::new);
        self.invalidate(x);
    }

    pub fn set_leaf(&mut self, l: LeafIndex, ln: LeafNode) {
        self.set_node(tm::leaf_to_node(l), Some(Node::Leaf(ln)));
    }

    /// Resolution of a node (RFC 9420 section 4.1.1).
    pub fn resolution(&self, x: NodeIndex) -> Vec<NodeIndex> {
        let mut out = Vec::new();
        self.resolve_into(x, &mut out);
        out
    }

    fn resolve_into(&self, x: NodeIndex, out: &mut Vec<NodeIndex>) {
        match self.node(x) {
            Some(Node::Leaf(_)) => out.push(x),
            Some(Node::Parent(p)) => {
                out.push(x);
                out.extend(p.unmerged_leaves.iter().map(|l| tm::leaf_to_node(*l)));
            }
            None => {
                if let (Some(l), Some(r)) = (tm::left(x), tm::right(x)) {
                    self.resolve_into(l, out);
                    self.resolve_into(r, out);
                }
            }
        }
    }

    /// Direct path of a leaf, keeping only nodes whose copath child has a non-empty resolution.
    pub fn filtered_direct_path(&self, l: LeafIndex) -> Vec<NodeIndex> {
        let n = self.n_leaves();
        let x = tm::leaf_to_node(l);
        let dp = tm::direct_path(x, n);
        let cp = tm::copath(x, n);
        dp.into_iter().zip(cp).filter(|(_, c)| !self.resolution(*c).is_empty()).map(|(p, _)| p).collect()
    }

    /// Pairs of (filtered direct path node, its copath child).
    pub fn filtered_direct_path_with_copath(&self, l: LeafIndex) -> Vec<(NodeIndex, NodeIndex)> {
        let n = self.n_leaves();
        let x = tm::leaf_to_node(l);
        let dp = tm::direct_path(x, n);
        let cp = tm::copath(x, n);
        dp.into_iter().zip(cp).filter(|(_, c)| !self.resolution(*c).is_empty()).collect()
    }

    // ---- tree hash ----

    pub fn root_tree_hash(&self) -> Vec<u8> {
        self.tree_hash(self.root())
    }

    pub fn tree_hash(&self, x: NodeIndex) -> Vec<u8> {
        if let Some(h) = &self.hash_cache.borrow()[x as usize] {
            return h.to_vec();
        }
        let h = self.compute_tree_hash(x, &HashSet::new());
        self.hash_cache.borrow_mut()[x as usize] = Some(Arc::from(h.as_slice()));
        h
    }

    /// Tree hash with the given leaves treated as blank and dropped from unmerged lists.
    /// With an empty `exclude` this is the ordinary tree hash.
    pub fn tree_hash_excluding(&self, x: NodeIndex, exclude: &HashSet<LeafIndex>) -> Vec<u8> {
        if exclude.is_empty() {
            return self.tree_hash(x);
        }
        self.compute_tree_hash(x, exclude)
    }

    fn compute_tree_hash(&self, x: NodeIndex, exclude: &HashSet<LeafIndex>) -> Vec<u8> {
        let mut inp = Vec::new();
        if tm::is_leaf(x) {
            1u8.encode(&mut inp);
            let l = tm::node_to_leaf(x);
            l.encode(&mut inp);
            let leaf = if exclude.contains(&l) { None } else { self.leaf(l) };
            match leaf {
                Some(ln) => {
                    1u8.encode(&mut inp);
                    ln.encode(&mut inp);
                }
                None => 0u8.encode(&mut inp),
            }
        } else {
            2u8.encode(&mut inp);
            match self.parent_node(x) {
                Some(p) => {
                    1u8.encode(&mut inp);
                    if exclude.is_empty() {
                        p.encode(&mut inp);
                    } else {
                        let mut q = p.clone();
                        q.unmerged_leaves.retain(|l| !exclude.contains(l));
                        q.encode(&mut inp);
                    }
                }
                None => 0u8.encode(&mut inp),
            }
            let lh = if exclude.is_empty() { self.tree_hash(tm::left(x).unwrap()) } else { self.compute_tree_hash(tm::left(x).unwrap(), exclude) };
            let rh = if exclude.is_empty() { self.tree_hash(tm::right(x).unwrap()) } else { self.compute_tree_hash(tm::right(x).unwrap(), exclude) };
            lh.encode(&mut inp);
            rh.encode(&mut inp);
        }
        self.cs.hash(&inp)
    }

    // ---- parent hash ----

    /// ParentHash(P, S): hash over P's key and parent hash and the original tree hash of S.
    pub fn parent_hash(&self, p: NodeIndex, sibling: NodeIndex) -> Result<Vec<u8>> {
        let pn = match self.parent_node(p) {
            Some(pn) => pn,
            None => return proto("parent hash of a blank node"),
        };
        let excl: HashSet<LeafIndex> = pn.unmerged_leaves.iter().copied().collect();
        let osth = self.tree_hash_excluding(sibling, &excl);
        Ok(self.parent_hash_raw(&pn.encryption_key, &pn.parent_hash, &osth))
    }

    pub fn parent_hash_raw(&self, enc_key: &[u8], parent_hash: &[u8], original_sibling_tree_hash: &[u8]) -> Vec<u8> {
        let mut inp = Vec::new();
        enc_key.to_vec().encode(&mut inp);
        parent_hash.to_vec().encode(&mut inp);
        original_sibling_tree_hash.to_vec().encode(&mut inp);
        self.cs.hash(&inp)
    }

    fn node_parent_hash(&self, x: NodeIndex) -> Option<&[u8]> {
        match self.node(x)? {
            Node::Leaf(l) => l.parent_hash(),
            Node::Parent(p) => Some(&p.parent_hash),
        }
    }

    /// Every non-blank parent must be parent-hash valid with respect to exactly
    /// one descendant (RFC 9420 section 7.9.2, top-down check).
    pub fn verify_parent_hashes(&self) -> Result<()> {
        for p in (0..self.nodes.len() as u32).filter(|x| !tm::is_leaf(*x)) {
            let Some(pn) = self.parent_node(p) else { continue };
            let unmerged: HashSet<LeafIndex> = pn.unmerged_leaves.iter().copied().collect();
            let (l, r) = (tm::left(p).unwrap(), tm::right(p).unwrap());
            let mut found = 0;
            for (c, s) in [(l, r), (r, l)] {
                let ph = self.parent_hash(p, s)?;
                let res = self.resolution(c);
                // Unmerged leaves of P that sit under C.
                let um_under: HashSet<NodeIndex> =
                    unmerged.iter().filter(|u| tm::leaves_under(c).contains(u)).map(|u| tm::leaf_to_node(*u)).collect();
                for d in &res {
                    if self.node_parent_hash(*d) != Some(ph.as_slice()) {
                        continue;
                    }
                    let rest: HashSet<NodeIndex> = res.iter().copied().filter(|x| x != d).collect();
                    if rest == um_under {
                        found += 1;
                    }
                }
            }
            if found != 1 {
                return proto(format!("parent node {p} is not parent-hash valid ({found} chains)"));
            }
        }
        Ok(())
    }

    /// Check every leaf signature against the group (RFC 9420 section 7.3).
    pub fn verify_leaf_signatures(&self, group_id: &[u8]) -> Result<()> {
        for (l, ln) in self.members() {
            ln.verify(self.cs, Some((group_id, l)))?;
        }
        Ok(())
    }

    // ---- structural edits ----

    /// Blank the leaf and its direct path, then truncate.
    pub fn remove_leaf(&mut self, l: LeafIndex) -> Result<()> {
        if self.leaf(l).is_none() {
            return proto(format!("remove of blank leaf {l}"));
        }
        let x = tm::leaf_to_node(l);
        self.set_node(x, None);
        for p in tm::direct_path(x, self.n_leaves()) {
            self.set_node(p, None);
        }
        self.truncate();
        Ok(())
    }

    /// Remove the right half of the tree while it holds no members.
    pub fn truncate(&mut self) {
        loop {
            let n = self.n_leaves();
            if n <= 1 {
                return;
            }
            let half = n / 2;
            if (half..n).any(|l| self.leaf(l).is_some()) {
                return;
            }
            self.nodes.truncate(tm::node_width(half) as usize);
            *self.hash_cache.borrow_mut() = vec![None; self.nodes.len()];
        }
    }

    /// Insert at the leftmost blank leaf (extending if full) and mark it unmerged on its path.
    pub fn add_leaf(&mut self, ln: LeafNode) -> LeafIndex {
        let n = self.n_leaves();
        let l = match (0..n).find(|l| self.leaf(*l).is_none()) {
            Some(l) => l,
            None => {
                self.nodes.resize(tm::node_width(n * 2) as usize, None);
                *self.hash_cache.borrow_mut() = vec![None; self.nodes.len()];
                n
            }
        };
        let x = tm::leaf_to_node(l);
        self.set_node(x, Some(Node::Leaf(ln)));
        for p in tm::direct_path(x, self.n_leaves()) {
            if let Some(Node::Parent(pn)) = self.nodes[p as usize].as_mut().map(Arc::make_mut) {
                pn.unmerged_leaves.push(l);
                self.invalidate(p);
            }
        }
        l
    }

    /// Replace a leaf and blank its direct path (Update proposal).
    pub fn update_leaf(&mut self, l: LeafIndex, ln: LeafNode) -> Result<()> {
        if self.leaf(l).is_none() {
            return proto("update of blank leaf");
        }
        let x = tm::leaf_to_node(l);
        self.set_node(x, Some(Node::Leaf(ln)));
        for p in tm::direct_path(x, self.n_leaves()) {
            self.set_node(p, None);
        }
        Ok(())
    }

    /// Whether any member already uses this HPKE or signature key.
    pub fn has_encryption_key(&self, k: &[u8]) -> bool {
        self.nodes.iter().flatten().any(|n| n.encryption_key() == k)
    }

    pub fn has_signature_key(&self, k: &[u8]) -> bool {
        self.members().any(|(_, l)| l.signature_key == k)
    }

    pub fn find_leaf(&self, pred: impl Fn(&LeafNode) -> bool) -> Option<LeafIndex> {
        self.members().find(|(_, l)| pred(l)).map(|(i, _)| i)
    }
}
