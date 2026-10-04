//! TreeKEM (RFC 9420 sections 7.4 to 7.6): creating and processing UpdatePaths.
//!
//! A committer draws one fresh secret and hashes it up its filtered direct path,
//! so every node it touches gets a new key pair. Each path secret is encrypted
//! once per node in the resolution of the corresponding copath child, which is
//! where the logarithmic cost of a membership change comes from.

use crate::codec::Codec;
use crate::crypto::{random_bytes, CipherSuite};
use crate::error::{proto, Error, Result};
use crate::messages::*;
use crate::tree::RatchetTree;
use crate::tree_math::{self as tm, LeafIndex, NodeIndex};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

/// A member's private view of the tree: HPKE private keys by node index.
#[derive(Clone, Debug, Default)]
pub struct TreePrivate {
    pub leaf: LeafIndex,
    pub keys: HashMap<NodeIndex, Vec<u8>>,
}

pub fn next_path_secret(cs: CipherSuite, ps: &[u8]) -> Result<Vec<u8>> {
    Ok(cs.derive_secret(ps, "path")?)
}

/// Node key pair from a path secret: `DeriveKeyPair(DeriveSecret(path_secret, "node"))`.
pub fn node_keypair(cs: CipherSuite, ps: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let ns = Zeroizing::new(cs.derive_secret(ps, "node")?);
    Ok(cs.derive_keypair(&ns)?)
}

impl TreePrivate {
    pub fn new(leaf: LeafIndex, leaf_priv: Vec<u8>) -> Self {
        let mut keys = HashMap::new();
        keys.insert(tm::leaf_to_node(leaf), leaf_priv);
        TreePrivate { leaf, keys }
    }

    /// Install path secrets starting at `from` along `nodes`, returning the
    /// secret derived one step past the last node (the commit secret).
    pub fn install_path_secrets(&mut self, cs: CipherSuite, nodes: &[NodeIndex], first: Vec<u8>) -> Result<Vec<u8>> {
        let mut ps = first;
        for n in nodes {
            let (sk, _) = node_keypair(cs, &ps)?;
            self.keys.insert(*n, sk);
            ps = next_path_secret(cs, &ps)?;
        }
        Ok(ps)
    }

    /// Drop keys for nodes that are now blank or carry a different public key.
    pub fn prune(&mut self, cs: CipherSuite, tree: &RatchetTree) {
        self.keys.retain(|n, sk| match tree.node(*n) {
            Some(node) => cs.hpke_public(sk).map(|pk| pk == node.encryption_key()).unwrap_or(false),
            None => false,
        });
    }

    /// Check every private key matches the public key in the tree.
    pub fn consistent_with(&self, cs: CipherSuite, tree: &RatchetTree) -> Result<()> {
        for (n, sk) in &self.keys {
            let node = tree.node(*n).ok_or_else(|| Error::Protocol(format!("private key for blank node {n}")))?;
            if cs.hpke_public(sk)? != node.encryption_key() {
                return proto(format!("private key at node {n} does not match tree"));
            }
        }
        Ok(())
    }
}

/// Result of generating an UpdatePath.
pub struct GeneratedPath {
    pub update_path: UpdatePath,
    pub commit_secret: Vec<u8>,
    /// Path secret for each node in the filtered direct path, for Welcome.
    pub path_secrets: Vec<(NodeIndex, Vec<u8>)>,
}

/// Blank the sender's direct path, install new parent keys along the filtered
/// direct path, and compute parent hashes top-down. Returns the parent hash the
/// sender's new leaf must carry.
fn merge_path_keys(tree: &mut RatchetTree, sender: LeafIndex, fdp: &[(NodeIndex, NodeIndex)], pubs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let x = tm::leaf_to_node(sender);
    for p in tm::direct_path(x, tree.n_leaves()) {
        tree.set_node(p, None);
    }
    for ((p, _), pk) in fdp.iter().zip(pubs) {
        tree.set_node(*p, Some(Node::Parent(ParentNode { encryption_key: pk.clone(), parent_hash: vec![], unmerged_leaves: vec![] })));
    }
    // Top-down parent hashes: node k carries ParentHash(node k+1, copath child of node k+1).
    for k in (0..fdp.len()).rev() {
        let ph = if k + 1 < fdp.len() { tree.parent_hash(fdp[k + 1].0, fdp[k + 1].1)? } else { vec![] };
        let mut pn = tree.parent_node(fdp[k].0).unwrap().clone();
        pn.parent_hash = ph;
        tree.set_node(fdp[k].0, Some(Node::Parent(pn)));
    }
    if fdp.is_empty() {
        Ok(vec![])
    } else {
        tree.parent_hash(fdp[0].0, fdp[0].1)
    }
}

/// Generate an UpdatePath for `sender` over `tree` (proposals already applied).
///
/// `leaf` is the sender's new leaf node; its encryption key must match
/// `leaf_priv`, and it is re-signed here once its parent hash is known.
/// `excluded` lists leaves added in this commit, which get no path secrets.
/// `context` builds the provisional GroupContext from the updated tree.
#[allow(clippy::too_many_arguments)]
pub fn generate(
    tree: &mut RatchetTree,
    private: &mut TreePrivate,
    sender: LeafIndex,
    mut leaf: LeafNode,
    leaf_priv: Vec<u8>,
    signature_priv: &[u8],
    group_id: &[u8],
    excluded: &HashSet<LeafIndex>,
    context: impl FnOnce(&RatchetTree) -> GroupContext,
) -> Result<GeneratedPath> {
    let cs = tree.cs;
    let fdp = tree.filtered_direct_path_with_copath(sender);
    let mut secrets = Vec::with_capacity(fdp.len());
    let mut ps = random_bytes(cs.nh());
    let mut pubs = Vec::with_capacity(fdp.len());
    for _ in &fdp {
        let (_, pk) = node_keypair(cs, &ps)?;
        pubs.push(pk);
        secrets.push(ps.clone());
        ps = next_path_secret(cs, &ps)?;
    }
    let commit_secret = ps;

    let leaf_ph = merge_path_keys(tree, sender, &fdp, &pubs)?;
    leaf.leaf_node_source = LeafNodeSource::Commit(leaf_ph);
    leaf.sign(cs, signature_priv, Some((group_id, sender)))?;
    tree.set_leaf(sender, leaf.clone());

    let ctx = context(tree).to_bytes();
    let mut nodes = Vec::with_capacity(fdp.len());
    for (k, (_, c)) in fdp.iter().enumerate() {
        let mut cts = Vec::new();
        for r in tree.resolution(*c) {
            if tm::is_leaf(r) && excluded.contains(&tm::node_to_leaf(r)) {
                continue;
            }
            let pk = tree.node(r).unwrap().encryption_key().to_vec();
            let (kem_output, ciphertext) = cs.encrypt_with_label(&pk, "UpdatePathNode", &ctx, &secrets[k])?;
            cts.push(HpkeCiphertext { kem_output, ciphertext });
        }
        nodes.push(UpdatePathNode { encryption_key: pubs[k].clone(), encrypted_path_secret: cts });
    }

    private.leaf = sender;
    private.keys.insert(tm::leaf_to_node(sender), leaf_priv);
    for ((p, _), s) in fdp.iter().zip(&secrets) {
        let (sk, _) = node_keypair(cs, s)?;
        private.keys.insert(*p, sk);
    }
    private.prune(cs, tree);

    Ok(GeneratedPath {
        update_path: UpdatePath { leaf_node: leaf, nodes },
        commit_secret,
        path_secrets: fdp.iter().map(|(p, _)| *p).zip(secrets).collect(),
    })
}

/// Merge a received UpdatePath into `tree` without decrypting (for members that
/// cannot decrypt, and for the parent-hash check). Returns the filtered direct path.
pub fn merge_public(tree: &mut RatchetTree, sender: LeafIndex, path: &UpdatePath, group_id: &[u8]) -> Result<Vec<(NodeIndex, NodeIndex)>> {
    let cs = tree.cs;
    let fdp = tree.filtered_direct_path_with_copath(sender);
    if fdp.len() != path.nodes.len() {
        return proto(format!("UpdatePath has {} nodes, filtered direct path has {}", path.nodes.len(), fdp.len()));
    }
    let ph = match &path.leaf_node.leaf_node_source {
        LeafNodeSource::Commit(ph) => ph.clone(),
        _ => return proto("UpdatePath leaf source is not commit"),
    };
    path.leaf_node.verify(cs, Some((group_id, sender)))?;
    let pubs: Vec<Vec<u8>> = path.nodes.iter().map(|n| n.encryption_key.clone()).collect();
    let expected = merge_path_keys(tree, sender, &fdp, &pubs)?;
    if expected != ph {
        return proto("UpdatePath leaf parent hash does not match");
    }
    tree.set_leaf(sender, path.leaf_node.clone());
    Ok(fdp)
}

/// Process a received UpdatePath as `private.leaf`. Returns the commit secret and
/// the path secret that was decrypted.
pub fn process(
    tree: &mut RatchetTree,
    private: &mut TreePrivate,
    sender: LeafIndex,
    path: &UpdatePath,
    group_id: &[u8],
    excluded: &HashSet<LeafIndex>,
    context: impl FnOnce(&RatchetTree) -> GroupContext,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cs = tree.cs;
    let me = tm::leaf_to_node(private.leaf);
    if sender == private.leaf {
        return proto("cannot process own UpdatePath");
    }
    // Locate the ciphertext meant for us before the tree changes.
    let fdp_before = tree.filtered_direct_path_with_copath(sender);
    let k = fdp_before
        .iter()
        .position(|(_, c)| tm::is_in_subtree(*c, me))
        .ok_or_else(|| Error::Protocol("receiver not under sender's filtered direct path".into()))?;
    let res: Vec<NodeIndex> = tree
        .resolution(fdp_before[k].1)
        .into_iter()
        .filter(|r| !(tm::is_leaf(*r) && excluded.contains(&tm::node_to_leaf(*r))))
        .collect();
    let (i, holder) = res
        .iter()
        .enumerate()
        .find(|(_, r)| private.keys.contains_key(r))
        .ok_or_else(|| Error::Protocol("no private key in resolution of copath child".into()))?;
    let sk = private.keys[holder].clone();

    let fdp = merge_public(tree, sender, path, group_id)?;
    let ctx = context(tree).to_bytes();
    let ct = path.nodes[k]
        .encrypted_path_secret
        .get(i)
        .ok_or_else(|| Error::Protocol("UpdatePathNode has too few ciphertexts".into()))?;
    let ps = cs.decrypt_with_label(&sk, "UpdatePathNode", &ctx, &ct.kem_output, &ct.ciphertext)?;

    let mut cur = ps.clone();
    for (j, (p, _)) in fdp.iter().enumerate().skip(k) {
        let (nsk, npk) = node_keypair(cs, &cur)?;
        if npk != path.nodes[j].encryption_key {
            return proto(format!("derived public key for node {p} does not match UpdatePath"));
        }
        private.keys.insert(*p, nsk);
        cur = next_path_secret(cs, &cur)?;
    }
    private.prune(cs, tree);
    Ok((cur, ps))
}
