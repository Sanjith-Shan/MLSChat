//! tree-validation, tree-operations, treekem.

use crate::schedule::ctx;
use crate::*;
use mls::messages::*;
use mls::tree::RatchetTree;
use mls::tree_math as tm;
use mls::treekem::{self, TreePrivate};
use mls::Codec;
use std::collections::HashSet;

pub(crate) fn tree_validation(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);
    let tree = RatchetTree::from_bytes(cs, &hx(v, "tree")?)?;
    let res = v["resolutions"].as_array().unwrap();
    let hashes = v["tree_hashes"].as_array().unwrap();
    for (i, r) in res.iter().enumerate() {
        let want: Vec<u32> = r.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
        ensure!(tree.resolution(i as u32) == want, "resolution of node {i}");
    }
    for (i, h) in hashes.iter().enumerate() {
        eqb(&format!("tree hash of node {i}"), &tree.tree_hash(i as u32), &hex::decode(h.as_str().unwrap())?)?;
    }
    tree.verify_parent_hashes()?;
    tree.verify_leaf_signatures(&hx(v, "group_id")?)?;
    Ok(Outcome::Pass)
}

pub(crate) fn tree_operations(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);
    let mut tree = RatchetTree::from_bytes(cs, &hx(v, "tree_before")?)?;
    eqb("tree_hash_before", &tree.root_tree_hash(), &hx(v, "tree_hash_before")?)?;
    let sender = num(v, "proposal_sender")? as u32;
    match Proposal::from_bytes(&hx(v, "proposal")?)? {
        Proposal::Add(kp) => {
            tree.add_leaf(kp.leaf_node);
        }
        Proposal::Update(ln) => tree.update_leaf(sender, ln)?,
        Proposal::Remove(l) => tree.remove_leaf(l)?,
        p => bail!("unexpected proposal {:?}", p.proposal_type()),
    }
    eqb("tree_after", &tree.to_bytes(), &hx(v, "tree_after")?)?;
    eqb("tree_hash_after", &tree.root_tree_hash(), &hx(v, "tree_hash_after")?)?;
    Ok(Outcome::Pass)
}

pub(crate) fn treekem(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);
    let gid = hx(v, "group_id")?;
    let epoch = num(v, "epoch")?;
    let cth = hx(v, "confirmed_transcript_hash")?;
    let tree = RatchetTree::from_bytes(cs, &hx(v, "ratchet_tree")?)?;
    let mk_ctx = |t: &RatchetTree| ctx(cs, gid.clone(), epoch, t.root_tree_hash(), cth.clone());

    let mut privs: Vec<(u32, TreePrivate, Vec<u8>)> = Vec::new();
    for lp in v["leaves_private"].as_array().unwrap() {
        let idx = num(lp, "index")? as u32;
        let mut p = TreePrivate::new(idx, hx(lp, "encryption_priv")?);
        for ps in lp["path_secrets"].as_array().unwrap() {
            let (sk, _) = treekem::node_keypair(cs, &hx(ps, "path_secret")?)?;
            p.keys.insert(num(ps, "node")? as u32, sk);
        }
        p.consistent_with(cs, &tree).with_context(|| format!("private state of leaf {idx}"))?;
        privs.push((idx, p, hx(lp, "signature_priv")?));
    }

    let none = HashSet::new();
    for up in v["update_paths"].as_array().unwrap() {
        let sender = num(up, "sender")? as u32;
        let path = UpdatePath::from_bytes(&hx(up, "update_path")?)?;
        let want_cs = hx(up, "commit_secret")?;
        let want_ps = up["path_secrets"].as_array().unwrap();

        let mut merged = tree.clone();
        treekem::merge_public(&mut merged, sender, &path, &gid).context("parent-hash validity of update_path")?;
        eqb("tree_hash_after", &merged.root_tree_hash(), &hx(up, "tree_hash_after")?)?;

        for (j, p, _) in &privs {
            if *j == sender {
                continue;
            }
            let mut t = tree.clone();
            let mut pj = p.clone();
            let (commit_secret, ps) = treekem::process(&mut t, &mut pj, sender, &path, &gid, &none, &mk_ctx)?;
            let want = hex::decode(want_ps[*j as usize].as_str().ok_or_else(|| anyhow!("null path secret for {j}"))?)?;
            eqb(&format!("path secret at leaf {j}"), &ps, &want)?;
            eqb("commit_secret", &commit_secret, &want_cs)?;
        }

        // Generate a fresh path as the same sender and check every other member agrees.
        let (_, sp, sig_priv) = privs.iter().find(|(j, _, _)| *j == sender).ok_or_else(|| anyhow!("no private state for sender"))?;
        let mut t = tree.clone();
        let mut spriv = sp.clone();
        let (leaf_priv, leaf_pub) = cs.generate_keypair();
        let mut leaf = tree.leaf(sender).unwrap().clone();
        leaf.encryption_key = leaf_pub;
        let g = treekem::generate(&mut t, &mut spriv, sender, leaf, leaf_priv, sig_priv, &gid, &none, &mk_ctx)?;
        let path_bytes = g.update_path.to_bytes();
        let new_path = UpdatePath::from_bytes(&path_bytes)?;
        for (j, p, _) in &privs {
            if *j == sender {
                continue;
            }
            let mut t2 = tree.clone();
            let mut pj = p.clone();
            let (commit_secret, _) = treekem::process(&mut t2, &mut pj, sender, &new_path, &gid, &none, &mk_ctx)?;
            eqb("new commit secret", &commit_secret, &g.commit_secret)?;
            ensure!(t2 == t, "trees diverge after new path");
        }
        let _ = tm::root(1);
    }
    Ok(Outcome::Pass)
}
