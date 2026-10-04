//! Secret tree and per-sender hash ratchets (RFC 9420 section 9).
//!
//! Secrets are derived lazily from the nearest stored ancestor, and each
//! consumed secret is deleted, which is what gives forward secrecy inside an
//! epoch. Out-of-order receipt is bounded by `MAX_SKIP` stored keys per ratchet.

use crate::crypto::CipherSuite;
use crate::error::{Error, Result};
use crate::tree_math as tm;
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroize;

pub const MAX_FORWARD: u32 = 1024;
pub const MAX_SKIP: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RatchetType {
    Handshake,
    Application,
}

#[derive(Clone, Debug)]
struct Ratchet {
    next_generation: u32,
    secret: Vec<u8>,
    /// Keys for skipped generations, kept for out-of-order delivery.
    skipped: BTreeMap<u32, (Vec<u8>, Vec<u8>)>,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct SecretTree {
    cs: CipherSuite,
    n_leaves: u32,
    nodes: HashMap<u32, Vec<u8>>,
    ratchets: HashMap<(u32, RatchetType), Ratchet>,
}

impl SecretTree {
    pub fn new(cs: CipherSuite, encryption_secret: &[u8], n_leaves: u32) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(tm::root(n_leaves), encryption_secret.to_vec());
        SecretTree { cs, n_leaves, nodes, ratchets: HashMap::new() }
    }

    fn leaf_secret(&mut self, leaf: u32) -> Result<Vec<u8>> {
        if leaf >= self.n_leaves {
            return Err(Error::Protocol(format!("leaf {leaf} outside secret tree of {}", self.n_leaves)));
        }
        let target = tm::leaf_to_node(leaf);
        // Path from root down to the target.
        let mut path = tm::direct_path(target, self.n_leaves);
        path.reverse();
        path.push(target);
        let start = path.iter().position(|n| self.nodes.contains_key(n)).ok_or_else(|| Error::Protocol("leaf secret already consumed".into()))?;
        for w in start..path.len() - 1 {
            let node = path[w];
            let mut secret = self.nodes.remove(&node).unwrap();
            let l = tm::left(node).unwrap();
            let r = tm::right(node).unwrap();
            let ls = self.cs.expand_with_label(&secret, "tree", b"left", self.cs.nh())?;
            let rs = self.cs.expand_with_label(&secret, "tree", b"right", self.cs.nh())?;
            secret.zeroize();
            self.nodes.insert(l, ls);
            self.nodes.insert(r, rs);
        }
        self.nodes.remove(&target).ok_or_else(|| Error::Protocol("leaf secret missing".into()))
    }

    fn ratchet(&mut self, leaf: u32, t: RatchetType) -> Result<&mut Ratchet> {
        if !self.ratchets.contains_key(&(leaf, t)) {
            // Create both ratchets for the leaf at once, since the leaf secret is consumed.
            let mut ls = self.leaf_secret(leaf)?;
            let hs = self.cs.expand_with_label(&ls, "handshake", &[], self.cs.nh())?;
            let app = self.cs.expand_with_label(&ls, "application", &[], self.cs.nh())?;
            ls.zeroize();
            let mk = |secret| Ratchet { next_generation: 0, secret, skipped: BTreeMap::new() };
            self.ratchets.insert((leaf, RatchetType::Handshake), mk(hs));
            self.ratchets.insert((leaf, RatchetType::Application), mk(app));
        }
        Ok(self.ratchets.get_mut(&(leaf, t)).unwrap())
    }

    fn step(cs: CipherSuite, r: &mut Ratchet) -> Result<(Vec<u8>, Vec<u8>)> {
        let g = r.next_generation;
        let key = cs.derive_tree_secret(&r.secret, "key", g, cs.nk())?;
        let nonce = cs.derive_tree_secret(&r.secret, "nonce", g, cs.nn())?;
        let next = cs.derive_tree_secret(&r.secret, "secret", g, cs.nh())?;
        r.secret.zeroize();
        r.secret = next;
        r.next_generation = g.checked_add(1).ok_or(Error::GenerationTooFar(g))?;
        Ok((key, nonce))
    }

    /// Key and nonce for receiving `generation` from `leaf`. Each generation can be used once.
    pub fn key_nonce(&mut self, leaf: u32, t: RatchetType, generation: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let cs = self.cs;
        let r = self.ratchet(leaf, t)?;
        if generation < r.next_generation {
            return r.skipped.remove(&generation).ok_or(Error::GenerationGone(generation));
        }
        if generation - r.next_generation > MAX_FORWARD {
            return Err(Error::GenerationTooFar(generation));
        }
        while r.next_generation < generation {
            let g = r.next_generation;
            let kn = Self::step(cs, r)?;
            r.skipped.insert(g, kn);
            while r.skipped.len() > MAX_SKIP {
                let first = *r.skipped.keys().next().unwrap();
                r.skipped.remove(&first);
            }
        }
        Self::step(cs, r)
    }

    /// Next key and nonce for sending as `leaf`.
    pub fn next_send(&mut self, leaf: u32, t: RatchetType) -> Result<(u32, Vec<u8>, Vec<u8>)> {
        let cs = self.cs;
        let r = self.ratchet(leaf, t)?;
        let g = r.next_generation;
        let (k, n) = Self::step(cs, r)?;
        Ok((g, k, n))
    }
}

pub fn sender_data_key_nonce(cs: CipherSuite, sender_data_secret: &[u8], ciphertext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let sample = &ciphertext[..ciphertext.len().min(cs.nh())];
    Ok((cs.expand_with_label(sender_data_secret, "key", sample, cs.nk())?, cs.expand_with_label(sender_data_secret, "nonce", sample, cs.nn())?))
}
