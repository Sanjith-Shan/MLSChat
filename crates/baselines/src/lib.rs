//! Baselines for the comparisons: pairwise encryption and Sender Keys, built on
//! the same primitives as cipher suite 1 (X25519, AES-128-GCM, SHA-256, Ed25519).
//!
//! * **Pairwise.** Every pair of members shares a session. A group message is
//!   encrypted once per recipient. Sessions start with an X3DH-style handshake
//!   (three X25519 operations each side) and advance a symmetric hash ratchet
//!   per message. The Double Ratchet's DH step per round trip is not modelled,
//!   which flatters this baseline slightly on CPU.
//! * **Sender Keys.** Each member owns a hash-ratchet chain and an Ed25519 key;
//!   a group message is encrypted once and signed. Chains are handed out over
//!   the pairwise sessions. Removing a member forces every remaining member to
//!   rotate its chain and hand it to everyone else, which is quadratic in total.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().into()
}

fn hkdf(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).unwrap();
    out
}

/// A symmetric hash ratchet: message key and next chain key from HMAC.
#[derive(Clone)]
pub struct Chain {
    pub key: [u8; 32],
    pub iteration: u32,
}

impl Chain {
    pub fn new(key: [u8; 32]) -> Chain {
        Chain { key, iteration: 0 }
    }
    fn step(&mut self) -> ([u8; 16], [u8; 12], u32) {
        let mk = hmac(&self.key, &[1]);
        self.key = hmac(&self.key, &[2]);
        let it = self.iteration;
        self.iteration += 1;
        let mut k = [0u8; 16];
        k.copy_from_slice(&mk[..16]);
        let mut n = [0u8; 12];
        n.copy_from_slice(&mk[16..28]);
        (k, n, it)
    }
    /// Advance to `iteration` and return that message key.
    fn key_at(&mut self, iteration: u32) -> Option<([u8; 16], [u8; 12])> {
        if iteration < self.iteration {
            return None;
        }
        while self.iteration < iteration {
            self.step();
        }
        let (k, n, _) = self.step();
        Some((k, n))
    }
}

fn seal(k: &[u8; 16], n: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    Aes128Gcm::new_from_slice(k).unwrap().encrypt(Nonce::from_slice(n), Payload { msg: pt, aad }).unwrap()
}

fn open(k: &[u8; 16], n: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    Aes128Gcm::new_from_slice(k).unwrap().decrypt(Nonce::from_slice(n), Payload { msg: ct, aad }).ok()
}

// ---------------------------------------------------------------------------
// Pairwise sessions

/// Long-term keys published by a user (identity key and signed prekey).
pub struct Identity {
    pub ik: StaticSecret,
    pub spk: StaticSecret,
    pub sig: SigningKey,
}

#[derive(Clone)]
pub struct PublicBundle {
    pub ik: PublicKey,
    pub spk: PublicKey,
    pub spk_sig: [u8; 64],
    pub sig_pub: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Identity {
        Identity { ik: StaticSecret::random_from_rng(OsRng), spk: StaticSecret::random_from_rng(OsRng), sig: SigningKey::generate(&mut OsRng) }
    }
    pub fn bundle(&self) -> PublicBundle {
        let spk = PublicKey::from(&self.spk);
        PublicBundle { ik: PublicKey::from(&self.ik), spk, spk_sig: self.sig.sign(spk.as_bytes()).to_bytes(), sig_pub: self.sig.verifying_key() }
    }
}

/// One direction-pair session between two users.
#[derive(Clone)]
pub struct Session {
    pub send: Chain,
    pub recv: Chain,
}

/// The first message of a session carries the initiator's ephemeral key.
pub const SESSION_INIT_BYTES: usize = 32 + 32;
/// Per-message overhead on the wire: iteration counter plus AEAD tag.
pub const PAIRWISE_OVERHEAD: usize = 4 + 16;

/// Initiator side of the handshake. Returns the session and the bytes sent.
pub fn initiate(me: &Identity, them: &PublicBundle) -> (Session, PublicKey) {
    them.sig_pub.verify(them.spk.as_bytes(), &ed25519_dalek::Signature::from_bytes(&them.spk_sig)).expect("prekey signature");
    let ek = StaticSecret::random_from_rng(OsRng);
    let dh1 = me.ik.diffie_hellman(&them.spk);
    let dh2 = ek.diffie_hellman(&them.ik);
    let dh3 = ek.diffie_hellman(&them.spk);
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    let a = hkdf(&ikm, b"pairwise a->b");
    let b = hkdf(&ikm, b"pairwise b->a");
    (Session { send: Chain::new(a), recv: Chain::new(b) }, PublicKey::from(&ek))
}

pub fn respond(me: &Identity, their_ik: &PublicKey, their_ek: &PublicKey) -> Session {
    let dh1 = me.spk.diffie_hellman(their_ik);
    let dh2 = me.ik.diffie_hellman(their_ek);
    let dh3 = me.spk.diffie_hellman(their_ek);
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    let a = hkdf(&ikm, b"pairwise a->b");
    let b = hkdf(&ikm, b"pairwise b->a");
    Session { send: Chain::new(b), recv: Chain::new(a) }
}

impl Session {
    /// Encrypt one message: 4-byte iteration then ciphertext.
    pub fn encrypt(&mut self, pt: &[u8]) -> Vec<u8> {
        let (k, n, it) = self.send.step();
        let mut out = it.to_be_bytes().to_vec();
        out.extend_from_slice(&seal(&k, &n, &it.to_be_bytes(), pt));
        out
    }
    pub fn decrypt(&mut self, ct: &[u8]) -> Option<Vec<u8>> {
        let it = u32::from_be_bytes(ct.get(..4)?.try_into().ok()?);
        let (k, n) = self.recv.key_at(it)?;
        open(&k, &n, &it.to_be_bytes(), &ct[4..])
    }
}

// ---------------------------------------------------------------------------
// Sender Keys

/// A member's own sending state.
pub struct SenderKey {
    pub chain: Chain,
    pub signing: SigningKey,
}

/// What a member hands to others so they can read its messages.
#[derive(Clone)]
pub struct SenderKeyDistribution {
    pub chain_key: [u8; 32],
    pub iteration: u32,
    pub signing_pub: [u8; 32],
}

/// Wire size of a distribution message: chain key, iteration, signing key.
pub const DISTRIBUTION_BYTES: usize = 32 + 4 + 32;
/// Per-message overhead on the wire: iteration, AEAD tag, Ed25519 signature.
pub const SENDER_KEY_OVERHEAD: usize = 4 + 16 + 64;

impl SenderKey {
    pub fn generate() -> SenderKey {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        SenderKey { chain: Chain::new(k), signing: SigningKey::generate(&mut OsRng) }
    }
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution { chain_key: self.chain.key, iteration: self.chain.iteration, signing_pub: self.signing.verifying_key().to_bytes() }
    }
    /// Encrypt once for the whole group and sign the ciphertext.
    pub fn encrypt(&mut self, pt: &[u8]) -> Vec<u8> {
        let (k, n, it) = self.chain.step();
        let mut out = it.to_be_bytes().to_vec();
        out.extend_from_slice(&seal(&k, &n, &it.to_be_bytes(), pt));
        let sig = self.signing.sign(&out);
        out.extend_from_slice(&sig.to_bytes());
        out
    }
}

impl SenderKeyDistribution {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.chain_key.to_vec();
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.signing_pub);
        v
    }
}

/// A receiver's copy of someone else's sender key.
pub struct ReceiverKey {
    pub chain: Chain,
    pub verify: VerifyingKey,
}

impl ReceiverKey {
    pub fn from_distribution(d: &SenderKeyDistribution) -> ReceiverKey {
        ReceiverKey { chain: Chain { key: d.chain_key, iteration: d.iteration }, verify: VerifyingKey::from_bytes(&d.signing_pub).unwrap() }
    }
    pub fn decrypt(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < 4 + 16 + 64 {
            return None;
        }
        let (body, sig) = msg.split_at(msg.len() - 64);
        self.verify.verify(body, &ed25519_dalek::Signature::from_bytes(sig.try_into().ok()?)).ok()?;
        let it = u32::from_be_bytes(body[..4].try_into().ok()?);
        let (k, n) = self.chain.key_at(it)?;
        open(&k, &n, &it.to_be_bytes(), &body[4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairwise_roundtrip() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (mut sa, ek) = initiate(&a, &b.bundle());
        let mut sb = respond(&b, &PublicKey::from(&a.ik), &ek);
        for i in 0..5u8 {
            let c = sa.encrypt(&[i; 10]);
            assert_eq!(sb.decrypt(&c).unwrap(), vec![i; 10]);
            let c = sb.encrypt(&[i; 3]);
            assert_eq!(sa.decrypt(&c).unwrap(), vec![i; 3]);
        }
    }

    #[test]
    fn sender_key_roundtrip_and_tamper() {
        let mut s = SenderKey::generate();
        let mut r = ReceiverKey::from_distribution(&s.distribution());
        let m1 = s.encrypt(b"one");
        let m2 = s.encrypt(b"two");
        assert_eq!(r.decrypt(&m2).unwrap(), b"two");
        assert!(r.decrypt(&m1).is_none(), "skipped keys are not kept in this model");
        let mut bad = s.encrypt(b"three");
        bad[6] ^= 1;
        assert!(r.decrypt(&bad).is_none());
    }
}
