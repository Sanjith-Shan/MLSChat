//! Cipher suite primitives: hash, HKDF, HMAC, AEAD, signatures and HPKE
//! (RFC 9180, base mode, single shot), plus the MLS labeled helpers of
//! RFC 9420 section 5.
//!
//! HPKE is implemented here rather than pulled from a crate so that every byte
//! of the MLS-facing crypto is visible and checked by the crypto-basics vectors.

use crate::codec::{write_bytes, Codec};
use hmac::Mac;
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("unsupported cipher suite {0}")]
    UnsupportedSuite(u16),
    #[error("invalid public key")]
    BadPublicKey,
    #[error("invalid private key")]
    BadPrivateKey,
    #[error("AEAD authentication failed")]
    AeadFailed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("HKDF output too long")]
    KdfLength,
    #[error("DH output was the identity")]
    ZeroSharedSecret,
    #[error("key derivation failed")]
    DeriveKeyPairFailed,
}

pub type CResult<T> = std::result::Result<T, CryptoError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KemAlg {
    X25519,
    P256,
    P384,
    P521,
    X448,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed448,
}

/// An MLS cipher suite (RFC 9420 section 17.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CipherSuite(pub u16);

impl Codec for CipherSuite {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out)
    }
    fn decode(r: &mut crate::codec::Reader) -> crate::codec::Result<Self> {
        Ok(CipherSuite(u16::decode(r)?))
    }
}

pub const MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519: CipherSuite = CipherSuite(1);
pub const MLS_128_DHKEMP256_AES128GCM_SHA256_P256: CipherSuite = CipherSuite(2);
pub const MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519: CipherSuite = CipherSuite(3);
pub const MLS_256_DHKEMX448_AES256GCM_SHA512_ED448: CipherSuite = CipherSuite(4);
pub const MLS_256_DHKEMP521_AES256GCM_SHA512_P521: CipherSuite = CipherSuite(5);
pub const MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448: CipherSuite = CipherSuite(6);
pub const MLS_256_DHKEMP384_AES256GCM_SHA384_P384: CipherSuite = CipherSuite(7);

/// Suites this library implements: all seven defined in RFC 9420.
pub const SUPPORTED_SUITES: [u16; 7] = [1, 2, 3, 4, 5, 6, 7];

impl CipherSuite {
    pub fn is_supported(self) -> bool {
        SUPPORTED_SUITES.contains(&self.0)
    }

    fn parts(self) -> CResult<(KemAlg, AeadAlg, HashAlg, SigAlg)> {
        use AeadAlg::*;
        use HashAlg::*;
        Ok(match self.0 {
            1 => (KemAlg::X25519, Aes128Gcm, Sha256, SigAlg::Ed25519),
            2 => (KemAlg::P256, Aes128Gcm, Sha256, SigAlg::EcdsaP256),
            3 => (KemAlg::X25519, ChaCha20Poly1305, Sha256, SigAlg::Ed25519),
            4 => (KemAlg::X448, Aes256Gcm, Sha512, SigAlg::Ed448),
            5 => (KemAlg::P521, Aes256Gcm, Sha512, SigAlg::EcdsaP521),
            6 => (KemAlg::X448, ChaCha20Poly1305, Sha512, SigAlg::Ed448),
            7 => (KemAlg::P384, Aes256Gcm, Sha384, SigAlg::EcdsaP384),
            x => return Err(CryptoError::UnsupportedSuite(x)),
        })
    }
    pub fn check(self) -> CResult<()> {
        self.parts().map(|_| ())
    }
    pub fn kem(self) -> KemAlg {
        self.parts().expect("unsupported suite").0
    }
    pub fn aead(self) -> AeadAlg {
        self.parts().expect("unsupported suite").1
    }
    pub fn hash_alg(self) -> HashAlg {
        self.parts().expect("unsupported suite").2
    }
    pub fn sig(self) -> SigAlg {
        self.parts().expect("unsupported suite").3
    }

    // ---- hash / kdf / mac ----

    pub fn nh(self) -> usize {
        self.hash_alg().len()
    }
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        self.hash_alg().hash(data)
    }
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.hash_alg().extract(salt, ikm)
    }
    pub fn expand(self, prk: &[u8], info: &[u8], len: usize) -> CResult<Vec<u8>> {
        self.hash_alg().expand(prk, info, len)
    }
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        self.hash_alg().mac(key, data)
    }
    pub fn verify_mac(self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let t = self.mac(key, data);
        t.len() == tag.len() && bool::from(t.ct_eq(tag))
    }

    // ---- aead ----

    pub fn nk(self) -> usize {
        self.aead().nk()
    }
    pub fn nn(self) -> usize {
        12
    }
    pub fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> CResult<Vec<u8>> {
        self.aead().seal(key, nonce, aad, pt)
    }
    pub fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> CResult<Vec<u8>> {
        self.aead().open(key, nonce, aad, ct)
    }

    // ---- signatures ----

    pub fn sign(self, sk: &[u8], msg: &[u8]) -> CResult<Vec<u8>> {
        sig_sign(self.sig(), sk, msg)
    }
    pub fn verify(self, pk: &[u8], msg: &[u8], sig: &[u8]) -> CResult<()> {
        sig_verify(self.sig(), pk, msg, sig)
    }
    /// Fresh signature key pair `(private, public)`.
    pub fn signature_keypair(self) -> (Vec<u8>, Vec<u8>) {
        sig_keygen(self.sig())
    }
    pub fn signature_public(self, sk: &[u8]) -> CResult<Vec<u8>> {
        sig_public(self.sig(), sk)
    }

    // ---- HPKE ----

    pub fn hpke(self) -> Hpke {
        let (kem, aead, hash, _) = self.parts().expect("unsupported suite");
        Hpke { kem, aead, kdf: hash }
    }
    pub fn derive_keypair(self, ikm: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
        self.hpke().derive_keypair(ikm)
    }
    pub fn generate_keypair(self) -> (Vec<u8>, Vec<u8>) {
        let mut ikm = Zeroizing::new(vec![0u8; self.hpke().kem.nsk()]);
        OsRng.fill_bytes(&mut ikm);
        self.derive_keypair(&ikm).expect("derive from random ikm")
    }
    pub fn hpke_public(self, sk: &[u8]) -> CResult<Vec<u8>> {
        kem_public(self.kem(), sk)
    }

    // ---- MLS labeled helpers (RFC 9420 section 5) ----

    pub fn expand_with_label(self, secret: &[u8], label: &str, context: &[u8], len: usize) -> CResult<Vec<u8>> {
        let mut info = Vec::new();
        (len as u16).encode(&mut info);
        write_bytes(&mut info, &mls_label(label));
        write_bytes(&mut info, context);
        self.expand(secret, &info, len)
    }
    pub fn derive_secret(self, secret: &[u8], label: &str) -> CResult<Vec<u8>> {
        self.expand_with_label(secret, label, &[], self.nh())
    }
    pub fn derive_tree_secret(self, secret: &[u8], label: &str, generation: u32, len: usize) -> CResult<Vec<u8>> {
        self.expand_with_label(secret, label, &generation.to_be_bytes(), len)
    }
    pub fn ref_hash(self, label: &str, value: &[u8]) -> Vec<u8> {
        let mut inp = Vec::new();
        write_bytes(&mut inp, label.as_bytes());
        write_bytes(&mut inp, value);
        self.hash(&inp)
    }
    pub fn sign_with_label(self, sk: &[u8], label: &str, content: &[u8]) -> CResult<Vec<u8>> {
        self.sign(sk, &sign_content(label, content))
    }
    pub fn verify_with_label(self, pk: &[u8], label: &str, content: &[u8], sig: &[u8]) -> CResult<()> {
        self.verify(pk, &sign_content(label, content), sig)
    }
    pub fn encrypt_with_label(self, pk: &[u8], label: &str, context: &[u8], pt: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
        self.hpke().seal(pk, &encrypt_context(label, context), &[], pt)
    }
    pub fn decrypt_with_label(self, sk: &[u8], label: &str, context: &[u8], kem_output: &[u8], ct: &[u8]) -> CResult<Vec<u8>> {
        self.hpke().open(sk, kem_output, &encrypt_context(label, context), &[], ct)
    }
}

fn mls_label(label: &str) -> Vec<u8> {
    let mut v = b"MLS 1.0 ".to_vec();
    v.extend_from_slice(label.as_bytes());
    v
}

fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    write_bytes(&mut v, &mls_label(label));
    write_bytes(&mut v, content);
    v
}

fn encrypt_context(label: &str, context: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    write_bytes(&mut v, &mls_label(label));
    write_bytes(&mut v, context);
    v
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

// ---------------------------------------------------------------------------
// Hash, HKDF, HMAC

macro_rules! with_hash {
    ($alg:expr, $H:ident => $body:expr) => {
        match $alg {
            HashAlg::Sha256 => {
                type $H = sha2::Sha256;
                $body
            }
            HashAlg::Sha384 => {
                type $H = sha2::Sha384;
                $body
            }
            HashAlg::Sha512 => {
                type $H = sha2::Sha512;
                $body
            }
        }
    };
}

impl HashAlg {
    pub fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        with_hash!(self, H => H::digest(data).to_vec())
    }
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        with_hash!(self, H => hkdf::Hkdf::<H>::extract(Some(salt), ikm).0.to_vec())
    }
    pub fn expand(self, prk: &[u8], info: &[u8], len: usize) -> CResult<Vec<u8>> {
        let mut out = vec![0u8; len];
        with_hash!(self, H => {
            let hk = hkdf::Hkdf::<H>::from_prk(prk).map_err(|_| CryptoError::KdfLength)?;
            hk.expand(info, &mut out).map_err(|_| CryptoError::KdfLength)?;
        });
        Ok(out)
    }
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        with_hash!(self, H => {
            let mut m = <hmac::Hmac<H> as hmac::Mac>::new_from_slice(key).expect("hmac takes any key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        })
    }
}

// ---------------------------------------------------------------------------
// AEAD

impl AeadAlg {
    pub fn nk(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
    fn id(self) -> u16 {
        match self {
            AeadAlg::Aes128Gcm => 1,
            AeadAlg::Aes256Gcm => 2,
            AeadAlg::ChaCha20Poly1305 => 3,
        }
    }
    pub fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> CResult<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let p = Payload { msg: pt, aad };
        let n = aes_gcm::Nonce::from_slice(nonce);
        let r = match self {
            AeadAlg::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::AeadFailed)?.encrypt(n, p),
            AeadAlg::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AeadFailed)?.encrypt(n, p),
            AeadAlg::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| CryptoError::AeadFailed)?
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), p),
        };
        r.map_err(|_| CryptoError::AeadFailed)
    }
    pub fn open(self, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> CResult<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        if nonce.len() != 12 {
            return Err(CryptoError::AeadFailed);
        }
        let p = Payload { msg: ct, aad };
        let n = aes_gcm::Nonce::from_slice(nonce);
        let r = match self {
            AeadAlg::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::AeadFailed)?.decrypt(n, p),
            AeadAlg::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AeadFailed)?.decrypt(n, p),
            AeadAlg::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| CryptoError::AeadFailed)?
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), p),
        };
        r.map_err(|_| CryptoError::AeadFailed)
    }
}

// ---------------------------------------------------------------------------
// Signatures

fn sig_sign(alg: SigAlg, sk: &[u8], msg: &[u8]) -> CResult<Vec<u8>> {
    use signature::Signer;
    Ok(match alg {
        SigAlg::Ed448 => ed448_signing_key(sk)?.sign_raw(msg).to_bytes().to_vec(),
        SigAlg::Ed25519 => {
            let b: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadPrivateKey)?;
            ed25519_dalek::SigningKey::from_bytes(&b).sign(msg).to_bytes().to_vec()
        }
        SigAlg::EcdsaP256 => {
            let k = p256::ecdsa::SigningKey::from_slice(sk).map_err(|_| CryptoError::BadPrivateKey)?;
            let s: p256::ecdsa::Signature = k.sign(msg);
            s.to_der().as_bytes().to_vec()
        }
        SigAlg::EcdsaP384 => {
            let k = p384::ecdsa::SigningKey::from_slice(sk).map_err(|_| CryptoError::BadPrivateKey)?;
            let s: p384::ecdsa::Signature = k.sign(msg);
            s.to_der().as_bytes().to_vec()
        }
        SigAlg::EcdsaP521 => {
            let k = p521::ecdsa::SigningKey::from_slice(sk).map_err(|_| CryptoError::BadPrivateKey)?;
            let s: p521::ecdsa::Signature = k.sign(msg);
            s.to_der().as_bytes().to_vec()
        }
    })
}

fn sig_verify(alg: SigAlg, pk: &[u8], msg: &[u8], sig: &[u8]) -> CResult<()> {
    use signature::Verifier;
    let bad = |_| CryptoError::BadSignature;
    match alg {
        SigAlg::Ed448 => {
            let b: [u8; 57] = pk.try_into().map_err(|_| CryptoError::BadPublicKey)?;
            let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(&b).map_err(|_| CryptoError::BadPublicKey)?;
            let s = ed448_goldilocks_plus::Signature::from_slice(sig).map_err(|_| CryptoError::BadSignature)?;
            vk.verify_raw(&s, msg).map_err(|_| CryptoError::BadSignature)
        }
        SigAlg::Ed25519 => {
            let b: [u8; 32] = pk.try_into().map_err(|_| CryptoError::BadPublicKey)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&b).map_err(|_| CryptoError::BadPublicKey)?;
            let s = ed25519_dalek::Signature::from_slice(sig).map_err(bad)?;
            vk.verify_strict(msg, &s).map_err(bad)
        }
        SigAlg::EcdsaP256 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| CryptoError::BadPublicKey)?;
            let s = p256::ecdsa::Signature::from_der(sig).map_err(bad)?;
            vk.verify(msg, &s).map_err(bad)
        }
        SigAlg::EcdsaP384 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| CryptoError::BadPublicKey)?;
            let s = p384::ecdsa::Signature::from_der(sig).map_err(bad)?;
            vk.verify(msg, &s).map_err(bad)
        }
        SigAlg::EcdsaP521 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| CryptoError::BadPublicKey)?;
            let s = p521::ecdsa::Signature::from_der(sig).map_err(bad)?;
            vk.verify(msg, &s).map_err(bad)
        }
    }
}

fn sig_keygen(alg: SigAlg) -> (Vec<u8>, Vec<u8>) {
    let sk = match alg {
        SigAlg::Ed25519 => ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes().to_vec(),
        SigAlg::EcdsaP256 => p256::SecretKey::random(&mut OsRng).to_bytes().to_vec(),
        SigAlg::EcdsaP384 => p384::SecretKey::random(&mut OsRng).to_bytes().to_vec(),
        SigAlg::EcdsaP521 => p521::SecretKey::random(&mut OsRng).to_bytes().to_vec(),
        SigAlg::Ed448 => random_bytes(57),
    };
    let pk = sig_public(alg, &sk).expect("fresh key");
    (sk, pk)
}

fn sig_public(alg: SigAlg, sk: &[u8]) -> CResult<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let e = |_| CryptoError::BadPrivateKey;
    Ok(match alg {
        SigAlg::Ed448 => ed448_signing_key(sk)?.verifying_key().to_bytes().to_vec(),
        SigAlg::Ed25519 => {
            let b: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadPrivateKey)?;
            ed25519_dalek::SigningKey::from_bytes(&b).verifying_key().to_bytes().to_vec()
        }
        SigAlg::EcdsaP256 => p256::SecretKey::from_slice(sk).map_err(e)?.public_key().to_encoded_point(false).as_bytes().to_vec(),
        SigAlg::EcdsaP384 => p384::SecretKey::from_slice(sk).map_err(e)?.public_key().to_encoded_point(false).as_bytes().to_vec(),
        SigAlg::EcdsaP521 => p521::SecretKey::from_slice(sk).map_err(e)?.public_key().to_encoded_point(false).as_bytes().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// HPKE (RFC 9180), base mode, DHKEM

impl KemAlg {
    pub fn id(self) -> u16 {
        match self {
            KemAlg::P256 => 0x10,
            KemAlg::P384 => 0x11,
            KemAlg::P521 => 0x12,
            KemAlg::X25519 => 0x20,
            KemAlg::X448 => 0x21,
        }
    }
    /// The hash used inside the DHKEM.
    fn kdf(self) -> HashAlg {
        match self {
            KemAlg::P256 | KemAlg::X25519 => HashAlg::Sha256,
            KemAlg::P384 => HashAlg::Sha384,
            KemAlg::P521 => HashAlg::Sha512,
            KemAlg::X448 => HashAlg::Sha512,
        }
    }
    pub fn nsecret(self) -> usize {
        self.kdf().len()
    }
    pub fn nsk(self) -> usize {
        match self {
            KemAlg::X25519 | KemAlg::P256 => 32,
            KemAlg::P384 => 48,
            KemAlg::P521 => 66,
            KemAlg::X448 => 56,
        }
    }
    fn suite_id(self) -> Vec<u8> {
        let mut v = b"KEM".to_vec();
        v.extend_from_slice(&self.id().to_be_bytes());
        v
    }
}

fn kem_public(kem: KemAlg, sk: &[u8]) -> CResult<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let e = |_| CryptoError::BadPrivateKey;
    Ok(match kem {
        KemAlg::X448 => {
            let s: [u8; 56] = sk.try_into().map_err(|_| CryptoError::BadPrivateKey)?;
            let mut base = [0u8; 56];
            base[0] = 5;
            ed448_goldilocks_plus::x448::x448(s, base).to_vec()
        }
        KemAlg::X25519 => {
            let b: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadPrivateKey)?;
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(b)).as_bytes().to_vec()
        }
        KemAlg::P256 => p256::SecretKey::from_slice(sk).map_err(e)?.public_key().to_encoded_point(false).as_bytes().to_vec(),
        KemAlg::P384 => p384::SecretKey::from_slice(sk).map_err(e)?.public_key().to_encoded_point(false).as_bytes().to_vec(),
        KemAlg::P521 => p521::SecretKey::from_slice(sk).map_err(e)?.public_key().to_encoded_point(false).as_bytes().to_vec(),
    })
}

fn kem_dh(kem: KemAlg, sk: &[u8], pk: &[u8]) -> CResult<Zeroizing<Vec<u8>>> {
    let bp = |_| CryptoError::BadPublicKey;
    let bs = |_| CryptoError::BadPrivateKey;
    Ok(Zeroizing::new(match kem {
        KemAlg::X448 => {
            let s: [u8; 56] = sk.try_into().map_err(|_| CryptoError::BadPrivateKey)?;
            let p: [u8; 56] = pk.try_into().map_err(|_| CryptoError::BadPublicKey)?;
            let out = ed448_goldilocks_plus::x448::x448(s, p);
            if out.iter().all(|b| *b == 0) {
                return Err(CryptoError::ZeroSharedSecret);
            }
            out.to_vec()
        }
        KemAlg::X25519 => {
            let s: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadPrivateKey)?;
            let p: [u8; 32] = pk.try_into().map_err(|_| CryptoError::BadPublicKey)?;
            let ss = x25519_dalek::StaticSecret::from(s).diffie_hellman(&x25519_dalek::PublicKey::from(p));
            if !ss.was_contributory() {
                return Err(CryptoError::ZeroSharedSecret);
            }
            ss.as_bytes().to_vec()
        }
        KemAlg::P256 => {
            let s = p256::SecretKey::from_slice(sk).map_err(bs)?;
            let p = p256::PublicKey::from_sec1_bytes(pk).map_err(bp)?;
            p256::ecdh::diffie_hellman(s.to_nonzero_scalar(), p.as_affine()).raw_secret_bytes().to_vec()
        }
        KemAlg::P384 => {
            let s = p384::SecretKey::from_slice(sk).map_err(bs)?;
            let p = p384::PublicKey::from_sec1_bytes(pk).map_err(bp)?;
            p384::ecdh::diffie_hellman(s.to_nonzero_scalar(), p.as_affine()).raw_secret_bytes().to_vec()
        }
        KemAlg::P521 => {
            let s = p521::SecretKey::from_slice(sk).map_err(bs)?;
            let p = p521::PublicKey::from_sec1_bytes(pk).map_err(bp)?;
            p521::ecdh::diffie_hellman(s.to_nonzero_scalar(), p.as_affine()).raw_secret_bytes().to_vec()
        }
    }))
}

#[derive(Clone, Copy, Debug)]
pub struct Hpke {
    pub kem: KemAlg,
    pub aead: AeadAlg,
    pub kdf: HashAlg,
}

fn labeled_extract(h: HashAlg, suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> Vec<u8> {
    let mut l = b"HPKE-v1".to_vec();
    l.extend_from_slice(suite_id);
    l.extend_from_slice(label.as_bytes());
    l.extend_from_slice(ikm);
    h.extract(salt, &l)
}

fn labeled_expand(h: HashAlg, suite_id: &[u8], prk: &[u8], label: &str, info: &[u8], len: usize) -> CResult<Vec<u8>> {
    let mut l = (len as u16).to_be_bytes().to_vec();
    l.extend_from_slice(b"HPKE-v1");
    l.extend_from_slice(suite_id);
    l.extend_from_slice(label.as_bytes());
    l.extend_from_slice(info);
    h.expand(prk, &l, len)
}

impl Hpke {
    fn suite_id(&self) -> Vec<u8> {
        let mut v = b"HPKE".to_vec();
        v.extend_from_slice(&self.kem.id().to_be_bytes());
        let kdf_id: u16 = match self.kdf {
            HashAlg::Sha256 => 1,
            HashAlg::Sha384 => 2,
            HashAlg::Sha512 => 3,
        };
        v.extend_from_slice(&kdf_id.to_be_bytes());
        v.extend_from_slice(&self.aead.id().to_be_bytes());
        v
    }

    /// DeriveKeyPair from RFC 9180 section 7.1.3. Returns `(private, public)`.
    pub fn derive_keypair(&self, ikm: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
        let kem = self.kem;
        let sid = kem.suite_id();
        let h = kem.kdf();
        let dkp_prk = labeled_extract(h, &sid, &[], "dkp_prk", ikm);
        let sk = match kem {
            KemAlg::X25519 => labeled_expand(h, &sid, &dkp_prk, "sk", &[], 32)?,
            KemAlg::X448 => labeled_expand(h, &sid, &dkp_prk, "sk", &[], 56)?,
            KemAlg::P256 | KemAlg::P384 | KemAlg::P521 => {
                let mask = if kem == KemAlg::P521 { 0x01 } else { 0xff };
                let mut found = None;
                for counter in 0u8..=255 {
                    let mut bytes = labeled_expand(h, &sid, &dkp_prk, "candidate", &[counter], kem.nsk())?;
                    bytes[0] &= mask;
                    if kem_public(kem, &bytes).is_ok() {
                        found = Some(bytes);
                        break;
                    }
                }
                found.ok_or(CryptoError::DeriveKeyPairFailed)?
            }
        };
        let pk = kem_public(kem, &sk)?;
        Ok((sk, pk))
    }

    fn extract_and_expand(&self, dh: &[u8], kem_context: &[u8]) -> CResult<Vec<u8>> {
        let sid = self.kem.suite_id();
        let h = self.kem.kdf();
        let prk = labeled_extract(h, &sid, &[], "eae_prk", dh);
        labeled_expand(h, &sid, &prk, "shared_secret", kem_context, self.kem.nsecret())
    }

    fn key_schedule(&self, shared_secret: &[u8], info: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
        let (key, nonce, _) = self.key_schedule_full(shared_secret, info)?;
        Ok((key, nonce))
    }

    /// Returns (key, base_nonce, exporter_secret).
    fn key_schedule_full(&self, shared_secret: &[u8], info: &[u8]) -> CResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let sid = self.suite_id();
        let h = self.kdf;
        let psk_id_hash = labeled_extract(h, &sid, &[], "psk_id_hash", &[]);
        let info_hash = labeled_extract(h, &sid, &[], "info_hash", info);
        let mut ctx = vec![0u8]; // mode_base
        ctx.extend_from_slice(&psk_id_hash);
        ctx.extend_from_slice(&info_hash);
        let secret = labeled_extract(h, &sid, shared_secret, "secret", &[]);
        let key = labeled_expand(h, &sid, &secret, "key", &ctx, self.aead.nk())?;
        let nonce = labeled_expand(h, &sid, &secret, "base_nonce", &ctx, 12)?;
        let exp = labeled_expand(h, &sid, &secret, "exp", &ctx, h.len())?;
        Ok((key, nonce, exp))
    }

    fn export_from(&self, exporter_secret: &[u8], exporter_context: &[u8], len: usize) -> CResult<Vec<u8>> {
        labeled_expand(self.kdf, &self.suite_id(), exporter_secret, "sec", exporter_context, len)
    }

    /// SetupBaseS followed by Export. Returns `(enc, exported_secret)`.
    pub fn send_export(&self, pk_r: &[u8], info: &[u8], exporter_context: &[u8], len: usize) -> CResult<(Vec<u8>, Vec<u8>)> {
        let mut ikm = Zeroizing::new(vec![0u8; self.kem.nsk()]);
        OsRng.fill_bytes(&mut ikm);
        let (sk_e, pk_e) = self.derive_keypair(&ikm)?;
        let dh = kem_dh(self.kem, &sk_e, pk_r)?;
        let mut kem_context = pk_e.clone();
        kem_context.extend_from_slice(pk_r);
        let ss = Zeroizing::new(self.extract_and_expand(&dh, &kem_context)?);
        let (_, _, exp) = self.key_schedule_full(&ss, info)?;
        Ok((pk_e, self.export_from(&exp, exporter_context, len)?))
    }

    /// SetupBaseR followed by Export.
    pub fn receive_export(&self, sk_r: &[u8], enc: &[u8], info: &[u8], exporter_context: &[u8], len: usize) -> CResult<Vec<u8>> {
        let dh = kem_dh(self.kem, sk_r, enc)?;
        let pk_r = kem_public(self.kem, sk_r)?;
        let mut kem_context = enc.to_vec();
        kem_context.extend_from_slice(&pk_r);
        let ss = Zeroizing::new(self.extract_and_expand(&dh, &kem_context)?);
        let (_, _, exp) = self.key_schedule_full(&ss, info)?;
        self.export_from(&exp, exporter_context, len)
    }

    /// Single-shot SealBase. Returns `(enc, ciphertext)`.
    pub fn seal(&self, pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
        let mut ikm = Zeroizing::new(vec![0u8; self.kem.nsk()]);
        OsRng.fill_bytes(&mut ikm);
        let (sk_e, pk_e) = self.derive_keypair(&ikm)?;
        let dh = kem_dh(self.kem, &sk_e, pk_r)?;
        let mut kem_context = pk_e.clone();
        kem_context.extend_from_slice(pk_r);
        let ss = Zeroizing::new(self.extract_and_expand(&dh, &kem_context)?);
        let (key, nonce) = self.key_schedule(&ss, info)?;
        let ct = self.aead.seal(&key, &nonce, aad, pt)?;
        Ok((pk_e, ct))
    }

    pub fn open(&self, sk_r: &[u8], enc: &[u8], info: &[u8], aad: &[u8], ct: &[u8]) -> CResult<Vec<u8>> {
        let dh = kem_dh(self.kem, sk_r, enc)?;
        let pk_r = kem_public(self.kem, sk_r)?;
        let mut kem_context = enc.to_vec();
        kem_context.extend_from_slice(&pk_r);
        let ss = Zeroizing::new(self.extract_and_expand(&dh, &kem_context)?);
        let (key, nonce) = self.key_schedule(&ss, info)?;
        self.aead.open(&key, &nonce, aad, ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_roundtrip_all_suites() {
        for s in SUPPORTED_SUITES {
            let cs = CipherSuite(s);
            let (sk, pk) = cs.generate_keypair();
            let (enc, ct) = cs.encrypt_with_label(&pk, "test", b"ctx", b"hello").unwrap();
            assert_eq!(cs.decrypt_with_label(&sk, "test", b"ctx", &enc, &ct).unwrap(), b"hello");
            let (ssk, spk) = cs.signature_keypair();
            let sig = cs.sign_with_label(&ssk, "L", b"m").unwrap();
            cs.verify_with_label(&spk, "L", b"m", &sig).unwrap();
            assert!(cs.verify_with_label(&spk, "L", b"x", &sig).is_err());
        }
    }
}

fn ed448_signing_key(sk: &[u8]) -> CResult<ed448_goldilocks_plus::SigningKey> {
    ed448_goldilocks_plus::SigningKey::try_from(sk).map_err(|_| CryptoError::BadPrivateKey)
}
