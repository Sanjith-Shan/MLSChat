//! Key schedule (RFC 9420 section 8), pre-shared keys (8.4), exporter (8.5)
//! and transcript hashes (8.2).

use crate::codec::Codec;
use crate::crypto::CipherSuite;
use crate::error::Result;
use crate::messages::{AuthenticatedContent, PreSharedKeyId};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecrets {
    pub joiner_secret: Vec<u8>,
    pub welcome_secret: Vec<u8>,
    pub epoch_secret: Vec<u8>,
    pub sender_data_secret: Vec<u8>,
    pub encryption_secret: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    pub epoch_authenticator: Vec<u8>,
    pub external_secret: Vec<u8>,
    pub confirmation_key: Vec<u8>,
    pub membership_key: Vec<u8>,
    pub resumption_psk: Vec<u8>,
    pub init_secret: Vec<u8>,
}

/// `joiner_secret = ExpandWithLabel(Extract(init_secret, commit_secret), "joiner", GroupContext, Nh)`.
pub fn joiner_secret(cs: CipherSuite, init_secret: &[u8], commit_secret: Option<&[u8]>, group_context: &[u8]) -> Result<Vec<u8>> {
    let zero = vec![0u8; cs.nh()];
    let prk = cs.extract(init_secret, commit_secret.unwrap_or(&zero));
    Ok(cs.expand_with_label(&prk, "joiner", group_context, cs.nh())?)
}

/// Derive every epoch secret from the joiner secret, PSK secret and new group context.
pub fn from_joiner(cs: CipherSuite, joiner_secret: &[u8], psk_secret: Option<&[u8]>, group_context: &[u8]) -> Result<EpochSecrets> {
    let zero = vec![0u8; cs.nh()];
    let member = cs.extract(joiner_secret, psk_secret.unwrap_or(&zero));
    let welcome_secret = cs.derive_secret(&member, "welcome")?;
    let epoch_secret = cs.expand_with_label(&member, "epoch", group_context, cs.nh())?;
    let d = |l: &str| cs.derive_secret(&epoch_secret, l);
    Ok(EpochSecrets {
        joiner_secret: joiner_secret.to_vec(),
        welcome_secret,
        sender_data_secret: d("sender data")?,
        encryption_secret: d("encryption")?,
        exporter_secret: d("exporter")?,
        epoch_authenticator: d("authentication")?,
        external_secret: d("external")?,
        confirmation_key: d("confirm")?,
        membership_key: d("membership")?,
        resumption_psk: d("resumption")?,
        init_secret: d("init")?,
        epoch_secret,
    })
}

pub fn derive(cs: CipherSuite, init_secret: &[u8], commit_secret: Option<&[u8]>, psk_secret: Option<&[u8]>, group_context: &[u8]) -> Result<EpochSecrets> {
    let j = joiner_secret(cs, init_secret, commit_secret, group_context)?;
    from_joiner(cs, &j, psk_secret, group_context)
}

impl EpochSecrets {
    /// `MLS-Exporter(label, context, length)`.
    pub fn export(&self, cs: CipherSuite, label: &str, context: &[u8], len: usize) -> Result<Vec<u8>> {
        let s = cs.derive_secret(&self.exporter_secret, label)?;
        Ok(cs.expand_with_label(&s, "exported", &cs.hash(context), len)?)
    }
    /// Public key of the external HPKE key pair (`external_pub` extension).
    pub fn external_pub(&self, cs: CipherSuite) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok(cs.derive_keypair(&self.external_secret)?)
    }
}

/// Welcome key and nonce from the welcome secret.
pub fn welcome_key_nonce(cs: CipherSuite, welcome_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((cs.expand_with_label(welcome_secret, "key", &[], cs.nk())?, cs.expand_with_label(welcome_secret, "nonce", &[], cs.nn())?))
}

/// `psk_secret` from an ordered list of (PreSharedKeyID, psk value). Returns None for an empty list.
pub fn psk_secret(cs: CipherSuite, psks: &[(PreSharedKeyId, Vec<u8>)]) -> Result<Option<Vec<u8>>> {
    if psks.is_empty() {
        return Ok(None);
    }
    let zero = vec![0u8; cs.nh()];
    let mut secret = zero.clone();
    let count = psks.len() as u16;
    for (i, (id, psk)) in psks.iter().enumerate() {
        let extracted = cs.extract(&zero, psk);
        let mut label = Vec::new();
        id.encode(&mut label);
        (i as u16).encode(&mut label);
        count.encode(&mut label);
        let input = cs.expand_with_label(&extracted, "derived psk", &label, cs.nh())?;
        secret = cs.extract(&input, &secret);
    }
    Ok(Some(secret))
}

pub fn confirmed_transcript_hash(cs: CipherSuite, interim_before: &[u8], ac: &AuthenticatedContent) -> Vec<u8> {
    let mut inp = interim_before.to_vec();
    inp.extend_from_slice(&ac.confirmed_transcript_input());
    cs.hash(&inp)
}

pub fn interim_transcript_hash(cs: CipherSuite, confirmed: &[u8], confirmation_tag: &[u8]) -> Vec<u8> {
    let mut inp = confirmed.to_vec();
    confirmation_tag.to_vec().encode(&mut inp);
    cs.hash(&inp)
}
