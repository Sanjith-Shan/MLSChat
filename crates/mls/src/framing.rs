//! Message protection (RFC 9420 section 6): signing and membership tags for
//! PublicMessage, sender-data and content encryption for PrivateMessage.

use crate::codec::{Codec, Reader};
use crate::crypto::{random_bytes, CipherSuite};
use crate::error::{proto, Error, Result};
use crate::messages::*;
use crate::secret_tree::{sender_data_key_nonce, RatchetType, SecretTree};

/// Sign framed content, producing AuthenticatedContent.
pub fn sign_content(
    cs: CipherSuite,
    signature_priv: &[u8],
    wire_format: WireFormat,
    content: FramedContent,
    context: Option<&GroupContext>,
    confirmation_tag: Option<Vec<u8>>,
) -> Result<AuthenticatedContent> {
    let tbs = framed_content_tbs(wire_format, &content, context);
    let signature = cs.sign_with_label(signature_priv, "FramedContentTBS", &tbs)?;
    Ok(AuthenticatedContent { wire_format, content, auth: FramedContentAuthData { signature, confirmation_tag } })
}

pub fn verify_content_signature(cs: CipherSuite, ac: &AuthenticatedContent, context: Option<&GroupContext>, signature_pub: &[u8]) -> Result<()> {
    let tbs = framed_content_tbs(ac.wire_format, &ac.content, context);
    cs.verify_with_label(signature_pub, "FramedContentTBS", &tbs, &ac.auth.signature)?;
    Ok(())
}

fn membership_tag_input(ac: &AuthenticatedContent, context: Option<&GroupContext>) -> Vec<u8> {
    let mut tbm = framed_content_tbs(ac.wire_format, &ac.content, context);
    ac.auth.encode(&mut tbm);
    tbm
}

/// Wrap signed content as a PublicMessage, adding the membership tag for member senders.
pub fn to_public(cs: CipherSuite, ac: AuthenticatedContent, context: Option<&GroupContext>, membership_key: Option<&[u8]>) -> Result<PublicMessage> {
    if ac.wire_format != WireFormat::PublicMessage {
        return proto("content was not signed for a PublicMessage");
    }
    if ac.content.content.content_type() == ContentType::Application {
        return proto("application data must not be sent as a PublicMessage");
    }
    let membership_tag = match ac.content.sender {
        Sender::Member(_) => {
            let key = membership_key.ok_or_else(|| Error::Protocol("membership key needed".into()))?;
            Some(cs.mac(key, &membership_tag_input(&ac, context)))
        }
        _ => None,
    };
    Ok(PublicMessage { content: ac.content, auth: ac.auth, membership_tag })
}

/// Check the membership tag of a PublicMessage and return its AuthenticatedContent.
/// The signature is checked separately once the sender's key is known.
pub fn from_public(cs: CipherSuite, pm: &PublicMessage, context: Option<&GroupContext>, membership_key: Option<&[u8]>) -> Result<AuthenticatedContent> {
    if pm.content.content.content_type() == ContentType::Application {
        return proto("application data in a PublicMessage");
    }
    let ac = AuthenticatedContent { wire_format: WireFormat::PublicMessage, content: pm.content.clone(), auth: pm.auth.clone() };
    if let Sender::Member(_) = pm.content.sender {
        let key = membership_key.ok_or_else(|| Error::Protocol("membership key needed".into()))?;
        let tag = pm.membership_tag.as_ref().ok_or_else(|| Error::Protocol("missing membership tag".into()))?;
        if !cs.verify_mac(key, &membership_tag_input(&ac, context), tag) {
            return proto("bad membership tag");
        }
    }
    Ok(ac)
}

fn private_content_aad(pm_group_id: &[u8], epoch: u64, ct: ContentType, authenticated_data: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    pm_group_id.to_vec().encode(&mut aad);
    epoch.encode(&mut aad);
    ct.encode(&mut aad);
    authenticated_data.to_vec().encode(&mut aad);
    aad
}

fn sender_data_aad(group_id: &[u8], epoch: u64, ct: ContentType) -> Vec<u8> {
    let mut aad = Vec::new();
    group_id.to_vec().encode(&mut aad);
    epoch.encode(&mut aad);
    ct.encode(&mut aad);
    aad
}

fn ratchet_for(ct: ContentType) -> RatchetType {
    match ct {
        ContentType::Application => RatchetType::Application,
        _ => RatchetType::Handshake,
    }
}

/// Encrypt signed content (wire format private_message) for a member sender.
pub fn encrypt_private(
    cs: CipherSuite,
    ac: &AuthenticatedContent,
    secrets: &mut SecretTree,
    sender_data_secret: &[u8],
    padding: usize,
) -> Result<PrivateMessage> {
    let leaf = match ac.content.sender {
        Sender::Member(l) => l,
        _ => return proto("only members send PrivateMessage"),
    };
    if ac.wire_format != WireFormat::PrivateMessage {
        return proto("content was not signed for a PrivateMessage");
    }
    let ct = ac.content.content.content_type();
    let (generation, key, mut nonce) = secrets.next_send(leaf, ratchet_for(ct))?;
    let reuse_guard: [u8; 4] = random_bytes(4).try_into().unwrap();
    for i in 0..4 {
        nonce[i] ^= reuse_guard[i];
    }
    let mut pt = Vec::new();
    ac.content.content.encode_body(&mut pt);
    ac.auth.encode(&mut pt);
    pt.resize(pt.len() + padding, 0);
    let c = &ac.content;
    let aad = private_content_aad(&c.group_id, c.epoch, ct, &c.authenticated_data);
    let ciphertext = cs.seal(&key, &nonce, &aad, &pt)?;

    let sd = SenderData { leaf_index: leaf, generation, reuse_guard };
    let (sk, sn) = sender_data_key_nonce(cs, sender_data_secret, &ciphertext)?;
    let encrypted_sender_data = cs.seal(&sk, &sn, &sender_data_aad(&c.group_id, c.epoch, ct), &sd.to_bytes())?;
    Ok(PrivateMessage {
        group_id: c.group_id.clone(),
        epoch: c.epoch,
        content_type: ct,
        authenticated_data: c.authenticated_data.clone(),
        encrypted_sender_data,
        ciphertext,
    })
}

/// Decrypt the sender data only (leaf index and generation).
pub fn decrypt_sender_data(cs: CipherSuite, pm: &PrivateMessage, sender_data_secret: &[u8]) -> Result<SenderData> {
    let (sk, sn) = sender_data_key_nonce(cs, sender_data_secret, &pm.ciphertext)?;
    let sd = cs.open(&sk, &sn, &sender_data_aad(&pm.group_id, pm.epoch, pm.content_type), &pm.encrypted_sender_data)?;
    Ok(SenderData::from_bytes(&sd)?)
}

/// Decrypt a PrivateMessage. The returned content still needs its signature checked.
pub fn decrypt_private(cs: CipherSuite, pm: &PrivateMessage, secrets: &mut SecretTree, sender_data_secret: &[u8]) -> Result<AuthenticatedContent> {
    let sd = decrypt_sender_data(cs, pm, sender_data_secret)?;
    let (key, mut nonce) = secrets.key_nonce(sd.leaf_index, ratchet_for(pm.content_type), sd.generation)?;
    for i in 0..4 {
        nonce[i] ^= sd.reuse_guard[i];
    }
    let aad = private_content_aad(&pm.group_id, pm.epoch, pm.content_type, &pm.authenticated_data);
    let pt = cs.open(&key, &nonce, &aad, &pm.ciphertext)?;
    let mut r = Reader::new(&pt);
    let content = Content::decode_body(pm.content_type, &mut r)?;
    let auth = FramedContentAuthData::decode(pm.content_type, &mut r)?;
    let padding = r.take(r.remaining())?;
    if padding.iter().any(|b| *b != 0) {
        return proto("non-zero padding");
    }
    Ok(AuthenticatedContent {
        wire_format: WireFormat::PrivateMessage,
        content: FramedContent {
            group_id: pm.group_id.clone(),
            epoch: pm.epoch,
            sender: Sender::Member(sd.leaf_index),
            authenticated_data: pm.authenticated_data.clone(),
            content,
        },
        auth,
    })
}
