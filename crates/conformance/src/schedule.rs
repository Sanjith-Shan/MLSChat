//! key-schedule, psk_secret, secret-tree, transcript-hashes, message-protection.

use crate::*;
use mls::messages::*;
use mls::Codec;

pub(crate) fn ctx(cs: mls::CipherSuite, gid: Vec<u8>, epoch: u64, th: Vec<u8>, cth: Vec<u8>) -> GroupContext {
    GroupContext { version: MLS10, cipher_suite: cs, group_id: gid, epoch, tree_hash: th, confirmed_transcript_hash: cth, extensions: vec![] }
}

pub(crate) fn key_schedule(v: &Value) -> Result<Outcome> {
    use mls::key_schedule as ks;
    let cs = suite_or_skip!(v);
    let gid = hx(v, "group_id")?;
    let mut init = hx(v, "initial_init_secret")?;
    for (i, e) in v["epochs"].as_array().unwrap().iter().enumerate() {
        let gc = ctx(cs, gid.clone(), i as u64, hx(e, "tree_hash")?, hx(e, "confirmed_transcript_hash")?);
        let gcb = gc.to_bytes();
        eqb("group_context", &gcb, &hx(e, "group_context")?)?;
        let s = ks::derive(cs, &init, Some(&hx(e, "commit_secret")?), Some(&hx(e, "psk_secret")?), &gcb)?;
        for (k, got) in [
            ("joiner_secret", &s.joiner_secret),
            ("welcome_secret", &s.welcome_secret),
            ("init_secret", &s.init_secret),
            ("sender_data_secret", &s.sender_data_secret),
            ("encryption_secret", &s.encryption_secret),
            ("exporter_secret", &s.exporter_secret),
            ("epoch_authenticator", &s.epoch_authenticator),
            ("external_secret", &s.external_secret),
            ("confirmation_key", &s.confirmation_key),
            ("membership_key", &s.membership_key),
            ("resumption_psk", &s.resumption_psk),
        ] {
            eqb(k, got, &hx(e, k)?)?;
        }
        eqb("external_pub", &s.external_pub(cs)?.1, &hx(e, "external_pub")?)?;
        let x = &e["exporter"];
        let out = s.export(cs, st(x, "label")?, &hx(x, "context")?, num(x, "length")? as usize)?;
        eqb("exporter", &out, &hx(x, "secret")?)?;
        init = s.init_secret.clone();
    }
    Ok(Outcome::Pass)
}

pub(crate) fn psk_secret(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);
    let mut psks = Vec::new();
    for p in v["psks"].as_array().unwrap() {
        let id = PreSharedKeyId { psk: Psk::External { psk_id: hx(p, "psk_id")? }, psk_nonce: hx(p, "psk_nonce")? };
        psks.push((id, hx(p, "psk")?));
    }
    let got = mls::key_schedule::psk_secret(cs, &psks)?.unwrap_or_else(|| vec![0u8; cs.nh()]);
    eqb("psk_secret", &got, &hx(v, "psk_secret")?)?;
    Ok(Outcome::Pass)
}

pub(crate) fn secret_tree(v: &Value) -> Result<Outcome> {
    use mls::secret_tree::*;
    let cs = suite_or_skip!(v);
    let sd = &v["sender_data"];
    let (k, n) = sender_data_key_nonce(cs, &hx(sd, "sender_data_secret")?, &hx(sd, "ciphertext")?)?;
    eqb("sender_data key", &k, &hx(sd, "key")?)?;
    eqb("sender_data nonce", &n, &hx(sd, "nonce")?)?;
    let leaves = v["leaves"].as_array().unwrap();
    let mut t = SecretTree::new(cs, &hx(v, "encryption_secret")?, leaves.len() as u32);
    for (i, gens) in leaves.iter().enumerate() {
        for g in gens.as_array().unwrap() {
            let gen = num(g, "generation")? as u32;
            let (hk, hn) = t.key_nonce(i as u32, RatchetType::Handshake, gen)?;
            let (ak, an) = t.key_nonce(i as u32, RatchetType::Application, gen)?;
            eqb("handshake_key", &hk, &hx(g, "handshake_key")?)?;
            eqb("handshake_nonce", &hn, &hx(g, "handshake_nonce")?)?;
            eqb("application_key", &ak, &hx(g, "application_key")?)?;
            eqb("application_nonce", &an, &hx(g, "application_nonce")?)?;
        }
    }
    Ok(Outcome::Pass)
}

pub(crate) fn transcript_hashes(v: &Value) -> Result<Outcome> {
    use mls::key_schedule::*;
    let cs = suite_or_skip!(v);
    let ac = AuthenticatedContent::from_bytes(&hx(v, "authenticated_content")?)?;
    ensure!(matches!(ac.content.content, Content::Commit(_)), "not a commit");
    let confirmed = confirmed_transcript_hash(cs, &hx(v, "interim_transcript_hash_before")?, &ac);
    eqb("confirmed_transcript_hash_after", &confirmed, &hx(v, "confirmed_transcript_hash_after")?)?;
    let tag = ac.auth.confirmation_tag.clone().unwrap();
    ensure!(cs.verify_mac(&hx(v, "confirmation_key")?, &confirmed, &tag), "confirmation tag");
    let interim = interim_transcript_hash(cs, &confirmed, &tag);
    eqb("interim_transcript_hash_after", &interim, &hx(v, "interim_transcript_hash_after")?)?;
    Ok(Outcome::Pass)
}

pub(crate) fn message_protection(v: &Value) -> Result<Outcome> {
    use mls::framing::*;
    use mls::secret_tree::SecretTree;
    let cs = suite_or_skip!(v);
    let gc = ctx(cs, hx(v, "group_id")?, num(v, "epoch")?, hx(v, "tree_hash")?, hx(v, "confirmed_transcript_hash")?);
    let (sig_priv, sig_pub) = (hx(v, "signature_priv")?, hx(v, "signature_pub")?);
    let enc = hx(v, "encryption_secret")?;
    let sds = hx(v, "sender_data_secret")?;
    let mk = hx(v, "membership_key")?;

    let cases: [(&str, Content); 3] = [
        ("proposal", Content::Proposal(Proposal::from_bytes(&hx(v, "proposal")?)?)),
        ("commit", Content::Commit(Commit::from_bytes(&hx(v, "commit")?)?)),
        ("application", Content::Application(hx(v, "application")?)),
    ];
    for (name, content) in cases {
        let framed = FramedContent {
            group_id: gc.group_id.clone(),
            epoch: gc.epoch,
            sender: Sender::Member(1),
            authenticated_data: vec![],
            content: content.clone(),
        };
        let tag = if name == "commit" { Some(cs.mac(&mk, b"confirmation")) } else { None };

        // PublicMessage
        if name != "application" {
            let m = MlsMessage::from_bytes(&hx(v, &format!("{name}_pub"))?)?;
            let MlsMessage::Public(pm) = m else { bail!("{name}_pub not public") };
            let ac = from_public(cs, &pm, Some(&gc), Some(&mk))?;
            verify_content_signature(cs, &ac, Some(&gc), &sig_pub)?;
            ensure!(ac.content.content == content, "{name}_pub content");
            let ac = sign_content(cs, &sig_priv, WireFormat::PublicMessage, framed.clone(), Some(&gc), tag.clone())?;
            let pm = to_public(cs, ac, Some(&gc), Some(&mk))?;
            let pm = PublicMessage::from_bytes(&pm.to_bytes())?;
            let ac = from_public(cs, &pm, Some(&gc), Some(&mk))?;
            verify_content_signature(cs, &ac, Some(&gc), &sig_pub)?;
        } else {
            let ac = sign_content(cs, &sig_priv, WireFormat::PublicMessage, framed.clone(), Some(&gc), None)?;
            ensure!(to_public(cs, ac, Some(&gc), Some(&mk)).is_err(), "application as PublicMessage must fail");
        }

        // PrivateMessage
        let m = MlsMessage::from_bytes(&hx(v, &format!("{name}_priv"))?)?;
        let MlsMessage::Private(pm) = m else { bail!("{name}_priv not private") };
        let mut tree = SecretTree::new(cs, &enc, 2);
        let ac = decrypt_private(cs, &pm, &mut tree, &sds)?;
        verify_content_signature(cs, &ac, Some(&gc), &sig_pub)?;
        ensure!(ac.content.content == content, "{name}_priv content");

        let mut tree = SecretTree::new(cs, &enc, 2);
        let ac = sign_content(cs, &sig_priv, WireFormat::PrivateMessage, framed, Some(&gc), tag)?;
        let pm = encrypt_private(cs, &ac, &mut tree, &sds, 7)?;
        let mut tree = SecretTree::new(cs, &enc, 2);
        let ac2 = decrypt_private(cs, &pm, &mut tree, &sds)?;
        verify_content_signature(cs, &ac2, Some(&gc), &sig_pub)?;
        ensure!(ac2 == ac, "{name} private roundtrip");
    }
    Ok(Outcome::Pass)
}
