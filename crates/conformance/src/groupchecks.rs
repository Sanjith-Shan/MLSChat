//! welcome, passive-client-welcome, passive-client-handling-commit, passive-client-random.

use crate::*;
use mls::group::{Group, GroupConfig, KeyPackageBundle, PskStore, Signer};
use mls::key_schedule as ks;
use mls::messages::*;
use mls::tree::RatchetTree;
use mls::Codec;

fn key_package(b: &[u8]) -> Result<KeyPackage> {
    match MlsMessage::from_bytes(b) {
        Ok(MlsMessage::KeyPackage(kp)) => Ok(kp),
        _ => Ok(KeyPackage::from_bytes(b)?),
    }
}

fn welcome_msg(b: &[u8]) -> Result<Welcome> {
    match MlsMessage::from_bytes(b)? {
        MlsMessage::Welcome(w) => Ok(w),
        _ => bail!("not a Welcome"),
    }
}

pub(crate) fn welcome(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);
    let kp = key_package(&hx(v, "key_package")?)?;
    let w = welcome_msg(&hx(v, "welcome")?)?;
    let init_priv = hx(v, "init_priv")?;
    let r = kp.reference();
    let egs = w.secrets.iter().find(|s| s.new_member == r).ok_or_else(|| anyhow!("no entry for key package"))?;
    let gs = GroupSecrets::from_bytes(&cs.decrypt_with_label(
        &init_priv,
        "Welcome",
        &w.encrypted_group_info,
        &egs.encrypted_group_secrets.kem_output,
        &egs.encrypted_group_secrets.ciphertext,
    )?)?;
    let zero = vec![0u8; cs.nh()];
    let member = cs.extract(&gs.joiner_secret, &zero);
    let (wk, wn) = ks::welcome_key_nonce(cs, &cs.derive_secret(&member, "welcome")?)?;
    let gi = GroupInfo::from_bytes(&cs.open(&wk, &wn, &[], &w.encrypted_group_info)?)?;
    cs.verify_with_label(&hx(v, "signer_pub")?, "GroupInfoTBS", &gi.tbs(), &gi.signature).context("GroupInfo signature")?;
    let s = ks::from_joiner(cs, &gs.joiner_secret, None, &gi.group_context.to_bytes())?;
    let tag = cs.mac(&s.confirmation_key, &gi.group_context.confirmed_transcript_hash);
    eqb("confirmation_tag", &tag, &gi.confirmation_tag)?;
    Ok(Outcome::Pass)
}

pub(crate) fn passive(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);
    let kp = key_package(&hx(v, "key_package")?)?;
    let sig_priv = hx(v, "signature_priv")?;
    let enc_priv = hx(v, "encryption_priv")?;
    let init_priv = hx(v, "init_priv")?;
    eqb("signature key", &cs.signature_public(&sig_priv)?, &kp.leaf_node.signature_key)?;
    eqb("encryption key", &cs.hpke_public(&enc_priv)?, &kp.leaf_node.encryption_key)?;
    eqb("init key", &cs.hpke_public(&init_priv)?, &kp.init_key)?;

    let mut psks = PskStore::default();
    for p in v["external_psks"].as_array().unwrap() {
        psks.external.insert(hx(p, "psk_id")?, hx(p, "psk")?);
    }
    let signer = Signer { signature_priv: sig_priv, signature_pub: kp.leaf_node.signature_key.clone(), credential: kp.leaf_node.credential.clone() };
    let kpb = KeyPackageBundle { key_package: kp, init_priv, encryption_priv: enc_priv, signer };
    let tree = match hx_opt(v, "ratchet_tree")? {
        Some(b) => Some(RatchetTree::from_bytes(cs, &b)?),
        None => None,
    };
    let w = welcome_msg(&hx(v, "welcome")?)?;
    let config = GroupConfig { max_past_epochs: 0, ..Default::default() };
    let mut g = Group::join(&w, &kpb, tree, psks, config).context("join")?;
    eqb("initial_epoch_authenticator", g.epoch_authenticator(), &hx(v, "initial_epoch_authenticator")?)?;

    for (i, e) in v["epochs"].as_array().unwrap().iter().enumerate() {
        for p in e["proposals"].as_array().unwrap() {
            let m = MlsMessage::from_bytes(&hex::decode(p.as_str().unwrap())?)?;
            g.process(&m).with_context(|| format!("epoch {i}: proposal"))?;
        }
        let m = MlsMessage::from_bytes(&hx(e, "commit")?)?;
        g.process(&m).with_context(|| format!("epoch {i}: commit"))?;
        eqb(&format!("epoch {i} authenticator"), g.epoch_authenticator(), &hx(e, "epoch_authenticator")?)?;
    }
    Ok(Outcome::Pass)
}
