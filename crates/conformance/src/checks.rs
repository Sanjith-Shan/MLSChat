use crate::*;
use mls::codec::{read_varint, Reader};
use mls::tree_math as tm;
use mls::messages::*;
use mls::Codec;
use crate::{groupchecks, schedule, treechecks};

pub type CheckFn = fn(&Value) -> Result<Outcome>;

pub static FILES: &[(&str, CheckFn)] = &[
    ("tree-math.json", tree_math),
    ("crypto-basics.json", crypto_basics),
    ("deserialization.json", deserialization),
    ("messages.json", messages),
    ("key-schedule.json", schedule::key_schedule),
    ("psk_secret.json", schedule::psk_secret),
    ("secret-tree.json", schedule::secret_tree),
    ("transcript-hashes.json", schedule::transcript_hashes),
    ("message-protection.json", schedule::message_protection),
    ("tree-validation.json", treechecks::tree_validation),
    ("tree-operations.json", treechecks::tree_operations),
    ("treekem.json", treechecks::treekem),
    ("welcome.json", groupchecks::welcome),
    ("passive-client-welcome.json", groupchecks::passive),
    ("passive-client-handling-commit.json", groupchecks::passive),
    ("passive-client-random.json", groupchecks::passive),
];

fn opt_u32_array(v: &Value, k: &str) -> Result<Vec<Option<u32>>> {
    v.get(k)
        .and_then(|x| x.as_array())
        .ok_or_else(|| anyhow!("missing {k}"))?
        .iter()
        .map(|x| Ok(x.as_u64().map(|n| n as u32)))
        .collect()
}

fn tree_math(v: &Value) -> Result<Outcome> {
    let n = num(v, "n_leaves")? as u32;
    ensure!(tm::node_width(n) == num(v, "n_nodes")? as u32, "n_nodes");
    ensure!(tm::root(n) == num(v, "root")? as u32, "root");
    let left = opt_u32_array(v, "left")?;
    let right = opt_u32_array(v, "right")?;
    let parent = opt_u32_array(v, "parent")?;
    let sibling = opt_u32_array(v, "sibling")?;
    for i in 0..tm::node_width(n) {
        let iu = i as usize;
        ensure!(tm::left(i) == left[iu], "left({i})");
        ensure!(tm::right(i) == right[iu], "right({i})");
        ensure!(tm::parent(i, n) == parent[iu], "parent({i})");
        ensure!(tm::sibling(i, n) == sibling[iu], "sibling({i})");
    }
    Ok(Outcome::Pass)
}

fn crypto_basics(v: &Value) -> Result<Outcome> {
    let cs = suite_or_skip!(v);

    let r = &v["ref_hash"];
    eqb("ref_hash", &cs.ref_hash(st(r, "label")?, &hx(r, "value")?), &hx(r, "out")?)?;

    let e = &v["expand_with_label"];
    let out = cs.expand_with_label(&hx(e, "secret")?, st(e, "label")?, &hx(e, "context")?, num(e, "length")? as usize)?;
    eqb("expand_with_label", &out, &hx(e, "out")?)?;

    let d = &v["derive_secret"];
    eqb("derive_secret", &cs.derive_secret(&hx(d, "secret")?, st(d, "label")?)?, &hx(d, "out")?)?;

    let t = &v["derive_tree_secret"];
    let out = cs.derive_tree_secret(&hx(t, "secret")?, st(t, "label")?, num(t, "generation")? as u32, num(t, "length")? as usize)?;
    eqb("derive_tree_secret", &out, &hx(t, "out")?)?;

    let s = &v["sign_with_label"];
    let (sk, pk, label, content) = (hx(s, "priv")?, hx(s, "pub")?, st(s, "label")?, hx(s, "content")?);
    cs.verify_with_label(&pk, label, &content, &hx(s, "signature")?).context("verify given signature")?;
    let sig = cs.sign_with_label(&sk, label, &content)?;
    cs.verify_with_label(&pk, label, &content, &sig).context("verify own signature")?;
    eqb("signature public key", &cs.signature_public(&sk)?, &pk)?;

    let x = &v["encrypt_with_label"];
    let (sk, pk, label, ctx, pt) = (hx(x, "priv")?, hx(x, "pub")?, st(x, "label")?, hx(x, "context")?, hx(x, "plaintext")?);
    let got = cs.decrypt_with_label(&sk, label, &ctx, &hx(x, "kem_output")?, &hx(x, "ciphertext")?)?;
    eqb("decrypt_with_label", &got, &pt)?;
    let (kem, ct) = cs.encrypt_with_label(&pk, label, &ctx, &pt)?;
    eqb("decrypt own ciphertext", &cs.decrypt_with_label(&sk, label, &ctx, &kem, &ct)?, &pt)?;
    Ok(Outcome::Pass)
}

fn deserialization(v: &Value) -> Result<Outcome> {
    let h = hx(v, "vlbytes_header")?;
    let mut r = Reader::new(&h);
    let len = read_varint(&mut r)?;
    ensure!(r.is_empty(), "header has trailing bytes");
    ensure!(len as u64 == num(v, "length")?, "length {len}");
    Ok(Outcome::Pass)
}

fn roundtrip<T: Codec>(v: &Value, k: &str) -> Result<T> {
    let b = hx(v, k)?;
    let x = T::from_bytes(&b).with_context(|| format!("decoding {k}"))?;
    eqb(k, &x.to_bytes(), &b)?;
    Ok(x)
}

fn messages(v: &Value) -> Result<Outcome> {
    let want = [
        ("mls_welcome", WireFormat::Welcome),
        ("mls_group_info", WireFormat::GroupInfo),
        ("mls_key_package", WireFormat::KeyPackage),
        ("public_message_application", WireFormat::PublicMessage),
        ("public_message_proposal", WireFormat::PublicMessage),
        ("public_message_commit", WireFormat::PublicMessage),
        ("private_message", WireFormat::PrivateMessage),
    ];
    for (k, wf) in want {
        let m: MlsMessage = roundtrip(v, k)?;
        ensure!(m.wire_format() == wf, "{k}: wrong wire format");
    }
    let ct = |k: &str, t: ContentType| -> Result<()> {
        match MlsMessage::from_bytes(&hx(v, k)?)? {
            MlsMessage::Public(p) => ensure!(p.content.content.content_type() == t, "{k}: wrong content type"),
            _ => bail!("{k}: not public"),
        }
        Ok(())
    };
    ct("public_message_application", ContentType::Application)?;
    ct("public_message_proposal", ContentType::Proposal)?;
    ct("public_message_commit", ContentType::Commit)?;
    roundtrip::<RatchetTreeNodes>(v, "ratchet_tree")?;
    roundtrip::<GroupSecrets>(v, "group_secrets")?;
    roundtrip::<KeyPackage>(v, "add_proposal")?;
    roundtrip::<LeafNode>(v, "update_proposal")?;
    roundtrip::<u32>(v, "remove_proposal")?;
    roundtrip::<PreSharedKeyId>(v, "pre_shared_key_proposal")?;
    roundtrip::<ReInit>(v, "re_init_proposal")?;
    roundtrip::<Vec<u8>>(v, "external_init_proposal")?;
    roundtrip::<Vec<Extension>>(v, "group_context_extensions_proposal")?;
    roundtrip::<Commit>(v, "commit")?;
    Ok(Outcome::Pass)
}
