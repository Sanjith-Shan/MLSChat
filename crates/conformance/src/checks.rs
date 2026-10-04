use crate::*;
use mls::codec::{read_varint, Reader};
use mls::tree_math as tm;

pub type CheckFn = fn(&Value) -> Result<Outcome>;

pub static FILES: &[(&str, CheckFn)] = &[
    ("tree-math.json", tree_math),
    ("crypto-basics.json", crypto_basics),
    ("deserialization.json", deserialization),
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
