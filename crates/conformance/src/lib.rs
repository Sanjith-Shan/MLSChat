//! Test-vector runner. Each `check_*` function verifies one test case exactly
//! as `test-vectors.md` in `mlswg/mls-implementations` describes it.

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

mod checks;
mod schedule;
mod treechecks;
mod groupchecks;

pub use checks::FILES;

/// Outcome of running one vector file.
#[derive(Debug, Clone)]
pub struct FileReport {
    pub file: String,
    pub total: usize,
    pub passed: usize,
    /// (case index, reason) for cases not run, e.g. an unimplemented cipher suite.
    pub skipped: Vec<(usize, String)>,
    /// (case index, error) for cases that ran and failed.
    pub failed: Vec<(usize, String)>,
}

impl FileReport {
    pub fn all_applicable_pass(&self) -> bool {
        self.failed.is_empty() && self.passed + self.skipped.len() == self.total
    }
}

pub enum Outcome {
    Pass,
    Skip(String),
}

pub fn vectors_dir() -> PathBuf {
    if let Ok(d) = std::env::var("MLS_VECTORS") {
        return PathBuf::from(d);
    }
    let work = std::env::var("MLS_WORK")
        .unwrap_or_else(|_| format!("{}/mlschat-work", std::env::var("HOME").unwrap_or_default()));
    PathBuf::from(work).join("mls-implementations/test-vectors")
}

pub fn run_file(dir: &Path, file: &str, check: fn(&Value) -> Result<Outcome>) -> Result<FileReport> {
    let path = dir.join(file);
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let v: Value = serde_json::from_str(&text)?;
    let cases = v.as_array().ok_or_else(|| anyhow!("{file}: not an array"))?;
    let mut rep = FileReport { file: file.to_string(), total: cases.len(), passed: 0, skipped: vec![], failed: vec![] };
    for (i, c) in cases.iter().enumerate() {
        let r = std::panic::catch_unwind(|| check(c));
        match r {
            Ok(Ok(Outcome::Pass)) => rep.passed += 1,
            Ok(Ok(Outcome::Skip(why))) => rep.skipped.push((i, why)),
            Ok(Err(e)) => rep.failed.push((i, format!("{e:#}"))),
            Err(_) => rep.failed.push((i, "panicked".into())),
        }
    }
    Ok(rep)
}

pub fn run_all(dir: &Path) -> Result<Vec<FileReport>> {
    FILES.iter().map(|(f, c)| run_file(dir, f, *c)).collect()
}

// ---- JSON helpers ----

pub(crate) fn hx(v: &Value, k: &str) -> Result<Vec<u8>> {
    let s = v.get(k).and_then(|x| x.as_str()).ok_or_else(|| anyhow!("missing hex field {k}"))?;
    Ok(hex::decode(s)?)
}

pub(crate) fn hx_opt(v: &Value, k: &str) -> Result<Option<Vec<u8>>> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(hex::decode(s)?)),
        _ => bail!("bad field {k}"),
    }
}

pub(crate) fn num(v: &Value, k: &str) -> Result<u64> {
    v.get(k).and_then(|x| x.as_u64()).ok_or_else(|| anyhow!("missing number {k}"))
}

pub(crate) fn st<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| anyhow!("missing string {k}"))
}

pub(crate) fn eqb(what: &str, got: &[u8], want: &[u8]) -> Result<()> {
    ensure!(got == want, "{what} mismatch: got {} want {}", hex::encode(got), hex::encode(want));
    Ok(())
}

pub(crate) fn suite(v: &Value) -> Result<std::result::Result<mls::CipherSuite, Outcome>> {
    let cs = mls::CipherSuite(num(v, "cipher_suite")? as u16);
    if !cs.is_supported() {
        return Ok(Err(Outcome::Skip(format!("cipher suite {} not implemented", cs.0))));
    }
    Ok(Ok(cs))
}

/// Early-return a skip for unsupported suites.
#[macro_export]
macro_rules! suite_or_skip {
    ($v:expr) => {
        match $crate::suite($v)? {
            Ok(cs) => cs,
            Err(skip) => return Ok(skip),
        }
    };
}
