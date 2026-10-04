//! Every line written to `results/*.jsonl` carries the machine it ran on and
//! the load at the time, so a number can always be traced to its conditions.

use serde_json::{json, Map, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HOST_DESCRIPTION: &str =
    "shared mini PC (Acemagic K1, Windows 11) running a 2-vCPU WSL2 Ubuntu 24.04 VM; other projects' sessions may share the box";

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

pub fn loadavg() -> [f64; 3] {
    let s = read("/proc/loadavg");
    let mut it = s.split_whitespace().map(|x| x.parse::<f64>().unwrap_or(-1.0));
    [it.next().unwrap_or(-1.0), it.next().unwrap_or(-1.0), it.next().unwrap_or(-1.0)]
}

fn meminfo_kb(key: &str) -> u64 {
    read("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn cpu_model() -> String {
    read("/proc/cpuinfo")
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn unix_time() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Machine and load fields attached to every result line.
pub fn machine() -> Value {
    let la = loadavg();
    json!({
        "host": HOST_DESCRIPTION,
        "cpu_model": cpu_model(),
        "vcpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "mem_total_mb": meminfo_kb("MemTotal:") / 1024,
        "mem_available_mb": meminfo_kb("MemAvailable:") / 1024,
        "kernel": read("/proc/sys/kernel/osrelease").trim(),
        "loadavg_1m": la[0],
        "loadavg_5m": la[1],
        "loadavg_15m": la[2],
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "git_commit": git_commit(),
        "unix_time": unix_time(),
    })
}

pub fn results_dir() -> PathBuf {
    let d = std::env::var("MLSCHAT_RESULTS").map(PathBuf::from).unwrap_or_else(|_| {
        // Walk up from the current dir to the workspace root.
        let mut p = std::env::current_dir().unwrap();
        while !p.join("Cargo.lock").exists() && p.pop() {}
        p.join("results")
    });
    std::fs::create_dir_all(&d).ok();
    d
}

/// Append one JSON object, merged with machine metadata, to `results/<file>`.
pub fn record(file: &str, experiment: &str, fields: Value) -> Value {
    let mut m = Map::new();
    m.insert("experiment".into(), json!(experiment));
    if let Value::Object(f) = fields {
        m.extend(f);
    }
    if let Value::Object(mach) = machine() {
        m.extend(mach);
    }
    let v = Value::Object(m);
    let path = results_dir().join(file);
    append(&path, &v);
    v
}

pub fn append(path: &Path, v: &Value) {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).expect("open results file");
    writeln!(f, "{}", serde_json::to_string(v).unwrap()).unwrap();
}

/// Percentile (0..=100) of a sorted slice.
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

pub fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    percentile(v, 50.0)
}
