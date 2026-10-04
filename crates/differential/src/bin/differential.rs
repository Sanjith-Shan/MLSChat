//! Run K randomized MLSChat/OpenMLS sessions per suite and record agreement.
//!
//! Usage: differential [sessions_per_suite] [ops_per_session] [--record]

use differential::*;
use mls::CipherSuite;
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let nums: Vec<u64> = args.iter().skip(1).filter_map(|a| a.parse().ok()).collect();
    let k = *nums.first().unwrap_or(&100);
    let ops = *nums.get(1).unwrap_or(&40) as usize;
    let record = args.iter().any(|a| a == "--record");
    let mut total = 0;
    let mut agreed = 0;
    let mut epochs = 0;
    let (mut ours, mut theirs, mut msgs) = (0, 0, 0);
    for s in OPENMLS_SUITES {
        let mut suite_ok = 0;
        for seed in 0..k {
            let r = run_session(seed, CipherSuite(s), ops);
            total += 1;
            epochs += r.epochs;
            ours += r.commits_by_ours;
            theirs += r.commits_by_theirs;
            msgs += r.messages;
            if r.agreed {
                agreed += 1;
                suite_ok += 1;
            } else {
                println!("suite {s} seed {seed}: DISAGREE: {}", r.error.clone().unwrap_or_default());
            }
        }
        println!("suite {s}: {suite_ok}/{k} sessions agreed");
    }
    println!("TOTAL: {agreed}/{total} randomized sessions agreed; {epochs} epochs, {ours} commits by MLSChat, {theirs} by OpenMLS, {msgs} application messages");
    if record {
        harness::record("exp5_conformance.jsonl", "exp5_openmls_differential", json!({
            "sessions": total, "sessions_agreed": agreed, "ops_per_session": ops, "suites": OPENMLS_SUITES,
            "epochs_checked": epochs, "commits_by_mlschat": ours, "commits_by_openmls": theirs, "application_messages": msgs,
            "openmls_version": "0.9.0",
            "check": "after every commit all members hold the same epoch, epoch_authenticator and exporter secret; every application message decrypts to the sent plaintext"
        }));
    }
    if agreed != total {
        std::process::exit(1);
    }
}
