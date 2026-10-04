//! Prints vector pass counts per file, exactly as run.
//! With `--record`, appends one line per file plus a summary to results/exp5_conformance.jsonl.
use conformance::*;
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let record = std::env::args().any(|a| a == "--record");
    let dir = vectors_dir();
    let pin = std::process::Command::new("git")
        .args(["-C", &dir.join("..").to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!("vectors: {} (mls-implementations {})", dir.display(), pin);
    let (mut ok, mut files_all_pass) = (true, 0);
    let (mut total, mut passed, mut skipped, mut failed) = (0, 0, 0, 0);
    for (file, check) in FILES {
        let t = std::time::Instant::now();
        let r = run_file(&dir, file, *check)?;
        let secs = t.elapsed().as_secs_f64();
        println!(
            "{:<38} {:>4}/{:<4} passed  {:>3} skipped  {:>3} failed",
            r.file, r.passed, r.total, r.skipped.len(), r.failed.len()
        );
        let mut reasons: Vec<&String> = r.skipped.iter().map(|(_, w)| w).collect();
        reasons.sort();
        reasons.dedup();
        for w in &reasons {
            let n = r.skipped.iter().filter(|(_, x)| x == *w).count();
            println!("    skipped {n}: {w}");
        }
        for (i, e) in r.failed.iter().take(5) {
            println!("    FAIL case {i}: {e}");
        }
        ok &= r.failed.is_empty();
        if r.failed.is_empty() && r.skipped.is_empty() {
            files_all_pass += 1;
        }
        total += r.total;
        passed += r.passed;
        skipped += r.skipped.len();
        failed += r.failed.len();
        if record {
            harness::record(
                "exp5_conformance.jsonl",
                "exp5_vectors_file",
                json!({"file": r.file, "cases": r.total, "passed": r.passed, "skipped": r.skipped.len(),
                       "skip_reasons": reasons, "failed": r.failed.len(), "seconds": secs, "vectors_commit": pin}),
            );
        }
    }
    println!("TOTAL: {passed}/{total} cases passed, {skipped} skipped, {failed} failed; {files_all_pass}/{} files pass every case", FILES.len());
    if record {
        harness::record(
            "exp5_conformance.jsonl",
            "exp5_vectors_summary",
            json!({"files": FILES.len(), "files_all_cases_pass": files_all_pass, "cases": total, "passed": passed,
                   "skipped": skipped, "failed": failed, "suites": mls::crypto::SUPPORTED_SUITES, "vectors_commit": pin}),
        );
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
