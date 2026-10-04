//! Prints vector pass counts per file, exactly as run.
use conformance::*;

fn main() -> anyhow::Result<()> {
    let dir = vectors_dir();
    println!("vectors: {}", dir.display());
    let mut ok = true;
    for (file, check) in FILES {
        let r = run_file(&dir, file, *check)?;
        println!(
            "{:<38} {:>4}/{:<4} passed  {:>3} skipped  {:>3} failed",
            r.file, r.passed, r.total, r.skipped.len(), r.failed.len()
        );
        let mut reasons: Vec<&String> = r.skipped.iter().map(|(_, w)| w).collect();
        reasons.sort();
        reasons.dedup();
        for w in reasons {
            let n = r.skipped.iter().filter(|(_, x)| x == w).count();
            println!("    skipped {n}: {w}");
        }
        for (i, e) in r.failed.iter().take(5) {
            println!("    FAIL case {i}: {e}");
        }
        ok &= r.failed.is_empty();
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
