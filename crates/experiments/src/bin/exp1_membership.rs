//! exp1: time and bytes to add or remove one member, groups of 2 to 10,000.
//! MLS (TreeKEM) against Sender Keys and pairwise, all on suite-1 primitives.
//!
//! Usage: exp1_membership [max_n] [reps]

use baselines::*;
use experiments::*;
use mls::group::{create_key_package, CommitOptions, Group, PskStore, Signer};
use mls::messages::{MlsMessage, Proposal};
use mls::{Codec, CipherSuite};
use serde_json::json;
use std::time::Instant;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn random_session() -> Session {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut a);
    rand_core::OsRng.fill_bytes(&mut b);
    Session { send: Chain::new(a), recv: Chain::new(b) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let max_n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10000);
    let reps_arg: Option<usize> = args.get(2).and_then(|s| s.parse().ok());
    let cs = CipherSuite(1);
    let file = "exp1_membership.jsonl";

    for &n in SIZES.iter().filter(|n| **n <= max_n) {
        let reps = reps_arg.unwrap_or(if n >= 5000 { 7 } else { 21 });
        // ---------------- MLS ----------------
        let measured_leaf = if n >= 3 { 2 } else { 1 };
        let bg = build(cs, n, &[measured_leaf]);
        let (filled, parents) = bg.parent_fill();
        eprintln!("n={n}: built in {:.1}s with {} fill commits, parents filled {filled}/{parents}", bg.build_seconds, bg.fill_commits);
        let mut creator = bg.creator.clone();
        let receiver = bg.measured[0].clone();
        let target = (n - 1) as u32;

        // Remove one member (commit with path, which RFC 9420 requires for Remove).
        let (mut c_ms, mut r_ms) = (vec![], vec![]);
        let mut commit_bytes = 0;
        let mut path_bytes = 0;
        for _ in 0..reps {
            let t = Instant::now();
            let out = creator.commit(vec![Proposal::Remove(target)], CommitOptions::default()).unwrap();
            c_ms.push(ms(t));
            commit_bytes = out.commit.to_bytes().len();
            path_bytes = out.path_bytes;
            creator.clear_pending_commit();
            if target != measured_leaf {
                let mut rc = receiver.clone();
                let t = Instant::now();
                rc.process(&out.commit).unwrap();
                r_ms.push(ms(t));
            }
        }
        harness::record(file, "exp1_membership", json!({
            "scheme": "mls", "op": "remove", "n": n, "suite": cs.0, "reps": reps,
            "committer_ms_median": median(&mut c_ms), "receiver_ms_median": if r_ms.is_empty() { f64::NAN } else { median(&mut r_ms) },
            "commit_bytes": commit_bytes, "update_path_bytes": path_bytes,
            "bytes_sent_total": commit_bytes,
            "tree_parents_filled": filled, "tree_parents_with_members": parents, "setup_fill_commits": bg.fill_commits,
            "note": "one commit carrying Remove plus an UpdatePath; server fans it out to n-1 members"
        }));

        // Add one member: without a path (the minimum RFC 9420 allows) and with one.
        for force_path in [false, true] {
            let (mut c_ms, mut r_ms, mut j_ms) = (vec![], vec![], vec![]);
            let (mut commit_bytes, mut welcome_bytes, mut welcome_no_tree) = (0, 0, 0);
            for rep in 0..reps {
                let kpb = create_key_package(cs, &Signer::generate(cs, b"newcomer")).unwrap();
                let t = Instant::now();
                let out = creator.commit(vec![Proposal::Add(kpb.key_package.clone())], CommitOptions { force_path, ..Default::default() }).unwrap();
                c_ms.push(ms(t));
                commit_bytes = out.commit.to_bytes().len();
                let w = out.welcome.clone().unwrap();
                welcome_bytes = w.to_bytes().len();
                let MlsMessage::Welcome(wel) = &w else { unreachable!() };
                creator.clear_pending_commit();
                if rep == 0 {
                    // The same Welcome without the ratchet tree, which a joiner can fetch from the server instead.
                    let mut nt = creator.clone();
                    nt.config.ratchet_tree_extension = false;
                    let o2 = nt.commit(vec![Proposal::Add(kpb.key_package.clone())], CommitOptions { force_path, ..Default::default() }).unwrap();
                    welcome_no_tree = o2.welcome.unwrap().to_bytes().len();
                }
                let mut rc = receiver.clone();
                let t = Instant::now();
                rc.process(&out.commit).unwrap();
                r_ms.push(ms(t));
                if rep < 3 || n <= 1000 {
                    let t = Instant::now();
                    Group::join(wel, &kpb, None, PskStore::default(), config()).unwrap();
                    j_ms.push(ms(t));
                }
            }
            harness::record(file, "exp1_membership", json!({
                "scheme": "mls", "op": if force_path { "add_with_path" } else { "add" }, "n": n, "suite": cs.0, "reps": reps,
                "committer_ms_median": median(&mut c_ms), "receiver_ms_median": median(&mut r_ms), "joiner_ms_median": median(&mut j_ms),
                "commit_bytes": commit_bytes, "welcome_bytes": welcome_bytes, "welcome_bytes_without_tree": welcome_no_tree,
                "bytes_sent_total": commit_bytes + welcome_bytes,
                "note": "commit fanned out to existing members, Welcome (with the ratchet tree) to the newcomer"
            }));
        }
        drop(bg);

        // ---------------- Sender Keys ----------------
        // Remove: every one of the n-2 remaining members other than... all n-1 remaining
        // members rotate their sender key and send it over pairwise sessions to the other n-2.
        let remaining = n - 1;
        let peers = remaining.saturating_sub(1);
        let mut per_member = vec![];
        for _ in 0..reps.min(9) {
            let mut sessions: Vec<Session> = (0..peers).map(|_| random_session()).collect();
            let t = Instant::now();
            let sk = SenderKey::generate();
            let d = sk.distribution().to_bytes();
            let mut bytes = 0usize;
            for s in sessions.iter_mut() {
                bytes += s.encrypt(&d).len();
            }
            per_member.push(ms(t));
            std::hint::black_box(bytes);
        }
        let per_member_ms = median(&mut per_member);
        let per_msg = DISTRIBUTION_BYTES + PAIRWISE_OVERHEAD;
        // Check the multiplication against a full run where every member does it, for small groups.
        let mut full_ms = None;
        if n <= 500 && remaining >= 1 {
            let mut all: Vec<Vec<Session>> = (0..remaining).map(|_| (0..peers).map(|_| random_session()).collect()).collect();
            let t = Instant::now();
            for sessions in all.iter_mut() {
                let d = SenderKey::generate().distribution().to_bytes();
                for s in sessions.iter_mut() {
                    std::hint::black_box(s.encrypt(&d));
                }
            }
            full_ms = Some(ms(t));
        }
        harness::record(file, "exp1_membership", json!({
            "scheme": "sender_keys", "op": "remove", "n": n, "reps": reps.min(9),
            "per_member_ms_median": per_member_ms, "members_rekeying": remaining,
            "aggregate_ms": per_member_ms * remaining as f64,
            "aggregate_method": "measured per-member rotation (new chain + pairwise encryption to every other remaining member) times the number of remaining members",
            "aggregate_ms_full_run": full_ms,
            "bytes_sent_per_member": peers * per_msg,
            "bytes_sent_total": remaining * peers * per_msg,
            "pairwise_messages_total": remaining * peers,
            "note": "every remaining sender must re-key so the removed member cannot read new messages"
        }));

        // Add: newcomer opens sessions with everyone and sends its sender key; everyone sends theirs back.
        let existing = n - 1;
        let mut newcomer_ms = vec![];
        let mut members_ms = vec![];
        for _ in 0..reps.min(5) {
            let ids: Vec<Identity> = (0..existing.min(2000)).map(|_| Identity::generate()).collect();
            let bundles: Vec<PublicBundle> = ids.iter().map(|i| i.bundle()).collect();
            let me = Identity::generate();
            let t = Instant::now();
            let mut sessions = Vec::with_capacity(existing);
            let mut ek = None;
            for i in 0..existing {
                let (s, e) = initiate(&me, &bundles[i % bundles.len()]);
                sessions.push(s);
                ek = Some(e);
            }
            let d = SenderKey::generate().distribution().to_bytes();
            for s in sessions.iter_mut() {
                std::hint::black_box(s.encrypt(&d));
            }
            newcomer_ms.push(ms(t));
            // Each existing member: respond to the handshake and send its key to the newcomer.
            let ek = ek.unwrap_or_else(|| x25519_dalek::PublicKey::from(&me.spk));
            let me_ik = x25519_dalek::PublicKey::from(&me.ik);
            let t = Instant::now();
            for i in 0..existing.min(2000) {
                let mut s = respond(&ids[i], &me_ik, &ek);
                std::hint::black_box(s.encrypt(&d));
            }
            let measured = existing.min(2000).max(1);
            members_ms.push(ms(t) / measured as f64);
        }
        let per_existing = median(&mut members_ms);
        harness::record(file, "exp1_membership", json!({
            "scheme": "sender_keys", "op": "add", "n": n,
            "newcomer_ms_median": median(&mut newcomer_ms),
            "per_existing_member_ms": per_existing,
            "aggregate_ms": median(&mut newcomer_ms.clone()) + per_existing * existing as f64,
            "bytes_sent_total": existing * (SESSION_INIT_BYTES + 2 * (DISTRIBUTION_BYTES + PAIRWISE_OVERHEAD)),
            "note": "newcomer sets up n-1 pairwise sessions (X3DH-style, 3 X25519 each) and swaps sender keys with every member"
        }));

        // ---------------- Pairwise ----------------
        harness::record(file, "exp1_membership", json!({
            "scheme": "pairwise", "op": "remove", "n": n, "aggregate_ms": 0.0, "bytes_sent_total": 0,
            "note": "nothing to re-key: senders simply stop encrypting to the removed member; the cost moves to every message (exp2)"
        }));
        let mut nm = vec![];
        for _ in 0..reps.min(5) {
            let ids: Vec<Identity> = (0..existing.min(2000)).map(|_| Identity::generate()).collect();
            let bundles: Vec<PublicBundle> = ids.iter().map(|i| i.bundle()).collect();
            let me = Identity::generate();
            let t = Instant::now();
            for i in 0..existing {
                std::hint::black_box(initiate(&me, &bundles[i % bundles.len()]));
            }
            nm.push(ms(t));
        }
        harness::record(file, "exp1_membership", json!({
            "scheme": "pairwise", "op": "add", "n": n, "newcomer_ms_median": median(&mut nm),
            "bytes_sent_total": existing * SESSION_INIT_BYTES,
            "note": "newcomer opens a session with each of the n-1 members"
        }));
        eprintln!("n={n} done");
    }
}
