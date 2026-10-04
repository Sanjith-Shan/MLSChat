//! exp2: sender encrypt time and bytes per message, groups of 2 to 10,000.
//!
//! Usage: exp2_send [max_n] [messages]

use baselines::*;
use experiments::*;
use mls::{Codec, CipherSuite};
use rand_core::RngCore;
use serde_json::json;
use std::time::Instant;

fn random_session() -> Session {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut a);
    rand_core::OsRng.fill_bytes(&mut b);
    Session { send: Chain::new(a), recv: Chain::new(b) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let max_n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10000);
    let msgs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);
    let cs = CipherSuite(1);
    let file = "exp2_send.jsonl";
    let payload = vec![0x61u8; 100];

    for &n in SIZES.iter().filter(|n| **n <= max_n) {
        // MLS: one PrivateMessage for the whole group.
        let measured_leaf = if n >= 3 { 2 } else { 1 };
        let bg = build(cs, n, &[measured_leaf]);
        let mut sender = bg.creator.clone();
        let mut receiver = bg.measured[0].clone();
        let (mut enc, mut dec) = (vec![], vec![]);
        let mut bytes = 0;
        for _ in 0..msgs {
            let t = Instant::now();
            let m = sender.encrypt_application(&payload, b"").unwrap();
            enc.push(t.elapsed().as_secs_f64() * 1e6);
            let wire = m.to_bytes();
            bytes = wire.len();
            let t = Instant::now();
            receiver.process(&m).unwrap();
            dec.push(t.elapsed().as_secs_f64() * 1e6);
        }
        harness::record(file, "exp2_send", json!({
            "scheme": "mls", "n": n, "suite": cs.0, "messages": msgs, "payload_bytes": payload.len(),
            "sender_us_median": median(&mut enc), "receiver_us_median": median(&mut dec),
            "bytes_uploaded": bytes, "bytes_delivered_total": bytes * (n - 1),
            "note": "one PrivateMessage (AES-128-GCM + Ed25519 signature), server fans it out"
        }));
        drop(bg);

        // Sender Keys: one ciphertext plus a signature.
        let mut sk = SenderKey::generate();
        let mut rk = ReceiverKey::from_distribution(&sk.distribution());
        let (mut enc, mut dec) = (vec![], vec![]);
        let mut bytes = 0;
        for _ in 0..msgs {
            let t = Instant::now();
            let c = sk.encrypt(&payload);
            enc.push(t.elapsed().as_secs_f64() * 1e6);
            bytes = c.len();
            let t = Instant::now();
            rk.decrypt(&c).unwrap();
            dec.push(t.elapsed().as_secs_f64() * 1e6);
        }
        harness::record(file, "exp2_send", json!({
            "scheme": "sender_keys", "n": n, "messages": msgs, "payload_bytes": payload.len(),
            "sender_us_median": median(&mut enc), "receiver_us_median": median(&mut dec),
            "bytes_uploaded": bytes, "bytes_delivered_total": bytes * (n - 1),
            "note": "one AES-128-GCM ciphertext signed with Ed25519, server fans it out"
        }));

        // Pairwise: one ciphertext per recipient.
        let mut sessions: Vec<Session> = (0..n - 1).map(|_| random_session()).collect();
        let reps = if n >= 5000 { 20 } else { msgs };
        let mut enc = vec![];
        let mut bytes = 0;
        for _ in 0..reps {
            let t = Instant::now();
            let mut total = 0;
            for s in sessions.iter_mut() {
                total += s.encrypt(&payload).len();
            }
            enc.push(t.elapsed().as_secs_f64() * 1e6);
            bytes = total;
        }
        harness::record(file, "exp2_send", json!({
            "scheme": "pairwise", "n": n, "messages": reps, "payload_bytes": payload.len(),
            "sender_us_median": median(&mut enc),
            "bytes_uploaded": bytes, "bytes_delivered_total": bytes,
            "note": "one AES-128-GCM ciphertext per recipient over established sessions"
        }));
        eprintln!("n={n} done");
    }
}
