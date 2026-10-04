//! exp4: messages lost, duplicated or reordered through server kills and
//! dropped connections. The server is a separate `mlschat-ds` process killed
//! with SIGKILL at random times and restarted on the same RocksDB directory.
//!
//! Usage: exp4_chaos [clients] [messages_per_client] [--no-idempotency] [--no-kills]

use client::testkit::{check_deliveries, parse_payload, payload};
use client::{Client, ClientConfig, Event};
use mls::CipherSuite;
use rand_core::RngCore;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn rnd() -> u64 {
    rand_core::OsRng.next_u64()
}

struct Ds {
    bin: std::path::PathBuf,
    data: std::path::PathBuf,
    port: u16,
    extra: Vec<String>,
    child: Option<Child>,
    kills: u64,
}

impl Ds {
    fn start(&mut self) {
        let mut cmd = Command::new(&self.bin);
        cmd.args(["--listen", &format!("127.0.0.1:{}", self.port), "--data"]).arg(&self.data);
        cmd.args(&self.extra).stdout(Stdio::null()).stderr(Stdio::null());
        self.child = Some(cmd.spawn().expect("spawn mlschat-ds"));
    }
    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill(); // SIGKILL
            let _ = c.wait();
            self.kills += 1;
        }
    }
}

impl Drop for Ds {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let nums: Vec<usize> = args.iter().skip(1).filter_map(|a| a.parse().ok()).collect();
    let n_clients = *nums.first().unwrap_or(&8);
    let per_client = *nums.get(1).unwrap_or(&300) as u64;
    let no_idem = args.iter().any(|a| a == "--no-idempotency");
    let kills_on = !args.iter().any(|a| a == "--no-kills");
    let commit_every = 40u64;
    let drop_prob_pct = 2u64;

    let dir = tempfile::tempdir().unwrap();
    let bin = std::env::current_exe().unwrap().parent().unwrap().join("mlschat-ds");
    let port = 20000 + (rnd() % 20000) as u16;
    let mut ds = Ds { bin, data: dir.path().join("db"), port, extra: if no_idem { vec!["--no-idempotency".into()] } else { vec![] }, child: None, kills: 0 };
    ds.start();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let url = format!("ws://127.0.0.1:{port}");
    let cs = CipherSuite(1);
    let dl = || Instant::now() + Duration::from_secs(120);

    let names: Vec<String> = (0..n_clients).map(|i| format!("dev{i}")).collect();
    let mut cl: Vec<Client> = names.iter().map(|n| Client::new(&url, n, cs, ClientConfig::default())).collect();
    for c in cl.iter_mut() {
        c.ensure_connected(dl()).await.unwrap();
        c.publish_key_packages(1).await.unwrap();
    }
    let gid = b"chaos-room".to_vec();
    cl[0].create_group(&gid).await.unwrap();
    let others: Vec<Vec<u8>> = names[1..].iter().map(|n| n.as_bytes().to_vec()).collect();
    cl[0].add_members(&gid, &others, dl()).await.unwrap();
    for c in cl[1..].iter_mut() {
        c.pump(dl(), |c| c.group(b"chaos-room").is_some()).await.unwrap();
    }

    let mut received: HashMap<String, Vec<(u64, String, u64)>> = names.iter().map(|n| (n.clone(), vec![])).collect();
    let mut process_errors: Vec<String> = vec![];
    let collect = |c: &mut Client, received: &mut HashMap<String, Vec<(u64, String, u64)>>, errs: &mut Vec<String>| {
        let me = String::from_utf8(c.id.clone()).unwrap();
        for e in c.take_events() {
            match e {
                Event::Message(m) => {
                    if let Some((s, n)) = parse_payload(&m.plaintext) {
                        received.get_mut(&me).unwrap().push((m.seq, s, n));
                    }
                }
                Event::ProcessError { error, .. } => errs.push(error),
                _ => {}
            }
        }
    };

    let start = Instant::now();
    let mut next_kill = Instant::now() + Duration::from_millis(500 + rnd() % 1500);
    let (mut drops, mut commits) = (0u64, 0u64);
    for step in 0..per_client {
        if kills_on && Instant::now() >= next_kill {
            ds.kill();
            tokio::time::sleep(Duration::from_millis(50 + rnd() % 250)).await;
            ds.start();
            next_kill = Instant::now() + Duration::from_millis(500 + rnd() % 1500);
        }
        for (i, c) in cl.iter_mut().enumerate() {
            if rnd() % 100 < drop_prob_pct {
                c.drop_connection();
                drops += 1;
            }
            c.ensure_connected(dl()).await.unwrap();
            c.send_text(&gid, &payload(&names[i], step)).await.unwrap();
            c.poll(Duration::from_millis(2)).await.unwrap();
            collect(c, &mut received, &mut process_errors);
        }
        if step > 0 && step % commit_every == 0 {
            let who = (rnd() as usize) % n_clients;
            cl[who].commit_with_retry(&gid, |_| vec![], vec![], vec![], dl()).await.unwrap();
            commits += 1;
        }
    }
    // Make sure the server is up, then drain.
    if ds.child.is_none() {
        ds.start();
    }
    for c in cl.iter_mut() {
        c.pump(dl(), |c| c.pending_sends() == 0).await.unwrap();
    }
    for c in cl.iter_mut() {
        c.sync_group(&gid, dl()).await.unwrap();
        collect(c, &mut received, &mut process_errors);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let auths: HashSet<Vec<u8>> = cl.iter().map(|c| c.epoch_authenticator(&gid).unwrap()).collect();
    let sent: HashMap<String, u64> = names.iter().map(|n| (n.clone(), per_client)).collect();
    let rep = check_deliveries(&received, &sent);
    let replayed = process_errors.iter().filter(|e| e.contains("already used")).count();
    let reconnects: u64 = cl.iter().map(|c| c.reconnects).sum();
    let resent: u64 = cl.iter().map(|c| c.resent).sum();
    println!(
        "messages sent {} | deliveries expected {} delivered {} lost {} duplicated {} reordered {} order disagreements {} | replayed ciphertexts {} | other errors {} | forks {} | server kills {} drops {} reconnects {} resent {} commits {} | {:.1}s",
        n_clients as u64 * per_client, rep.expected, rep.delivered, rep.lost, rep.duplicated, rep.reordered_per_sender, rep.order_disagreements,
        replayed, process_errors.len() - replayed, auths.len() - 1, ds.kills, drops, reconnects, resent, commits, elapsed
    );
    for e in process_errors.iter().take(5) {
        eprintln!("process error: {e}");
    }
    harness::record("exp4_chaos.jsonl", "exp4_chaos", json!({
        "clients": n_clients, "messages_per_client": per_client, "messages_sent": n_clients as u64 * per_client,
        "deliveries_expected": rep.expected, "delivered": rep.delivered, "lost": rep.lost, "duplicated": rep.duplicated,
        "reordered_per_sender": rep.reordered_per_sender, "global_order_disagreements": rep.order_disagreements,
        "replayed_ciphertexts": replayed, "other_process_errors": process_errors.len() - replayed,
        "distinct_epoch_states_at_end": auths.len(),
        "server_sigkills": ds.kills, "client_connection_drops": drops, "client_reconnects": reconnects, "requests_resent": resent,
        "commits_during_run": commits, "seconds": elapsed,
        "server_idempotency": !no_idem, "server_kills_enabled": kills_on, "server_fsync": true,
        "drop_probability_per_send_pct": drop_prob_pct, "commit_every_steps": commit_every,
    }));
}
