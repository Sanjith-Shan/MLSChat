//! Delivery-service load test. Many concurrent WebSocket clients in real MLS
//! groups send application messages at a fixed offered rate; we measure the
//! achieved rate and the end-to-end latency from the sender's send call to the
//! message being decrypted at each recipient (so it includes MLS encrypt,
//! server fence/append/fan-out and MLS decrypt).
//!
//! The server is a separate `mlschat-ds` process. The load generator runs on
//! the same 2-vCPU VM, so the two compete for CPU; numbers are a floor.
//!
//! Usage: loadtest <groups> <members_per_group> <rate_msgs_per_s>... [--no-sync] [--seconds S]

use client::{Client, ClientConfig, Event};
use mls::CipherSuite;
use rand_core::RngCore;
use serde_json::json;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Stats {
    latencies_us: Vec<f64>,
    sent: u64,
    delivered: u64,
    errors: u64,
}

/// utime + stime of a process, in seconds (from /proc).
fn cpu_seconds(pid: &str) -> f64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let rest = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = rest.split_whitespace().collect();
    let tick = 100.0;
    let u: f64 = f.get(11).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let k: f64 = f.get(12).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    (u + k) / tick
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let nums: Vec<f64> = args.iter().skip(1).take_while(|a| !a.starts_with("--")).filter_map(|a| a.parse().ok()).collect();
    let groups = nums.first().copied().unwrap_or(50.0) as usize;
    let per_group = nums.get(1).copied().unwrap_or(10.0) as usize;
    let rates: Vec<f64> = if nums.len() > 2 { nums[2..].to_vec() } else { vec![100.0, 300.0, 1000.0] };
    let no_sync = args.iter().any(|a| a == "--no-sync");
    let seconds: f64 = args.iter().position(|a| a == "--seconds").and_then(|i| args.get(i + 1)).and_then(|s| s.parse().ok()).unwrap_or(20.0);

    let dir = tempfile::tempdir().unwrap();
    let bin = std::env::current_exe().unwrap().parent().unwrap().join("mlschat-ds");
    let port = 30000 + (rand_core::OsRng.next_u32() % 20000) as u16;
    let mut cmd = Command::new(bin);
    cmd.args(["--listen", &format!("127.0.0.1:{port}"), "--data"]).arg(dir.path().join("db")).stdout(Stdio::null()).stderr(Stdio::null());
    if no_sync {
        cmd.arg("--no-sync");
    }
    let mut server = cmd.spawn().expect("spawn mlschat-ds");
    std::thread::sleep(Duration::from_millis(400));
    let url = format!("ws://127.0.0.1:{port}");

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let base = Instant::now();
    let cs = CipherSuite(1);

    // Build every group over the real server.
    let all: Vec<Vec<Client>> = rt.block_on(async {
        let mut out = vec![];
        for g in 0..groups {
            let names: Vec<String> = (0..per_group).map(|i| format!("g{g}-m{i}")).collect();
            let mut cl: Vec<Client> = names.iter().map(|n| Client::new(&url, n, cs, ClientConfig { ack_every: 64, ..Default::default() })).collect();
            for c in cl.iter_mut() {
                c.ensure_connected(Instant::now() + Duration::from_secs(30)).await.unwrap();
                c.publish_key_packages(1).await.unwrap();
            }
            let gid = format!("g{g}").into_bytes();
            cl[0].create_group(&gid).await.unwrap();
            let ids: Vec<Vec<u8>> = names[1..].iter().map(|n| n.as_bytes().to_vec()).collect();
            cl[0].add_members(&gid, &ids, Instant::now() + Duration::from_secs(60)).await.unwrap();
            for c in cl[1..].iter_mut() {
                c.pump(Instant::now() + Duration::from_secs(60), |c| c.group(&gid).is_some()).await.unwrap();
            }
            out.push(cl);
        }
        out
    });
    let connections = groups * per_group;
    eprintln!("{groups} groups x {per_group} members = {connections} connections ready");

    let mut clients: Vec<(Vec<u8>, Client)> = vec![];
    for (g, cl) in all.into_iter().enumerate() {
        for c in cl {
            clients.push((format!("g{g}").into_bytes(), c));
        }
    }

    for rate in rates {
        let stats = Arc::new(Mutex::new(Stats::default()));
        let per_client_interval = Duration::from_secs_f64(connections as f64 / rate);
        let stop_send = Instant::now() + Duration::from_secs_f64(seconds);
        let stop_all = stop_send + Duration::from_secs(3);
        let server_pid = server.id().to_string();
        let (srv0, gen0) = (cpu_seconds(&server_pid), cpu_seconds("self"));
        let started = Instant::now();
        let warm_ns = (started + Duration::from_secs(2)).duration_since(base).as_nanos() as u64;
        let handles: Vec<_> = std::mem::take(&mut clients)
            .into_iter()
            .enumerate()
            .map(|(i, (gid, mut c))| {
                let stats = stats.clone();
                rt.spawn(async move {
                    // Stagger start so sends are spread evenly.
                    let offset = per_client_interval.mul_f64((i as f64 * 0.618) % 1.0);
                    let mut next = Instant::now() + offset;
                    let (mut sent, mut lat, mut delivered, mut errors) = (0u64, Vec::new(), 0u64, 0u64);
                    while Instant::now() < stop_all {
                        let now = Instant::now();
                        if now >= next && now < stop_send {
                            let t = base.elapsed().as_nanos() as u64;
                            if c.send_text(&gid, format!("{t}").as_bytes()).await.is_ok() {
                                sent += 1;
                            }
                            next += per_client_interval;
                        }
                        let wait = next.saturating_duration_since(Instant::now()).min(Duration::from_millis(20)).max(Duration::from_millis(1));
                        let _ = c.poll(wait).await;
                        for e in c.take_events() {
                            match e {
                                Event::Message(m) => {
                                    if let Some(t) = std::str::from_utf8(&m.plaintext).ok().and_then(|s| s.parse::<u64>().ok()) {
                                        let now = m.at.duration_since(base).as_nanos() as u64;
                                        if t < warm_ns {
                                            continue; // warm-up: first 2 s of each step
                                        }
                                        lat.push((now.saturating_sub(t)) as f64 / 1000.0);
                                        delivered += 1;
                                    }
                                }
                                Event::ProcessError { .. } => errors += 1,
                                _ => {}
                            }
                        }
                    }
                    let mut s = stats.lock().unwrap();
                    s.sent += sent;
                    s.delivered += delivered;
                    s.errors += errors;
                    s.latencies_us.extend(lat);
                    (gid, c)
                })
            })
            .collect();
        for h in handles {
            clients.push(rt.block_on(h).unwrap());
        }
        let elapsed_send = seconds;
        let wall = started.elapsed().as_secs_f64();
        let server_cpu = (cpu_seconds(&server_pid) - srv0) / wall;
        let generator_cpu = (cpu_seconds("self") - gen0) / wall;
        let _ = started;
        let mut s = stats.lock().unwrap();
        s.latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let expected = s.sent * (per_group as u64 - 1);
        let p = |q| harness::percentile(&s.latencies_us, q) / 1000.0;
        eprintln!(
            "offered {rate:.0} msg/s: sent {} ({:.0}/s), deliveries {} of {} expected ({:.0}/s), p50 {:.1} ms p99 {:.1} ms max {:.1} ms, errors {}, cpu server {:.2} generator {:.2}",
            s.sent, s.sent as f64 / elapsed_send, s.delivered, expected, s.delivered as f64 / (elapsed_send - 2.0), p(50.0), p(99.0), p(100.0), s.errors, server_cpu, generator_cpu
        );
        harness::record("loadtest.jsonl", "ds_loadtest", json!({
            "groups": groups, "members_per_group": per_group, "connections": connections,
            "offered_msgs_per_s": rate, "seconds": seconds, "server_fsync": !no_sync,
            "sent": s.sent, "achieved_msgs_per_s": s.sent as f64 / elapsed_send,
            "deliveries_measured": s.delivered, "deliveries_per_s": s.delivered as f64 / (elapsed_send - 2.0), "deliveries_expected_incl_warmup": expected,
            "latency_ms_p50": p(50.0), "latency_ms_p90": p(90.0), "latency_ms_p99": p(99.0), "latency_ms_max": p(100.0),
            "process_errors": s.errors, "warmup_seconds_excluded": 2,
            "server_cpu_cores": server_cpu, "load_generator_cpu_cores": generator_cpu,
            "deliveries_counted_until": "3 s after sending stops",
            "latency_definition": "sender's send call to plaintext decrypted at a recipient: MLS encrypt + server fence, durable append and fan-out + MLS decrypt",
            "load_generator": "same VM as the server, 2 tokio worker threads",
        }));
    }
    let _ = server.kill();
    let _ = server.wait();
}
