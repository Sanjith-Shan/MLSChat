//! exp3: forked groups when members commit at once, with and without epoch fencing.
//!
//! Three server modes, same client policy (merge your own commit once the server
//! acknowledges it):
//!   fenced            ordered log, a commit is accepted only for the current epoch
//!   ordered-unfenced  ordered log, every commit accepted
//!   relay             no ordering, each message fanned out independently
//!
//! Usage: exp3_concurrency [trials] [members]

use client::testkit::TestServer;
use client::{Client, ClientConfig, Event};
use ds::{Config, Mode};
use mls::messages::Proposal;
use mls::CipherSuite;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct Trial {
    branches: usize,
    off_main: usize,
    joiners_off_main: usize,
    accepted: usize,
    rejected: usize,
    unreadable: usize,
    process_errors: usize,
}

async fn trial(mode: Mode, members: usize, k: usize, adds: bool, seed: usize) -> Trial {
    let dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(dir.path(), Config { mode, sync_writes: false, ..Config::default() }, None);
    let url = server.url();
    let cs = CipherSuite(1);
    let cfg = ClientConfig { optimistic: mode == Mode::Relay, merge_on_accept: true, ..Default::default() };
    let dl = || Instant::now() + Duration::from_secs(20);
    let names: Vec<String> = (0..members).map(|i| format!("t{seed}-m{i}")).collect();
    let mut cl: Vec<Client> = names.iter().map(|n| Client::new(&url, n, cs, cfg.clone())).collect();
    for c in cl.iter_mut() {
        c.connect().await.unwrap();
        c.publish_key_packages(1).await.unwrap();
    }
    let gid = b"g".to_vec();
    cl[0].create_group(&gid).await.unwrap();
    let ids: Vec<Vec<u8>> = names[1..].iter().map(|n| n.as_bytes().to_vec()).collect();
    let req = {
        let mut kps = vec![];
        for i in &ids {
            kps.push(cl[0].fetch_key_package(i).await.unwrap());
        }
        cl[0].fire_commit(&gid, kps.into_iter().map(Proposal::Add).collect(), ids.clone()).await.unwrap()
    };
    cl[0].await_outcome(req, dl()).await.unwrap();
    for c in cl[1..].iter_mut() {
        c.pump(dl(), |c| c.group(b"g").is_some()).await.unwrap();
    }
    for c in cl.iter_mut() {
        c.poll(Duration::from_millis(20)).await.unwrap();
        c.take_events();
    }

    // Newcomers for the add variant, one per committer.
    let mut newcomers: Vec<Client> = (0..if adds { k } else { 0 }).map(|i| Client::new(&url, &format!("t{seed}-new{i}"), cs, cfg.clone())).collect();
    let mut new_kps = vec![];
    for (i, n) in newcomers.iter_mut().enumerate() {
        n.connect().await.unwrap();
        n.publish_key_packages(1).await.unwrap();
        let id = format!("t{seed}-new{i}").into_bytes();
        new_kps.push((id.clone(), cl[0].fetch_key_package(&id).await.unwrap()));
    }

    // k members commit at the same moment: all sends go out before anyone reads.
    let committers: Vec<usize> = (0..k).map(|i| (seed + i * 2 + 1) % members).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let mut reqs = HashMap::new();
    for (j, &i) in committers.iter().enumerate() {
        let (props, add) = if adds { (vec![Proposal::Add(new_kps[j].1.clone())], vec![new_kps[j].0.clone()]) } else { (vec![], vec![]) };
        let r = cl[i].fire_commit(&gid, props, add).await.unwrap();
        reqs.insert(i, r);
    }
    let (mut accepted, mut rejected) = (0, 0);
    for (&i, &r) in &reqs {
        match cl[i].await_outcome(r, dl()).await.unwrap() {
            client::SendOutcome::Accepted { .. } => accepted += 1,
            client::SendOutcome::Rejected(..) => rejected += 1,
        }
    }
    let settle = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle {
        for c in cl.iter_mut().chain(newcomers.iter_mut()) {
            c.poll(Duration::from_millis(5)).await.unwrap();
        }
    }

    // Branches: distinct (epoch, epoch_authenticator) across members and joined newcomers.
    let mut branch_of: Vec<Option<Vec<u8>>> = cl.iter().map(|c| c.epoch_authenticator(&gid)).collect();
    let joined_new: Vec<Option<Vec<u8>>> = newcomers.iter().map(|c| c.epoch_authenticator(&gid)).collect();
    branch_of.extend(joined_new.iter().cloned());
    let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
    for a in branch_of.iter().flatten() {
        *counts.entry(a.clone()).or_default() += 1;
    }
    let main = counts.iter().max_by_key(|(_, n)| **n).map(|(a, _)| a.clone()).unwrap_or_default();
    let off_main = cl.iter().filter(|c| c.epoch_authenticator(&gid).as_ref() != Some(&main)).count();
    let joiners_off_main = joined_new.iter().flatten().filter(|a| **a != main).count();

    // Can members still read each other? Everyone sends one message.
    let mut process_errors = 0;
    for c in cl.iter_mut().chain(newcomers.iter_mut()) {
        for e in c.take_events() {
            if let Event::ProcessError { .. } = e {
                process_errors += 1;
            }
        }
    }
    for (i, c) in cl.iter_mut().enumerate() {
        let _ = c.send_text(&gid, format!("after {i}").as_bytes()).await;
    }
    let settle = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle {
        for c in cl.iter_mut() {
            c.poll(Duration::from_millis(5)).await.unwrap();
        }
    }
    let mut unreadable = 0;
    for c in cl.iter_mut() {
        for e in c.take_events() {
            if let Event::ProcessError { .. } = e {
                unreadable += 1;
            }
        }
    }
    drop(server);
    Trial { branches: counts.len(), off_main, joiners_off_main, accepted, rejected, unreadable, process_errors }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trials: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(50);
    let members: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(6);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for mode in [Mode::Fenced, Mode::OrderedUnfenced, Mode::Relay] {
        for adds in [false, true] {
            for k in [2usize, 4] {
                let (mut forked, mut off, mut joff, mut acc, mut rej, mut unr, mut perr) = (0, 0, 0, 0, 0, 0, 0);
                for t in 0..trials {
                    let r = rt.block_on(trial(mode, members, k, adds, t));
                    if r.branches > 1 {
                        forked += 1;
                    }
                    off += r.off_main;
                    joff += r.joiners_off_main;
                    acc += r.accepted;
                    rej += r.rejected;
                    unr += r.unreadable;
                    perr += r.process_errors;
                }
                let mode_s = match mode {
                    Mode::Fenced => "fenced",
                    Mode::OrderedUnfenced => "ordered-unfenced",
                    Mode::Relay => "relay",
                };
                eprintln!("{mode_s:>17} adds={adds} k={k}: forked {forked}/{trials}, members off main branch {off}, rejected {rej}");
                harness::record("exp3_concurrency.jsonl", "exp3_concurrency", json!({
                    "mode": mode_s, "variant": if adds { "concurrent_add_commits" } else { "concurrent_empty_commits" },
                    "members": members, "concurrent_committers": k, "trials": trials,
                    "forked_trials": forked, "members_off_main_branch_total": off, "newcomers_off_main_branch_total": joff,
                    "commits_accepted_total": acc, "commits_rejected_total": rej,
                    "commit_process_errors_total": perr, "unreadable_messages_after_total": unr,
                    "client_policy": "merge own commit when the server acknowledges it",
                }));
            }
        }
    }
}
