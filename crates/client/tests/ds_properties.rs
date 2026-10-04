//! M2 property test: under random disconnects, server crashes and concurrent
//! commits, no group forks and no message is lost, duplicated or reordered.

use client::testkit::*;
use client::{Client, ClientConfig, Event};
use ds::Config;
use mls::CipherSuite;
use proptest::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Scenario {
    members: usize,
    per_sender: u64,
    /// (step, client) pairs at which that client drops its connection.
    drops: Vec<(u64, usize)>,
    /// Steps at which the server crashes and restarts.
    crashes: Vec<u64>,
    /// (step, client) pairs at which that client commits (an empty commit with a fresh path).
    commits: Vec<(u64, usize)>,
}

fn scenario() -> impl Strategy<Value = Scenario> {
    (3usize..5, 4u64..10).prop_flat_map(|(m, n)| {
        (
            Just(m),
            Just(n),
            proptest::collection::vec((0..n, 0..m), 0..6),
            proptest::collection::vec(0..n, 0..3),
            proptest::collection::vec((0..n, 0..m), 0..4),
        )
            .prop_map(|(members, per_sender, drops, crashes, commits)| Scenario { members, per_sender, drops, crashes, commits })
    })
}

async fn run(sc: Scenario) -> (DeliveryReport, usize) {
    let dir = tempfile::tempdir().unwrap();
    let mut server = TestServer::start(dir.path(), Config { sync_writes: false, ..Config::default() }, None);
    let url = server.url();
    let cs = CipherSuite(1);
    let deadline = || Instant::now() + Duration::from_secs(30);
    let names: Vec<String> = (0..sc.members).map(|i| format!("c{i}")).collect();
    let mut clients: Vec<Client> = names.iter().map(|n| Client::new(&url, n, cs, ClientConfig::default())).collect();
    for c in clients.iter_mut() {
        c.connect().await.unwrap();
        c.publish_key_packages(1).await.unwrap();
    }
    let gid = b"room".to_vec();
    clients[0].create_group(&gid).await.unwrap();
    let others: Vec<Vec<u8>> = names[1..].iter().map(|n| n.as_bytes().to_vec()).collect();
    clients[0].add_members(&gid, &others, deadline()).await.unwrap();
    for c in clients[1..].iter_mut() {
        c.pump(deadline(), |c| c.group(b"room").is_some()).await.unwrap();
    }

    let mut received: HashMap<String, Vec<(u64, String, u64)>> = names.iter().map(|n| (n.clone(), vec![])).collect();
    let mut errors = 0usize;
    let collect = |c: &mut Client, received: &mut HashMap<String, Vec<(u64, String, u64)>>, errors: &mut usize| {
        let me = String::from_utf8(c.id.clone()).unwrap();
        for e in c.take_events() {
            match e {
                Event::Message(m) => {
                    let (s, n) = parse_payload(&m.plaintext).unwrap();
                    received.get_mut(&me).unwrap().push((m.seq, s, n));
                }
                Event::ProcessError { .. } => *errors += 1,
                _ => {}
            }
        }
    };

    for step in 0..sc.per_sender {
        if sc.crashes.contains(&step) {
            server.restart();
        }
        for (i, c) in clients.iter_mut().enumerate() {
            if sc.drops.contains(&(step, i)) {
                c.drop_connection();
            }
            if c.ensure_connected(deadline()).await.is_err() {
                continue;
            }
            c.send_text(&gid, &payload(&names[i], step)).await.unwrap();
        }
        for (i, c) in clients.iter_mut().enumerate() {
            if sc.commits.contains(&(step, i)) {
                c.commit_with_retry(&gid, |_| vec![], vec![], vec![], deadline()).await.unwrap();
            }
            c.poll(Duration::from_millis(5)).await.unwrap();
            collect(c, &mut received, &mut errors);
        }
    }
    // Drain: every send answered, every client caught up to the log end.
    for c in clients.iter_mut() {
        c.pump(deadline(), |c| c.pending_sends() == 0).await.unwrap();
    }
    for c in clients.iter_mut() {
        c.sync_group(&gid, deadline()).await.unwrap();
        collect(c, &mut received, &mut errors);
    }
    let auths: std::collections::HashSet<Vec<u8>> = clients.iter().map(|c| c.epoch_authenticator(&gid).unwrap()).collect();
    let sent: HashMap<String, u64> = names.iter().map(|n| (n.clone(), sc.per_sender)).collect();
    let mut rep = check_deliveries(&received, &sent);
    rep.order_disagreements += errors as u64;
    (rep, auths.len())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn no_fork_loss_duplicate_or_reorder(sc in scenario()) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (rep, distinct_epochs) = rt.block_on(run(sc));
        prop_assert!(rep.expected > 0 && rep.delivered == rep.expected, "{:?}", rep);
        prop_assert_eq!(distinct_epochs, 1, "group forked");
        prop_assert_eq!(rep.lost, 0, "{:?}", rep);
        prop_assert_eq!(rep.duplicated, 0, "{:?}", rep);
        prop_assert_eq!(rep.reordered_per_sender, 0, "{:?}", rep);
        prop_assert_eq!(rep.order_disagreements, 0, "{:?}", rep);
    }
}
