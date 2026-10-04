//! Helpers shared by the property tests and the experiments: an in-process
//! server that can be crashed and restarted, and a checker for what each
//! client received.

use ds::{Config, Server};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// A delivery service on its own runtime thread. Dropping or calling `crash`
/// tears down the runtime, which drops every connection and closes RocksDB,
/// like a process exit without a clean shutdown of client sessions.
pub struct TestServer {
    pub addr: SocketAddr,
    pub path: PathBuf,
    pub config: Config,
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn start(path: &Path, config: Config, addr: Option<SocketAddr>) -> TestServer {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let p = path.to_path_buf();
        let cfg = config.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            rt.block_on(async move {
                let server = Server::open(&p, cfg).expect("open store");
                let bind = addr.map(|a| a.to_string()).unwrap_or_else(|| "127.0.0.1:0".into());
                let mut tries = 0;
                let (local, _h) = loop {
                    match server.clone().bind(&bind).await {
                        Ok(x) => break x,
                        Err(e) if tries < 50 => {
                            tries += 1;
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            let _ = e;
                        }
                        Err(e) => panic!("bind: {e}"),
                    }
                };
                ready_tx.send(local).unwrap();
                tokio::task::spawn_blocking(move || {
                    let _ = stop_rx.recv();
                })
                .await
                .ok();
            });
            rt.shutdown_background();
        });
        let addr = ready_rx.recv().expect("server start");
        TestServer { addr, path: path.to_path_buf(), config, stop: Some(stop_tx), thread: Some(thread) }
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    /// Stop abruptly; the store is reopened by `restart`.
    pub fn crash(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn restart(&mut self) {
        self.crash();
        // RocksDB releases its lock when the runtime drops the last handle; retry briefly.
        let mut n = 0;
        loop {
            let r = std::panic::catch_unwind(|| TestServer::start(&self.path, self.config.clone(), Some(self.addr)));
            match r {
                Ok(s) => {
                    *self = s;
                    return;
                }
                Err(_) if n < 40 => {
                    n += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => std::panic::resume_unwind(e),
            }
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.crash();
    }
}

/// Application payload used by tests: "<sender>|<counter>".
pub fn payload(sender: &str, counter: u64) -> Vec<u8> {
    format!("{sender}|{counter}").into_bytes()
}

pub fn parse_payload(p: &[u8]) -> Option<(String, u64)> {
    let s = std::str::from_utf8(p).ok()?;
    let (a, b) = s.split_once('|')?;
    Some((a.to_string(), b.parse().ok()?))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub expected: u64,
    pub delivered: u64,
    pub lost: u64,
    pub duplicated: u64,
    /// Messages from one sender seen out of that sender's order.
    pub reordered_per_sender: u64,
    /// Pairs of clients that saw the same messages in a different global order.
    pub order_disagreements: u64,
}

/// `received[client]` is the list of (seq, sender, counter) the client delivered,
/// in delivery order. `sent[sender]` is how many messages the sender sent.
/// A client is expected to receive every message from every other sender.
pub fn check_deliveries(received: &HashMap<String, Vec<(u64, String, u64)>>, sent: &HashMap<String, u64>) -> DeliveryReport {
    let mut r = DeliveryReport::default();
    for (client, list) in received {
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        let mut last: HashMap<&str, u64> = HashMap::new();
        for (_, s, c) in list {
            if !seen.insert((s.clone(), *c)) {
                r.duplicated += 1;
                continue;
            }
            if let Some(prev) = last.get(s.as_str()) {
                if c < prev {
                    r.reordered_per_sender += 1;
                }
            }
            last.insert(s, *c);
        }
        for (sender, n) in sent {
            if sender == client {
                continue;
            }
            r.expected += n;
            for c in 0..*n {
                if seen.contains(&(sender.clone(), c)) {
                    r.delivered += 1;
                } else {
                    r.lost += 1;
                }
            }
        }
    }
    // Global order: for every pair of clients, the messages both received must appear in the same order.
    let orders: Vec<Vec<(String, u64)>> = received.values().map(|l| l.iter().map(|(_, s, c)| (s.clone(), *c)).collect()).collect();
    for i in 0..orders.len() {
        for j in i + 1..orders.len() {
            let pos_j: BTreeMap<&(String, u64), usize> = orders[j].iter().enumerate().map(|(k, x)| (x, k)).collect();
            let common: Vec<usize> = orders[i].iter().filter_map(|x| pos_j.get(x).copied()).collect();
            if common.windows(2).any(|w| w[0] > w[1]) {
                r.order_disagreements += 1;
            }
        }
    }
    r
}
