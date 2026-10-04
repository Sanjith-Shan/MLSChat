//! Run the delivery service.
//!
//!   mlschat-ds --listen 127.0.0.1:7070 --data /path/to/db [--mode fenced|ordered-unfenced|relay] [--no-sync]

use ds::{Config, Mode, Server};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let mut listen = "127.0.0.1:7070".to_string();
    let mut data = PathBuf::from("mlschat-ds-data");
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().expect("--listen value"),
            "--data" => data = PathBuf::from(args.next().expect("--data value")),
            "--mode" => config.mode = args.next().expect("--mode value").parse::<Mode>().map_err(anyhow::Error::msg)?,
            "--no-sync" => config.sync_writes = false,
            "--no-idempotency" => config.idempotent = false,
            "--web" => config.web_root = Some(PathBuf::from(args.next().expect("--web value"))),
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let server = Server::open(&data, config.clone())?;
    let (addr, h) = server.bind(&listen).await?;
    println!("mlschat-ds listening on {addr} mode={:?} sync={} data={}", config.mode, config.sync_writes, data.display());
    h.await?;
    Ok(())
}
