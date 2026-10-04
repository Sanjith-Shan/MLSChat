//! Just enough HTTP to serve the static web client from the same port as the
//! WebSocket endpoint, so the demo is one process.

use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Peek at the request head without consuming it.
pub async fn is_websocket(stream: &TcpStream) -> anyhow::Result<bool> {
    let mut buf = vec![0u8; 4096];
    for _ in 0..50 {
        let n = stream.peek(&mut buf).await?;
        let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
        if head.contains("\r\n\r\n") || n == buf.len() {
            return Ok(head.contains("upgrade: websocket"));
        }
        if n == 0 {
            return Ok(false);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(false)
}

fn content_type(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript",
        "css" => "text/css",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "gif" => "image/gif",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

pub async fn serve(stream: &mut TcpStream, root: &Path) -> anyhow::Result<()> {
    let mut head = Vec::new();
    let mut b = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16384 {
        let n = stream.read(&mut b).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&b[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let path = text.split_whitespace().nth(1).unwrap_or("/").split('?').next().unwrap_or("/");
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    let (status, body, ctype) = if rel.split('/').any(|c| c == ".." || c.starts_with('.')) {
        ("403 Forbidden", b"forbidden".to_vec(), "text/plain")
    } else {
        let p = root.join(rel);
        match tokio::fs::read(&p).await {
            Ok(b) => ("200 OK", b, content_type(&p)),
            Err(_) => ("404 Not Found", b"not found".to_vec(), "text/plain"),
        }
    };
    let hdr = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(hdr.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await.ok();
    Ok(())
}
