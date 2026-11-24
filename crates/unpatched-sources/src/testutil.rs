//! Test helpers: a tiny in-process HTTP server (no network, no extra crates)
//! and fixture loading. Only compiled for tests.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub struct TestServer {
    addr: std::net::SocketAddr,
}

impl TestServer {
    /// Answer every request with `handler(request) -> (status, body)`.
    pub fn start(mut handler: impl FnMut(&Request) -> (u16, Vec<u8>) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path = parts.next().unwrap_or("").to_owned();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let (status, out) = handler(&Request { method, path, body });
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    out.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&out);
            }
        });
        Self { addr }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

/// Read a file from the shared `fixtures/` directory.
pub fn fixture(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {}: {e}", p.display()))
}
