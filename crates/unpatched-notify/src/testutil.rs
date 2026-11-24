//! Test helper: a tiny in-process HTTP server that records requests. Only
//! compiled for tests; nothing here touches the network.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Path and query.
    pub path: String,
    /// Lower-cased header names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

pub struct TestServer {
    addr: std::net::SocketAddr,
    log: Arc<Mutex<Vec<Request>>>,
}

impl TestServer {
    /// Answer every request with `handler(request) -> (status, body)`.
    pub fn start(mut handler: impl FnMut(&Request) -> (u16, String) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<Request>>> = Arc::default();
        let log2 = Arc::clone(&log);
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
                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_owned());
                        if k == "content-length" {
                            len = v.parse().unwrap_or(0);
                        }
                        headers.push((k, v));
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let req = Request {
                    method,
                    path,
                    headers,
                    body,
                };
                let (status, out) = handler(&req);
                log2.lock().unwrap().push(req);
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    out.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(out.as_bytes());
            }
        });
        Self { addr, log }
    }

    /// Always answer `200 {}`.
    pub fn ok() -> Self {
        Self::start(|_| (200, "{}".into()))
    }

    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.log.lock().unwrap().clone()
    }
}
