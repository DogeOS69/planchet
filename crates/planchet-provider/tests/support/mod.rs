use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub struct Step {
    pub method: &'static str,
    pub params: Value,
    pub status: u16,
    pub body: String,
    pub chunked: bool,
    pub declared_length: Option<usize>,
    pub extra_header: String,
    pub delay: Duration,
}
impl Step {
    pub fn result(method: &'static str, params: Value, result: &str) -> Self {
        Self::body(
            method,
            params,
            200,
            &format!(r#"{{"result":{result},"error":null,"id":$ID}}"#),
        )
    }
    pub fn body(method: &'static str, params: Value, status: u16, body: &str) -> Self {
        Self {
            method,
            params,
            status,
            body: body.into(),
            chunked: false,
            declared_length: None,
            extra_header: String::new(),
            delay: Duration::ZERO,
        }
    }
}
pub struct Server {
    pub url: String,
    thread: JoinHandle<Vec<Value>>,
}
impl Server {
    pub fn start(steps: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = thread::spawn(move || {
            let mut requests = Vec::new();
            for step in steps {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "expected another RPC request: {}",
                                step.method
                            );
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                let (headers, request) = read_request(&mut stream);
                assert!(headers.starts_with("POST / HTTP/1.1\r\n"));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("content-type: application/json")
                );
                assert_eq!(request["jsonrpc"], "1.0");
                assert_eq!(request["method"], step.method);
                assert_eq!(request["params"], step.params);
                requests.push(json!({"request":request,"headers":headers}));
                let body = step.body.replace("$ID", &request["id"].to_string());
                thread::sleep(step.delay);
                let encoding = if step.chunked {
                    "Transfer-Encoding: chunked\r\n".into()
                } else {
                    format!(
                        "Content-Length: {}\r\n",
                        step.declared_length.unwrap_or(body.len())
                    )
                };
                let header = format!(
                    "HTTP/1.1 {} Reply\r\nContent-Type: application/json\r\nConnection: close\r\n{}{}\r\n",
                    step.status, encoding, step.extra_header
                );
                let _ = stream.write_all(header.as_bytes());
                if step.chunked {
                    for chunk in body.as_bytes().chunks(7) {
                        let _ = write!(stream, "{:x}\r\n", chunk.len());
                        let _ = stream.write_all(chunk);
                        let _ = stream.write_all(b"\r\n");
                    }
                    let _ = stream.write_all(b"0\r\n\r\n");
                } else {
                    let _ = stream.write_all(body.as_bytes());
                }
            }
            requests
        });
        Self { url, thread }
    }
    pub fn finish(self) -> Vec<Value> {
        self.thread.join().unwrap()
    }
}
pub fn read_request(stream: &mut TcpStream) -> (String, Value) {
    // macOS can inherit O_NONBLOCK from the listening socket. Restore blocking
    // I/O explicitly before applying finite read/write deadlines.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut data = Vec::new();
    let end = loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).unwrap();
        data.push(byte[0]);
        assert!(data.len() < 65536);
        if data.ends_with(b"\r\n\r\n") {
            break data.len();
        }
    };
    let headers = String::from_utf8(data).unwrap();
    let len: usize = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .unwrap();
    assert!(len < 1_000_000);
    let mut body = vec![0; len];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(end, headers.len());
    (headers, serde_json::from_slice(&body).unwrap())
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub const GENESIS: &str = "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5";
pub const TXID: &str = "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69";
pub const AUX_HASH: &str = "76c8c746788452725dec232c8897bf56f0dab9e50c5cfe97ef105134b4a5a666";
pub const BLOCK: &[u8] = include_bytes!("../fixtures/regtest-genesis.bin");
pub const AUX_BLOCK: &[u8] = include_bytes!("../fixtures/regtest-106-auxpow.bin");
pub fn header(hash: &str) -> String {
    format!(
        r#"{{"hash":"{hash}","confirmations":1,"height":0,"version":1,"merkleroot":"{TXID}","time":1386325540,"nonce":2,"bits":"207fffff","difficulty":1.00000000000000001e-8,"chainwork":"02"}}"#
    )
}
pub fn chain_info(chain: &str) -> String {
    format!(
        r#"{{"chain":"{chain}","blocks":0,"headers":0,"bestblockhash":"{GENESIS}","difficulty":1e-8,"verificationprogress":0.99999999999999999,"chainwork":"02","pruned":false}}"#
    )
}
