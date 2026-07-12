#![allow(clippy::await_holding_lock)]

use super::*;
use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use crate::roles::{ROLE_TEST_LOCK, is_compatibility_shim_record};
use crate::types::{FileRecord, MethodRecord};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn parse_virtual_file(file_path: &str, source: &str) -> FileRecord {
    let extension = file_path
        .rsplit(['\\', '/'])
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension)
        .expect("virtual role fixture needs a file extension");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let temp_path = std::env::temp_dir().join(format!("sniff-role-fixture-{nonce}.{extension}"));
    std::fs::write(&temp_path, source).expect("write virtual role fixture");
    let mut file = crate::parser::parse_file_checked(temp_path.to_str().unwrap())
        .expect("parse virtual role fixture");
    let _ = std::fs::remove_file(&temp_path);

    file.file_path = file_path.to_string();
    for method in &mut file.methods {
        method.file_path = file_path.to_string();
    }
    file
}

fn cfg(endpoint: &str) -> ResolvedConfig {
    ResolvedConfig {
        thresholds: ThresholdsConfig::default(),
        ignore: vec![],
        generic_names: vec![],
        generic_file_names: vec![],
        model: "test-model".to_string(),
        llm: LLMConfig {
            system_context: String::new(),
            endpoint: endpoint.to_string(),
        },
    }
}

fn spawn_openai_style_server(body: &'static str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let Ok(n) = stream.read(&mut buf) else {
                continue;
            };
            if n == 0 {
                continue;
            }
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_http_status_server(status: u16, body: &'static str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        request.extend_from_slice(&chunk[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|idx| idx + 4)
                .unwrap_or(request.len());
            let content_length = request_text
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(key, value)| {
                        if key.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(0);
            let has_expect_continue = request_text
                .lines()
                .any(|line| line.eq_ignore_ascii_case("expect: 100-continue"));
            if has_expect_continue {
                let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                let _ = stream.flush();
            }
            let mut remaining =
                content_length.saturating_sub(request.len().saturating_sub(header_end));
            while remaining > 0 {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        remaining = remaining.saturating_sub(n);
                    }
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 {} ERROR\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

#[path = "roles/classification.rs"]
mod classification;
#[path = "roles/intentional.rs"]
mod intentional;
#[path = "roles/paths.rs"]
mod paths;
#[path = "roles/surfaces.rs"]
mod surfaces;
#[path = "roles/wrappers.rs"]
mod wrappers;
