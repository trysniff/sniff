#![allow(clippy::await_holding_lock)]

use super::*;
use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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

fn spawn_hanging_server() -> (String, std::sync::Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let hits_clone = std::sync::Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        thread::sleep(Duration::from_secs(10));
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_text_json_server(body: &'static str) -> (String, std::sync::Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let hits_clone = std::sync::Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_body_stall_server() -> (String, std::sync::Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let hits_clone = std::sync::Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\n";
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        thread::sleep(Duration::from_secs(10));
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_status_server(status: u16, body: &'static str) -> (String, std::sync::Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let hits_clone = std::sync::Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let encoded = body.as_bytes();
        let response = format!(
            "HTTP/1.1 {} ERROR\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            encoded.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(encoded);
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

#[tokio::test]
async fn request_times_out_when_the_server_never_answers() {
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        env::set_var("SNIFF_LLM_REQUEST_TIMEOUT_SECS", "1");
    }

    let (endpoint, hits) = spawn_hanging_server();
    let client = reqwest::Client::builder().build().unwrap();
    let config = cfg(&endpoint);

    let err = try_call_raw(
        &client,
        &config,
        Some(&"test-key".to_string()),
        "return exactly one JSON object",
    )
    .await;

    unsafe {
        env::remove_var("SNIFF_LLM_REQUEST_TIMEOUT_SECS");
    }
    drop(lock);

    assert!(hits.load(Ordering::SeqCst) >= 1);
    let err = err.expect_err("expected request timeout");
    assert!(err.contains("timed out"), "{err}");
}

#[tokio::test]
async fn try_call_raw_accepts_json_with_plain_text_content_type() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let (endpoint, hits) = spawn_text_json_server(
        r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#,
    );
    let client = reqwest::Client::builder().build().unwrap();
    let config = cfg(&endpoint);

    let result = try_call_raw(
        &client,
        &config,
        Some(&"test-key".to_string()),
        "return exactly one JSON object",
    )
    .await
    .expect("expected text/json response to parse");

    assert!(result.0.contains("\"tier\":\"clean\""));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn response_body_timeout_is_configurable() {
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        env::set_var("SNIFF_LLM_BODY_TIMEOUT_SECS", "1");
    }

    let (endpoint, hits) = spawn_body_stall_server();
    let client = reqwest::Client::builder().build().unwrap();
    let config = cfg(&endpoint);

    let err = try_call_raw(
        &client,
        &config,
        Some(&"test-key".to_string()),
        "return exactly one JSON object",
    )
    .await;

    unsafe {
        env::remove_var("SNIFF_LLM_BODY_TIMEOUT_SECS");
    }
    drop(lock);

    assert!(hits.load(Ordering::SeqCst) >= 1);
    let err = err.expect_err("expected body timeout");
    assert!(err.contains("Timed out reading response body"), "{err}");
}

#[tokio::test]
async fn insufficient_balance_is_reported_explicitly() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let (endpoint, _hits) = spawn_status_server(
        402,
        r#"{"error":{"message":"Insufficient Balance","type":"unknown_error","code":"invalid_request_error"}}"#,
    );
    let client = reqwest::Client::builder().build().unwrap();
    let config = cfg(&endpoint);

    let err = try_call_raw(
        &client,
        &config,
        Some(&"test-key".to_string()),
        "return exactly one JSON object",
    )
    .await;

    let err = err.expect_err("expected insufficient-balance error");
    assert!(
        err.contains("LLM provider balance is insufficient"),
        "{err}"
    );
    assert!(err.contains("HTTP 402"), "{err}");
}
