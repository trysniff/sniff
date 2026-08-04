#![allow(clippy::await_holding_lock)]

use sniff::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use sniff::llm::{LLMClient, ResponseSchema};
use std::env;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn read_http_request(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]).to_string();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let expected_total = header_end + content_length;
            while request.len() < expected_total {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            break;
        }
    }
    String::from_utf8_lossy(&request).to_string()
}

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = env::var_os(key);
        unsafe {
            env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(previous) = self.previous.take() {
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }
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

fn spawn_openai_style_server(responses: Vec<&'static str>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        for body in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let _ = read_http_request(&mut stream);
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

fn spawn_openai_style_server_with_prompts(
    responses: Vec<&'static str>,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
    let prompts_clone = Arc::clone(&prompts);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        for body in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let req = read_http_request(&mut stream);
            if let Ok(mut locked) = prompts_clone.lock() {
                locked.push(req);
            }
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

    (format!("http://{}", addr), hits, prompts)
}

fn spawn_body_stall_then_valid_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let hit = hits_clone.fetch_add(1, Ordering::SeqCst) + 1;
            thread::spawn(move || {
                let mut stream = stream;
                let _ = read_http_request(&mut stream);
                if hit == 1 {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\n",
                    );
                    let _ = stream.flush();
                    thread::sleep(Duration::from_secs(2));
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }

                let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
            });
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
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let _ = read_http_request(&mut stream);
        let response = format!(
            "HTTP/1.1 {} ERROR\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_hanging_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let _ = read_http_request(&mut stream);
        thread::sleep(Duration::from_secs(10));
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_path_asserting_server(expected_path: &'static str) -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let matched = Arc::new(AtomicBool::new(false));
    let matched_clone = Arc::clone(&matched);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        for _ in 0..3 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let req = read_http_request(&mut stream);
            let first_line = req.lines().next().unwrap_or("");
            if first_line.contains(expected_path) {
                matched_clone.store(true, Ordering::SeqCst);
            }
            let response_body = if expected_path.contains("/anthropic/") {
                r#"{"content":[{"type":"text","text":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}]}"#
            } else {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), matched)
}

fn spawn_header_asserting_server(
    expected_header: &'static str,
    response_body: &'static str,
) -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let matched = Arc::new(AtomicBool::new(false));
    let matched_clone = Arc::clone(&matched);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let req = read_http_request(&mut stream);
        if req
            .to_ascii_lowercase()
            .contains(&expected_header.to_ascii_lowercase())
        {
            matched_clone.store(true, Ordering::SeqCst);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), matched)
}

#[tokio::test]
async fn anthropic_base_url_expands_to_messages_endpoint() {
    let _env_lock = env_guard();
    let (endpoint, matched) = spawn_path_asserting_server("/anthropic/v1/messages");
    let client = LLMClient::new(
        cfg(&format!("{}/anthropic", endpoint)),
        Some("test-key".to_string()),
    );
    let _ = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await;
    assert!(matched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn openai_base_url_expands_to_chat_completions() {
    let _env_lock = env_guard();
    let (endpoint, matched) = spawn_path_asserting_server("/chat/completions");
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));
    let _ = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await;
    assert!(matched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn call_retries_when_json_is_missing_required_fields() {
    let _env_lock = env_guard();
    let first = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\"}"}}],"usage":{"prompt_tokens":100,"completion_tokens":10}}"#;
    let second = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}],"usage":{"prompt_tokens":200,"completion_tokens":20}}"#;
    let third = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}],"usage":{"prompt_tokens":300,"completion_tokens":30}}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![first, second, third]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, input_tokens, output_tokens)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected retried response to parse");
    };

    let value = value.expect("expected retried response to parse");
    assert_eq!(value["tier"], "slop");
    assert_eq!(input_tokens, 600);
    assert_eq!(output_tokens, 60);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn call_retries_once_when_the_assistant_returns_no_json() {
    let _env_lock = env_guard();
    let first = "sorry, I need another try";
    let second = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let third = second;
    let (endpoint, hits) = spawn_openai_style_server(vec![first, second, third]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected no-json retry response to parse");
    };

    let value = value.expect("expected no-json retry response to parse");
    assert_eq!(value["tier"], "slop");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn call_keeps_retrying_empty_assistant_content_before_repairing() {
    let _env_lock = env_guard();
    let empty = r#"{"choices":[{"message":{"content":""}}]}"#;
    let valid = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![empty, empty, valid, valid]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected empty-content retry response to parse");
    };

    let value = value.expect("expected empty-content retry response to parse");
    assert_eq!(value["tier"], "slop");
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn call_retries_body_timeout_before_repairing() {
    let _env_lock = env_guard();
    let _body_timeout = EnvVarGuard::set("SNIFF_LLM_BODY_TIMEOUT_SECS", "1");
    let (endpoint, hits) = spawn_body_stall_then_valid_server();
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected body-timeout retry response to parse");
    };

    let value = value.expect("expected body-timeout retry response to parse");
    assert_eq!(value["tier"], "slop");
    assert!(hits.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn call_switches_to_repair_prompt_after_repeated_no_json() {
    let _env_lock = env_guard();
    let first = "sorry, I need another try";
    let second = "still not ready";
    let third = "still not ready either";
    let fourth = "still not ready once more";
    let fifth = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let sixth = fifth;
    let (endpoint, hits, prompts) =
        spawn_openai_style_server_with_prompts(vec![first, second, third, fourth, fifth, sixth]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected repair-prompt response to parse");
    };

    let value = value.expect("expected repair-prompt response to parse");
    assert_eq!(value["tier"], "slop");
    assert_eq!(hits.load(Ordering::SeqCst), 6);

    let prompts = prompts.lock().unwrap();
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("Your previous answer was not valid JSON")),
        "expected one of the requests to switch to repair prompt, got:\n{}",
        prompts.join("\n---\n")
    );
}

#[tokio::test]
async fn probe_retries_once_when_the_assistant_returns_no_json() {
    let _env_lock = env_guard();
    let first = r#"{"choices":[{"message":{"content":"sorry, I need another try"}}]}"#;
    let second =
        r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![first, second]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    assert!(client.probe().await.is_ok());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn call_uses_consensus_when_borderline_votes_disagree() {
    let _env_lock = env_guard();
    let first = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#;
    let second = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let third = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![first, second, third]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected consensus response to parse");
    };

    let value = value.expect("expected consensus response to parse");
    assert_eq!(value["tier"], "slop");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn role_classification_uses_consensus_when_votes_disagree() {
    let _env_lock = env_guard();
    let first =
        r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"ambiguous\"}"}}]}"#;
    let second = r#"{"choices":[{"message":{"content":"{\"role\":\"adapter_integration\",\"reason\":\"glue\"}"}}]}"#;
    let third = r#"{"choices":[{"message":{"content":"{\"role\":\"adapter_integration\",\"reason\":\"glue\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![first, second, third]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Classify this file.", ResponseSchema::RoleClassification)
        .await
    else {
        panic!("expected consensus response to parse");
    };

    let value = value.expect("expected consensus response to parse");
    assert_eq!(value["role"], "adapter_integration");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn call_preserves_a_majority_slop_vote() {
    let _env_lock = env_guard();
    let first = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#;
    let second = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let third = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![first, second, third]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let Ok((value, _, _)) = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
    else {
        panic!("expected tie response to parse");
    };

    let value = value.expect("expected tie response to parse");
    assert_eq!(value["tier"], "slop");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn call_does_not_retry_on_permanent_http_errors() {
    let _env_lock = env_guard();
    let (endpoint, hits) = spawn_http_status_server(402, r#"{"error":"insufficient balance"}"#);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let err = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
        .expect_err("expected permanent http error to fail fast");
    assert!(err.contains("LLM provider balance is insufficient"));
    assert!(err.contains("HTTP 402"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn call_does_not_retry_on_not_found_endpoints() {
    let _env_lock = env_guard();
    let (endpoint, hits) = spawn_http_status_server(404, r#"{"error":"not found"}"#);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let err = client
        .call("Review this method.", ResponseSchema::MethodReview)
        .await
        .expect_err("expected permanent http error to fail fast");
    assert!(err.contains("HTTP 404"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn probe_uses_a_single_valid_json_request() {
    let _env_lock = env_guard();
    let body =
        r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![body]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    client.probe().await.expect("expected probe to succeed");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn quoted_api_keys_are_normalized_before_sending() {
    let _env_lock = env_guard();
    let response_body =
        r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#;
    let (endpoint, matched) =
        spawn_header_asserting_server("authorization: bearer test-key", response_body);
    let client = LLMClient::new(cfg(&endpoint), Some("\"test-key\"".to_string()));

    client.probe().await.expect("expected probe to succeed");
    assert!(matched.load(Ordering::SeqCst));
}

#[tokio::test]
async fn probe_reports_transport_errors_directly() {
    let _env_lock = env_guard();
    let _max_attempts = EnvVarGuard::set("SNIFF_LLM_MAX_ATTEMPTS", "1");

    let client = LLMClient::new(
        cfg("http://127.0.0.1:9/anthropic"),
        Some("test-key".to_string()),
    );

    let err = client
        .probe()
        .await
        .expect_err("expected probe to fail on a dead endpoint");

    assert!(err.contains("error sending request"), "{err}");
    assert!(err.contains("/anthropic/v1/messages"), "{err}");
}

#[tokio::test]
async fn probe_retries_until_the_payload_becomes_valid() {
    let _env_lock = env_guard();
    let _max_attempts = EnvVarGuard::set("SNIFF_LLM_MAX_ATTEMPTS", "3");

    let invalid = r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\"}"}}]}"#;
    let valid =
        r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(vec![invalid, invalid, valid]);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    client
        .probe()
        .await
        .expect("expected probe retry to succeed");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn probe_does_not_retry_on_permanent_http_errors() {
    let _env_lock = env_guard();
    let (endpoint, hits) = spawn_http_status_server(402, r#"{"error":"insufficient balance"}"#);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let err = client
        .probe()
        .await
        .expect_err("expected probe to fail fast on permanent http errors");
    assert!(err.contains("LLM provider balance is insufficient"));
    assert!(err.contains("HTTP 402"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn probe_times_out_promptly_on_hanging_requests() {
    let _env_lock = env_guard();
    let _client_timeout = EnvVarGuard::set("SNIFF_LLM_CLIENT_TIMEOUT_SECS", "1");
    let _max_attempts = EnvVarGuard::set("SNIFF_LLM_MAX_ATTEMPTS", "1");

    let (endpoint, hits) = spawn_hanging_server();
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let err = client
        .probe()
        .await
        .expect_err("expected probe to fail on a hanging request");

    assert!(hits.load(Ordering::SeqCst) >= 1);
    assert!(
        err.contains("timed out")
            || err.contains("watchdog expired")
            || err.contains("no valid JSON response")
            || err.contains("error sending request"),
        "{err}"
    );
}
