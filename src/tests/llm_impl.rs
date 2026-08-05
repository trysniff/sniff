use super::{parse_max_concurrency, parse_max_prompt_chars};
use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use crate::llm::{LLMClient, ResponseSchema};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

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

#[test]
fn review_context_key_versions_the_semantic_contract_not_the_binary() {
    let client = LLMClient::new(cfg("https://example.invalid/v1"), None);
    let context = client.review_context_key();

    assert!(!context.contains("sniff_version="));
    assert!(context.contains("review_contract=semantic-method-v27"));
    assert!(context.contains("model=test-model"));
    assert!(context.contains("endpoint=https://example.invalid/v1"));
}

#[test]
fn prompt_limit_reserves_output_context_and_allows_explicit_override() {
    assert_eq!(parse_max_prompt_chars(None, None), 359_424);
    assert_eq!(parse_max_prompt_chars(None, Some("64000")), 167_424);
    assert_eq!(
        parse_max_prompt_chars(Some("900000"), Some("64000")),
        900_000
    );
    assert_eq!(parse_max_prompt_chars(Some("100"), None), 4_096);
}

#[tokio::test]
async fn oversized_prompts_fail_before_transport() {
    let mut client = LLMClient::new(cfg("http://127.0.0.1:1/v1"), Some("test".to_string()));
    client.max_prompt_chars = 10;

    let error = client
        .call_single(
            "this prompt is too long",
            ResponseSchema::RoleClassification,
        )
        .await
        .expect_err("oversized prompt must fail before transport");

    assert!(error.contains("exceeding the configured safe limit"));
    assert!(error.contains("SNIFF_LLM_CONTEXT_TOKENS"));
}

fn spawn_empty_then_valid_anthropic_server() -> (String, Arc<AtomicUsize>) {
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

            let hit = hits_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let body = if hit == 1 {
                r#"{"content":[{"type":"text","text":""}]}"#
            } else {
                r#"{"content":[{"type":"text","text":"{\"role\":\"mixed\",\"reason\":\"ok\"}"}]}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    let _ = ready_rx.recv();

    (format!("http://{}/anthropic", addr), hits)
}

fn spawn_cached_usage_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"ok\"}"}}],"usage":{"prompt_tokens":1000,"completion_tokens":20,"prompt_cache_hit_tokens":750}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });
    let _ = ready_rx.recv();

    format!("http://{addr}")
}

fn spawn_malformed_batch_usage_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\"}"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"prompt_cache_hit_tokens":4}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    let _ = ready_rx.recv();

    format!("http://{addr}")
}

#[test]
fn llm_concurrency_defaults_and_clamps_to_the_supported_range() {
    assert_eq!(parse_max_concurrency(None), 4);
    assert_eq!(parse_max_concurrency(Some("")), 4);
    assert_eq!(parse_max_concurrency(Some("invalid")), 4);
    assert_eq!(parse_max_concurrency(Some("0")), 1);
    assert_eq!(parse_max_concurrency(Some("6")), 6);
    assert_eq!(parse_max_concurrency(Some("99")), 8);
}

#[tokio::test]
async fn anthropic_empty_content_is_retried_and_then_succeeds() {
    let (endpoint, hits) = spawn_empty_then_valid_anthropic_server();
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    client
        .probe()
        .await
        .expect("expected retry to recover from empty anthropic content");

    assert!(hits.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn client_accumulates_provider_cache_hits() {
    let endpoint = spawn_cached_usage_server();
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let (result, task_cached_tokens) = LLMClient::track_cached_input_tokens(
        client.call_single("classify", ResponseSchema::RoleClassification),
    )
    .await;
    let (_, input_tokens, output_tokens) = result.expect("cached response should parse");

    assert_eq!(input_tokens, 1_000);
    assert_eq!(output_tokens, 20);
    assert_eq!(client.cached_input_tokens(), 750);
    assert_eq!(task_cached_tokens, 750);
}

#[tokio::test]
async fn exhausted_format_repairs_are_included_in_usage_totals() {
    let endpoint = spawn_malformed_batch_usage_server();
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    client
        .call_single("review this batch", ResponseSchema::MethodIntentBatchReview)
        .await
        .expect_err("malformed batch should exhaust its format repair");

    assert_eq!(client.failed_input_tokens(), 20);
    assert_eq!(client.failed_output_tokens(), 4);
    assert_eq!(client.cached_input_tokens(), 8);
}
