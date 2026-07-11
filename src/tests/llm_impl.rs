use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use crate::llm::LLMClient;
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
