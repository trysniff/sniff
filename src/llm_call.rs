#[path = "llm_call_policy.rs"]
mod llm_call_policy;
#[path = "llm_call_state.rs"]
mod llm_call_state;

use super::{LLMClient, ResponseSchema};

pub(super) async fn execute_call(
    client: &LLMClient,
    prompt: &str,
    schema: ResponseSchema,
) -> Result<(Option<serde_json::Value>, usize, usize), String> {
    llm_call_state::execute_call(client, prompt, schema).await
}

#[cfg(test)]
mod tests {
    use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
    use crate::llm::{LLMClient, ResponseSchema};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
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

    fn spawn_retry_server() -> (String, Arc<AtomicUsize>) {
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
                let hit = hits_clone.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body = if hit == 0 {
                    r#"{"choices":[{"message":{"content":"plain text no json here"}}]}"#
                } else {
                    r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\",\"cohesive\":true,\"name_accurate\":true}"}}]}"#
                };
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

    #[test]
    fn retry_same_prompt_includes_decode_failures() {
        assert!(super::super::llm_retry::retry_same_prompt_without_repair(
            "error decoding response body"
        ));
        assert!(super::super::llm_retry::retry_same_prompt_without_repair(
            "No JSON object found in response."
        ));
        assert!(super::super::llm_retry::retry_same_prompt_without_repair(
            "Timed out reading response body from Anthropic endpoint"
        ));
        assert!(super::super::llm_retry::retry_same_prompt_without_repair(
            "Invalid JSON response from OpenAI-style endpoint"
        ));
        assert!(super::super::llm_retry::retry_same_prompt_without_repair(
            "Empty assistant content"
        ));
        assert!(!super::super::llm_retry::retry_same_prompt_without_repair(
            "HTTP 500 from endpoint"
        ));
    }

    #[tokio::test]
    async fn no_json_object_retries_the_same_prompt_before_repair() {
        let (endpoint, hits) = spawn_retry_server();
        let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

        let (result, _, _) = client
            .call_once("return exactly one JSON object", ResponseSchema::FileReview)
            .await
            .expect("expected retry path to recover");

        assert!(result.is_some());
        assert!(hits.load(Ordering::SeqCst) >= 2);
    }
}
