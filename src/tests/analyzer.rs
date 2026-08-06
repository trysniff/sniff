#![allow(clippy::await_holding_lock)]

use super::dossier::StaleDiscardSignatureProof;
use super::method_review::MethodReviewContext;
use super::verdicts::normalize_file_verdict;
use super::*;
use crate::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use crate::types::FindingTier;
use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
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

fn semanticize_method_response(request: &str, body: &str) -> String {
    if !(request.contains("semantic intent pass")
        || request.contains("adversarial semantic pass")
        || request.contains("final adjudicator")
        || request.contains("claim-scoped adjudicator"))
    {
        return body.to_string();
    }

    let Ok(mut envelope) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };
    let Some(content) = envelope
        .pointer("/choices/0/message/content")
        .and_then(serde_json::Value::as_str)
    else {
        return body.to_string();
    };
    let Ok(mut verdict) = serde_json::from_str::<serde_json::Value>(content) else {
        return body.to_string();
    };
    if let Some(reviews) = verdict
        .get_mut("reviews")
        .and_then(serde_json::Value::as_array_mut)
    {
        for review in reviews {
            let Some(object) = review.as_object_mut() else {
                continue;
            };
            let Some(tier) = object.get("tier").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let complete_semantic = [
                "pattern",
                "intent",
                "necessity_check",
                "contract_status",
                "contract_impact",
                "dependency_impact",
                "simplification",
                "behavior_status",
                "missing_evidence",
                "evidence",
            ]
            .iter()
            .all(|field| object.contains_key(*field));
            if !complete_semantic {
                continue;
            }
            object.insert(
                "change_scope".to_string(),
                serde_json::Value::String(if matches!(tier, "clean" | "unresolved") {
                    "none".to_string()
                } else {
                    "local".to_string()
                }),
            );
        }
        envelope["choices"][0]["message"]["content"] =
            serde_json::Value::String(serde_json::to_string(&verdict).unwrap());
        return serde_json::to_string(&envelope).unwrap();
    }
    let complete_semantic = verdict.get("tier").is_some()
        && verdict.get("pattern").is_some()
        && verdict.get("contract_status").is_some()
        && verdict.get("contract_impact").is_some()
        && verdict.get("dependency_impact").is_some()
        && verdict.get("simplification").is_some()
        && verdict.get("behavior_status").is_some()
        && verdict.get("missing_evidence").is_some()
        && verdict
            .get("evidence")
            .is_some_and(serde_json::Value::is_array);
    if complete_semantic && verdict.get("change_scope").is_none() {
        let tier = verdict
            .get("tier")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("clean");
        verdict["change_scope"] = serde_json::Value::String(
            if matches!(tier, "clean" | "unresolved") {
                "none"
            } else {
                "local"
            }
            .to_string(),
        );
        envelope["choices"][0]["message"]["content"] =
            serde_json::Value::String(serde_json::to_string(&verdict).unwrap());
        return serde_json::to_string(&envelope).unwrap();
    }
    if verdict.get("tier").is_some()
        && verdict.get("pattern").is_some()
        && verdict.get("contract_status").is_some()
        && verdict.get("change_scope").is_some()
        && verdict.get("behavior_status").is_some()
        && verdict.get("missing_evidence").is_some()
        && verdict.get("evidence").is_some()
    {
        return body.to_string();
    }

    let tier = verdict
        .get("tier")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("clean")
        .to_string();
    verdict["contract_status"] = serde_json::Value::String(if tier == "clean" {
        "required".to_string()
    } else {
        "unnecessary".to_string()
    });
    verdict["contract_impact"] = serde_json::Value::String(if tier == "clean" {
        "The fixture contract requires the current method shape.".to_string()
    } else {
        "The simplification preserves the fixture method signature and contract.".to_string()
    });
    verdict["dependency_impact"] = serde_json::Value::String(if tier == "clean" {
        "The fixture callers depend on the current behavior.".to_string()
    } else {
        "No fixture caller, test, adapter, callback, re-export, or compatibility path depends on the redundant machinery.".to_string()
    });
    verdict["simplification"] = serde_json::Value::String(if tier == "clean" {
        "none".to_string()
    } else {
        "replace the unnecessary machinery with the direct operation".to_string()
    });
    verdict["change_scope"] = serde_json::Value::String(if tier == "clean" {
        "none".to_string()
    } else {
        "local".to_string()
    });
    verdict["behavior_status"] = serde_json::Value::String("preserved".to_string());
    verdict["missing_evidence"] = serde_json::json!([]);
    let reason = verdict
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let lower_reason = reason.to_lowercase();
    let prompt_source = request
        .split_once("Method source:\\n---\\n")
        .and_then(|(_, rest)| rest.split_once("\\n---"))
        .map(|(source, _)| source.replace("\\n", "\n").replace("\\\"", "\""))
        .unwrap_or_default();
    let should_be_clean = tier != "clean"
        && (reason.trim().is_empty()
            || prompt_source.trim().is_empty()
            || lower_reason.contains("previous version")
            || lower_reason.contains("copy-paste")
            || lower_reason.contains("format string uses placeholder")
            || lower_reason.contains("type annotation mismatch"));
    if should_be_clean {
        verdict["smelly"] = serde_json::Value::Bool(false);
        verdict["tier"] = serde_json::Value::String("clean".to_string());
        verdict["pattern"] = serde_json::Value::String("none".to_string());
        verdict["contract_status"] = serde_json::Value::String("required".to_string());
        verdict["behavior_status"] = serde_json::Value::String("preserved".to_string());
        verdict["change_scope"] = serde_json::Value::String("none".to_string());
        verdict["intent"] = serde_json::Value::String(
            "The method performs the behavior represented by the test fixture.".to_string(),
        );
        verdict["necessity_check"] = serde_json::Value::String(
            "The semantic review found no supported slop claim.".to_string(),
        );
        verdict["contract_impact"] = serde_json::Value::String(
            "The fixture method retains its current contract and direct behavior.".to_string(),
        );
        verdict["dependency_impact"] = serde_json::Value::String(
            "Fixture callers continue to depend on the current method behavior.".to_string(),
        );
        verdict["simplification"] = serde_json::Value::String("none".to_string());
        verdict["reason"] = serde_json::Value::String(String::new());
        verdict["evidence"] = serde_json::json!([]);
    } else {
        verdict["pattern"] = serde_json::Value::String(if tier == "clean" {
            "none".to_string()
        } else {
            "residual_machinery".to_string()
        });
        verdict["intent"] = serde_json::Value::String(
            "The method performs the behavior represented by the test fixture.".to_string(),
        );
        verdict["necessity_check"] = serde_json::Value::String(
            "The semantic review considered whether the implementation is necessary.".to_string(),
        );

        if tier == "clean" {
            verdict["evidence"] = serde_json::json!([]);
        } else {
            let evidence = verdict
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let start_line = request
                .split_once("absolute file line numbers from ")
                .and_then(|(_, rest)| rest.split_once(" through "))
                .and_then(|(start, _)| start.trim().parse::<usize>().ok())
                .unwrap_or(1);
            let quote_is_in_source =
                prompt_source.contains(evidence) && !evidence.trim().is_empty();
            let quote = if quote_is_in_source {
                evidence.to_string()
            } else {
                prompt_source
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("return value")
                    .to_string()
            };
            let quote_start_line = if quote_is_in_source {
                prompt_source
                    .lines()
                    .position(|line| line.contains(evidence))
                    .map(|offset| start_line + offset)
                    .unwrap_or(start_line)
            } else {
                start_line
            };
            let quote_end_line = quote_start_line + quote.lines().count().saturating_sub(1);
            verdict["evidence"] = serde_json::json!([{
                "start_line": quote_start_line,
                "end_line": quote_end_line,
                "quote": quote
            }]);
        }
    }

    let Some(content_slot) = envelope.pointer_mut("/choices/0/message/content") else {
        return body.to_string();
    };
    *content_slot = serde_json::Value::String(verdict.to_string());
    envelope.to_string()
}

fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut request = Vec::new();
    let mut expected_len = None;
    loop {
        let mut chunk = [0u8; 8192];
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);

        if expected_len.is_none()
            && let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let body_start = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            expected_len = Some(body_start + content_length);
        }

        if expected_len.is_some_and(|expected| request.len() >= expected) {
            break;
        }
    }
    (!request.is_empty()).then(|| String::from_utf8_lossy(&request).to_string())
}

fn spawn_openai_style_server(body: &'static str) -> (String, Arc<AtomicUsize>) {
    spawn_openai_style_server_impl(body, false)
}

fn spawn_openai_style_server_with_clean_batches(body: &'static str) -> (String, Arc<AtomicUsize>) {
    spawn_openai_style_server_impl(body, true)
}

fn clean_batch_response(request: &str) -> Option<String> {
    let method_keys = (0..8)
        .map(|index| format!("m{index}"))
        .filter(|key| request.contains(&format!("METHOD KEY: {key}")))
        .collect::<Vec<_>>();
    if method_keys.len() < 2 {
        return None;
    }

    let intent_only = request.contains("Do not assign a slop tier in this pass.");
    let reviews = method_keys
        .into_iter()
        .map(|method_key| {
            if intent_only {
                serde_json::json!({
                    "method_key": method_key,
                    "intent": "Implement the method's documented input contract.",
                    "contract_status": "required",
                    "necessity_check": "The method behavior is required by its contract.",
                    "missing_evidence": []
                })
            } else {
                serde_json::json!({
                    "method_key": method_key,
                    "tier": "clean",
                    "pattern": "none",
                    "intent": "Implement the method's documented input contract.",
                    "reason": "The method directly implements its contract.",
                    "necessity_check": "The implementation behavior is required.",
                    "contract_status": "required",
                    "contract_impact": "The method contract requires this behavior.",
                    "dependency_impact": "Callers consume the method result.",
                    "simplification": "none",
                    "behavior_status": "preserved",
                    "missing_evidence": [],
                    "evidence": []
                })
            }
        })
        .collect::<Vec<_>>();
    let content = serde_json::json!({"reviews": reviews}).to_string();
    Some(
        serde_json::json!({
            "choices": [{"message": {"content": content}}]
        })
        .to_string(),
    )
}

fn spawn_openai_style_server_impl(
    body: &'static str,
    provide_clean_batches: bool,
) -> (String, Arc<AtomicUsize>) {
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
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let body = if provide_clean_batches {
                clean_batch_response(&request)
                    .unwrap_or_else(|| semanticize_method_response(&request, body))
            } else {
                semanticize_method_response(&request, body)
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
    thread::sleep(Duration::from_millis(50));

    (format!("http://{}", addr), hits)
}

fn spawn_openai_style_server_sequence(bodies: Vec<&'static str>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let mut idx = 0usize;
        let mut last_body = bodies.last().copied().unwrap_or("");
        loop {
            let body = if idx < bodies.len() {
                let body = bodies[idx];
                idx += 1;
                last_body = body;
                body
            } else {
                last_body
            };
            loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let Some(request) = read_http_request(&mut stream) else {
                    continue;
                };
                hits_clone.fetch_add(1, Ordering::SeqCst);
                let body = semanticize_method_response(&request, body);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }
        }
    });
    let _ = ready_rx.recv();

    (format!("http://{}", addr), hits)
}

fn spawn_openai_style_server_with_capture(
    body: &'static str,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_clone = Arc::clone(&captured);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut slot) = captured_clone.lock() {
                *slot = request.clone();
            }
            let body = semanticize_method_response(&request, body);
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

    (format!("http://{}", addr), hits, captured)
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
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let body = if status == 200 {
                semanticize_method_response(&request, body)
            } else {
                body.to_string()
            };
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

fn spawn_http_status_sequence_server(
    statuses: Vec<u16>,
    body: &'static str,
) -> (String, Arc<AtomicUsize>) {
    let bodies = vec![body; statuses.len()];
    spawn_http_status_sequence_server_with_bodies(statuses, bodies)
}

fn spawn_http_status_sequence_server_with_bodies(
    statuses: Vec<u16>,
    bodies: Vec<&'static str>,
) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        let mut idx = 0usize;
        let mut last_status = statuses.last().copied().unwrap_or(500);
        let mut last_body = bodies.last().copied().unwrap_or("");
        loop {
            let status = if idx < statuses.len() {
                let status = statuses[idx];
                last_status = status;
                status
            } else {
                last_status
            };
            let body = if idx < bodies.len() {
                let body = bodies[idx];
                last_body = body;
                body
            } else {
                last_body
            };
            idx += 1;
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let body = if status == 200 {
                semanticize_method_response(&request, body)
            } else {
                body.to_string()
            };
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

#[path = "analyzer/evidence.rs"]
mod evidence;
#[path = "analyzer/normalization.rs"]
mod normalization;
#[path = "analyzer/repository.rs"]
mod repository;
#[path = "analyzer/support.rs"]
mod support;
#[path = "analyzer/surfaces.rs"]
mod surfaces;
#[path = "analyzer/transport.rs"]
mod transport;
