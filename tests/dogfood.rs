use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

struct ManagedChild {
    child: Option<Child>,
}

impl ManagedChild {
    fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }

    fn wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill();
        self.wait();
    }
}

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{label}-{nanos}"))
}

fn write_file(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn ts_slop_module(function_name: &str) -> String {
    let function_name = function_name.replace('-', "_");
    format!(
        "export function {function_name}() {{\n  const values = [1, 2, 3, 4, 5, 6];\n  let total = 0;\n  for (const value of values) {{\n    if (value % 2 === 0) {{\n      total += value;\n    }} else {{\n      total += value * 2;\n    }}\n  }}\n  if (total > 10) {{\n    return total.toString();\n  }}\n  return \"0\";\n}}\n"
    )
}

fn js_slop_bundle(prefix: &str) -> String {
    format!(
        "export function {prefix}Entry(value) {{\n  let total = 0;\n  for (const item of [1, 2, 3, 4, 5, 6]) {{\n    if (item % 2 === 0) {{\n      total += item;\n    }} else {{\n      total += item * 2;\n    }}\n  }}\n  if (value) {{\n    total += value;\n  }}\n  return total;\n}}\n\nexport function {prefix}Fallback(value) {{\n  if (!value) {{\n    return null;\n  }}\n  if (value.length > 3) {{\n    return value.trim();\n  }}\n  return value;\n}}\n\nexport function {prefix}Summarize(items) {{\n  const output = [];\n  for (const item of items) {{\n    if (item) {{\n      output.push(item);\n    }}\n  }}\n  return output.join(\",\");\n}}\n"
    )
}

fn js_branchy_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\nexport function {prefix}Helper{idx:02}(value) {{\n  if (value === 0) {{\n    return 0;\n  }}\n  if (value === 1) {{\n    return 1;\n  }}\n  if (value === 2) {{\n    return 2;\n  }}\n  return value;\n}}\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn python_slop_module(function_name: &str) -> String {
    format!(
        "def {function_name}(items):\n    total = 0\n    for item in items:\n        if item:\n            total += item\n        else:\n            total += 0\n    if total > 10:\n        return total\n    return total\n"
    )
}

fn python_clean_module(function_name: &str) -> String {
    format!("def {function_name}(items):\n    return list(items)\n")
}

fn branchy_python_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\ndef {prefix}_helper_{idx:02}(value):\n    if value == 0:\n        return 0\n    if value == 1:\n        return 1\n    if value == 2:\n        return 2\n    return value\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn ts_clean_module(function_name: &str) -> String {
    format!("export function {function_name}() {{\n  return \"ok\";\n}}\n")
}

fn python_slop_bundle(prefix: &str, function_name: &str) -> String {
    format!(
        "{}{}",
        python_slop_module(function_name),
        branchy_python_helpers(prefix, 18)
    )
}

fn ts_slop_bundle(prefix: &str, function_name: &str) -> String {
    format!(
        "{}{}",
        ts_slop_module(function_name),
        js_branchy_helpers(prefix, 18)
    )
}

fn read_http_request(stream: TcpStream) -> (TcpStream, String) {
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 {
            break;
        }
        headers.push_str(&line);
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body);
    }

    let request = format!("{}{}", headers, String::from_utf8_lossy(&body));
    (reader.into_inner(), request)
}

fn repair_mock_file_evidence(request: &str, body: &str) -> String {
    if !request.contains("Filename:") || !body.contains("\\\"smelly\\\":true") {
        return body.to_string();
    }

    let source = request
        .split_once("Source:\\n---\\n")
        .and_then(|(_, rest)| rest.split_once("\\n---"))
        .map(|(source, _)| source.replace("\\n", "\n").replace("\\\"", "\""))
        .unwrap_or_default();

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
    let evidence_is_valid = verdict
        .get("evidence")
        .and_then(serde_json::Value::as_str)
        .map(|evidence| source.contains(evidence))
        .unwrap_or(false);
    if !evidence_is_valid {
        let replacement = source
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                if request.contains(".py") {
                    "def ".to_string()
                } else if request.contains(".rs") {
                    "fn ".to_string()
                } else if request.contains(".go") {
                    "func ".to_string()
                } else if request.contains(".kt") {
                    "fun ".to_string()
                } else {
                    "export".to_string()
                }
            });
        verdict["evidence"] = serde_json::Value::String(replacement);
        let Some(content_slot) = envelope.pointer_mut("/choices/0/message/content") else {
            return body.to_string();
        };
        *content_slot = serde_json::Value::String(verdict.to_string());
    }

    envelope.to_string()
}

fn spawn_openai_style_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    thread::spawn(move || {
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let (stream_back, request) = read_http_request(stream);
            let body = if request.contains("You classify codebase file roles for Sniff.")
                || (request.contains("probe")
                    && request.contains("Return exactly one JSON object with this shape"))
            {
                r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"mock\"}"}}]}"#
            } else if request.contains("Filename:") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
            } else {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut stream = stream_back;
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    (format!("http://{}", addr), hits)
}

fn spawn_prompt_logging_server() -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
    let prompts_clone = Arc::clone(&prompts);

    thread::spawn(move || {
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let (stream_back, request) = read_http_request(stream);
            if let Ok(mut locked) = prompts_clone.lock() {
                locked.push(request.clone());
            }

            let body = if request.contains("Return exactly one JSON object with this shape")
                || request.contains("You classify codebase file roles for Sniff.")
            {
                r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"mock\"}"}}]}"#
            } else if request.contains("Method: sloppy") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return total\",\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: sloppy.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return total\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: polar-webhook/index.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"const totals = (order?.totals as Record<string, unknown> | undefined) ?? {};\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"readAmountCents: overbuilt fallback chain with unused totals variable; readCustomerEmail: unnecessary fallback to empty object for customer; readEnvBool: copy-pasted method body\"}"}}]}"#
            } else if request.contains("Filename: drop-payload-staging.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createDropPayloadStaging\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: service-worker-runtime-handlers.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createServiceWorkerRuntimeHandlers\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: registry-sync.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createRegistrySync\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: session-launch-policy.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function mapEntitlementReasonToResponse(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: session-actions.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function createSessionActions(deps: SessionActionsDeps) {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: session-state.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function createSessionStateManager(deps: {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: session-safe-start.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function randomIntInclusive(min: number, max: number): number {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: runtime-message-validation.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"if (message.type === \\\"START_SESSION\\\") {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"single function handles validation for many unrelated message types\"}"}}]}"#
            } else if request.contains("Filename: session-launch-orchestration.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"async function prepareSessionLaunch(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: pipeline.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run(args: Namespace, *, comment_poster: CommentPoster | None = None) -> int:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: planning.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def prepare_release_plan(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: runtime-wireup.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"registerRuntimeWireup: function is too big (374 LOC > 100)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: feedback-handlers.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function createFeedbackHandlers(deps: FeedbackHandlersDeps) {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: crypto-feedback.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export async function encryptWithSessionKey(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: repository_client.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def get_pull_request(self, number: int) -> ReleaseScopedPullRequest:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: rationale.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_release_why_lines(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: comments.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_recommendation_comment_metadata(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: engine.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def apply_impact_evidence_threshold(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: recommendations.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_api_diff_result(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: frame-sync.ts") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function createFrameSyncCoordinator(chromeApi: typeof chrome) {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: contracts.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def validate_app_event_envelope_payload(payload: dict[str, Any]) -> list[str]:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module has sprawling helper surface\"}"}}]}"#
            } else if request.contains("Filename: ingress.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def ingest_webhook_event(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: reactions.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"class GitHubIssueCommentPublisher:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: webhook.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def handle_github_webhook(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: webhook_commands.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_command_reaction(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: webhook_service.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def process_merge_recommendation(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: rendering.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def _build_release_evidence_lines(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: webhook_release_flow.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def process_release_command(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: persistence_ephemeral.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"class EphemeralAppStateStore:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: persistence_sqlite.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"class SqliteAppStateStore:\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("signup-wrapper") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function normalizeIpToken(raw: unknown): string | null {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("buildOutputPayload")
                || request.contains("normalizePayload")
                || request.contains("renderPayloadSummary")
                || request.contains("auditPayloadLine")
                || request.contains("multiline-evidence.ts")
            {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function buildOutputPayload(status: string, payload: string) {\n  const lines: string[] = [];\n  lines.push(status.trim());\n  lines.push(payload.trim());\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("main.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"from bumpkin.release.analysis import (\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: release_job.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run_release_job(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: finding_python_signatures.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def extract_python_signatures\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: case_file.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def case_file_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: finding_js_ts.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def finding_js_ts_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: finding_python_signature_findings.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def finding_python_signature_findings_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: finding_python_surface_findings.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def finding_python_surface_findings_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: semantic_review.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def semantic_review_orchestrate(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: chunking.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def split_diff_units_into_chunks(units):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: semantic.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def semantic_fallback_recommendation(items):\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("applicationController.js")
                || request.contains("jobController.js")
                || request.contains("postsController.js")
                || request.contains("userController.js")
            {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
            };
            let body = repair_mock_file_evidence(&request, body);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut stream = stream_back;
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    (format!("http://{}", addr), hits, prompts)
}

fn spawn_bumpkin_shape_server() -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
    let prompts_clone = Arc::clone(&prompts);

    thread::spawn(move || {
        loop {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let (stream_back, request) = read_http_request(stream);
            if let Ok(mut locked) = prompts_clone.lock() {
                locked.push(request.clone());
            }

            let body = if request.contains("Return exactly one JSON object with this shape") {
                r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#
            } else if request.contains("Filename: checkout-rpc.ts")
                || request.contains("Filename: domain-gateway.ts")
            {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"createCheckoutRpc\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: chunking.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def split_diff_units_into_chunks(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: semantic.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def semantic_fallback_recommendation(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: case_file.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def build_case_file(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: finding_js_ts.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run_js_ts_export_detection(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: finding_python_signature_findings.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def append_python_signature_findings(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: finding_python_signatures.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def extract_python_signatures(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#
            } else if request.contains("Filename: finding_python_surface_findings.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def append_python_surface_findings(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: semantic_review.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def detect_contradictions(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else if request.contains("Filename: release_job.py") {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def run_release_job(\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
            };
            let body = repair_mock_file_evidence(&request, body);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut stream = stream_back;
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    (format!("http://{}", addr), hits, prompts)
}

fn spawn_bumpkin_github_integration_server() -> (String, ManagedChild) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let (ready_tx, ready_rx) = mpsc::channel();

    thread::spawn(move || {
        let _ = ready_tx.send(());
        loop {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let (mut stream, request) = read_http_request(stream);
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let body = if request.contains("Return exactly one JSON object with this shape") {
                r#"{"choices":[{"message":{"content":"{\"role\":\"mixed\",\"reason\":\"probe\"}"}}]}"#
            } else if request.contains("Filename: contracts.py")
                || request.contains("Filename: ingress.py")
                || request.contains("Filename: reactions.py")
                || request.contains("Filename: recommendations.py")
                || request.contains("Filename: webhook.py")
                || request.contains("Filename: webhook_commands.py")
                || request.contains("Filename: webhook_service.py")
                || request.contains("Filename: persistence_sqlite.py")
                || request.contains("Filename: github_auth.py")
            {
                r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"function is too big\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#
            } else {
                r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#
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
    (format!("http://{}", addr), ManagedChild { child: None })
}

fn populate_bumpkin_like_repo(root: &Path) {
    let packages = ["analysis", "providers", "release", "orchestrator", "github"];

    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );

    for package in packages {
        let package_dir = root.join("src").join("bumpkin").join(package);
        fs::create_dir_all(&package_dir).unwrap();

        write_file(
            root,
            &format!("src/bumpkin/{package}/__init__.py"),
            &format!("from .core import {package}_entry\nfrom .helpers import {package}_helper\n"),
        );

        write_file(
            root,
            &format!("src/bumpkin/{package}/core.py"),
            &format!(
                "from .helpers import {package}_helper\n\n\
def {package}_entry():\n    return {package}_helper()\n\n\
def {package}_dispatch(flag: bool):\n    if flag:\n        return {package}_helper()\n    return 0\n"
            ),
        );

        write_file(
            root,
            &format!("src/bumpkin/{package}/helpers.py"),
            &format!(
                "def {package}_helper():\n    return 1\n\n\
def {package}_fallback(value):\n    if value:\n        return value\n    return {package}_helper()\n"
            ),
        );

        write_file(
            root,
            &format!("src/bumpkin/{package}/bridge.py"),
            &format!(
                "from .core import {package}_entry\n\n\
def bridge_{package}():\n    return {package}_entry()\n"
            ),
        );
    }

    write_file(
        root,
        "src/bumpkin/__init__.py",
        "from .analysis import analysis_entry\nfrom .providers import providers_entry\nfrom .release import release_entry\n",
    );

    write_file(
        root,
        "src/main.py",
        "from bumpkin import analysis_entry\n\ndef main():\n    return analysis_entry()\n",
    );
}

fn populate_react_entrypoint_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "src/main.tsx",
        "import { createRoot } from 'react-dom/client';\n\
         import { App } from './App';\n\
         createRoot(document.getElementById('root')!).render(<App />);\n",
    );
    write_file(
        root,
        "src/App.tsx",
        "export function App() {\n  return <main>Hello</main>;\n}\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

fn populate_support_boundary_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "ui/background/core/service-worker-support.ts",
        "export async function getImprovementTelemetryConsent() { return true; }\n\
         export async function setImprovementTelemetryConsent(enabled: boolean) { return enabled; }\n\
         export async function migrateNamesetStoreToCanonicalObject() { return; }\n\
         export async function readKillSwitches() { return {}; }\n\
         export function deriveFeedbackContextFromSender(sender: chrome.runtime.MessageSender) { return { domain: null, uriHash: null }; }\n\
         export async function encryptWithSessionKey(plaintext: string) { return plaintext; }\n",
    );
    write_file(
        root,
        "ui/src/lib/feature-flags.ts",
        "export class FeatureFlags {\n\
             static isEnabled(flag: string) { return true; }\n\
             static async setOverride(flag: string, value: boolean) { return value; }\n\
         }\n",
    );
    write_file(
        root,
        "ui/src/lib/password-session-cache.ts",
        "export const getSessionPassword = async (brandId: string) => null;\n\
         export const setSessionPassword = async (brandId: string, password: string) => {};\n\
         export const clearSessionPassword = async (brandId: string) => {};\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

fn populate_data_catalog_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "ui/src/data/platforms.ts",
        "export type Platform = { id: string };\n\
         const RAW_PLATFORMS: Record<string, Platform> = Object.fromEntries([]);\n\
         export const PLATFORMS = RAW_PLATFORMS;\n\
         export function getPlatformClaimMode(platformId: string) { return 'assisted'; }\n\
         export function isPlatformCacheEligible(platformId: string) { return false; }\n\
         export function getPlatformSetupObjective(platformId: string) { return 'create_account'; }\n\
         export function getPlatformSetupLabel(platformId: string) { return 'Create Account'; }\n\
         export function getPlatformSetupTasks(platformId: string) { return []; }\n\
         export function isStrictFillPlatform(platformId: string) { return false; }\n\
         export function getPlatformDisplayName(platformId: string) { return platformId; }\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

fn populate_contract_type_repo(root: &Path) {
    write_file(
        root,
        ".env",
        "SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT=http://127.0.0.1:0\nSNIFF_MODEL=test-model\n",
    );
    write_file(
        root,
        "ui/background/core/session-runtime-contracts.ts",
        "export type LoggerMethod = (...args: unknown[]) => void;\n\
         export type SessionPolicy = 'aggressive_clean' | 'preserve_login';\n\
         export interface PlatformConfig {\n\
           signupUrl?: string;\n\
           checkUrl?: string;\n\
         }\n",
    );
    write_file(root, "src/sloppy.py", &python_slop_module("sloppy"));
}

#[path = "dogfood/brandset.rs"]
mod brandset;
#[path = "dogfood/bumpkin_github.rs"]
mod bumpkin_github;
#[path = "dogfood/bumpkin_release.rs"]
mod bumpkin_release;
#[path = "dogfood/contracts.rs"]
mod contracts;
#[path = "dogfood/core.rs"]
mod core;
#[path = "dogfood/surfaces.rs"]
mod surfaces;
