use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

enum ProviderAction {
    Json(String),
    Status(u16, String),
    Disconnect,
    Stall,
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut expected_total = None;
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if expected_total.is_none()
            && let Some(header_offset) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let header_end = header_offset + 4;
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
            expected_total = Some(header_end + content_length);
        }
        if expected_total.is_some_and(|expected| request.len() >= expected) {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn spawn_provider(
    actions: Vec<ProviderAction>,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local provider");
    let address = listener.local_addr().expect("local provider address");
    let hits = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_hits = Arc::clone(&hits);
    let server_requests = Arc::clone(&requests);

    thread::spawn(move || {
        for action in actions {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            server_hits.fetch_add(1, Ordering::SeqCst);
            let requests = Arc::clone(&server_requests);
            thread::spawn(move || {
                let request = read_http_request(&mut stream);
                requests.lock().expect("request log").push(request);
                match action {
                    ProviderAction::Json(body) => {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    ProviderAction::Status(status, body) => {
                        let response = format!(
                            "HTTP/1.1 {status} ERROR\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    ProviderAction::Disconnect => {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    ProviderAction::Stall => {
                        thread::sleep(Duration::from_secs(5));
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }
            });
        }
    });

    (format!("http://{address}"), hits, requests)
}

fn method_fixture() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should follow the Unix epoch")
        .as_nanos();
    let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "sniff-durable-runtime-{}-{nonce}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("src")).expect("fixture source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"durable-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(
        root.join("src/main.rs"),
        "pub fn first() -> i32 {\n    1\n}\n\npub fn second() -> i32 {\n    2\n}\n",
    )
    .expect("fixture source");
    root
}

fn openai_response(content: serde_json::Value) -> String {
    serde_json::json!({
        "choices": [{"message": {"content": content.to_string()}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 1}
    })
    .to_string()
}

fn intent_response() -> String {
    openai_response(serde_json::json!({
        "reviews": [{
            "method_key": "m0",
            "intent": "Return the method's declared value.",
            "contract_status": "required",
            "necessity_check": "The direct return implements the declared contract.",
            "missing_evidence": []
        }]
    }))
}

fn clean_response() -> String {
    openai_response(serde_json::json!({
        "reviews": [{
            "method_key": "m0",
            "tier": "clean",
            "reason": "The direct return contains no unnecessary machinery."
        }]
    }))
}

fn spawn_sniff(root: &Path, endpoint: &str, resume: bool) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sniff"));
    command
        .args(["--skip-dotenv", "--yes"])
        .env("SNIFF_API_KEY", "offline-test-key")
        .env("SNIFF_ENDPOINT", endpoint)
        .env("SNIFF_MODEL", "offline-test-model")
        .env("SNIFF_LLM_MAX_ATTEMPTS", "1")
        .env("SNIFF_LLM_RETRY_BUDGET_SECS", "1")
        .env("SNIFF_LLM_REQUEST_TIMEOUT_SECS", "10")
        .env("SNIFF_LLM_MAX_CONCURRENCY", "1")
        .env("SNIFF_LLM_METHOD_BATCH_SIZE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if resume {
        command.arg("resume");
    }
    command
        .arg(root)
        .spawn()
        .expect("sniff process should start")
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("condition was not met within {timeout:?}");
}

fn completed_method_units(journal: &Path) -> usize {
    std::fs::read_to_string(journal)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| {
            entry["stage"] == "method"
                && entry["is_manifest"] == false
                && entry["status"] == "completed"
        })
        .count()
}

fn wait_for_output(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("inspect sniff process") {
            Some(_) => return child.wait_with_output().expect("collect sniff output"),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            None => {
                let _ = child.kill();
                let output = child.wait_with_output().expect("collect timed-out output");
                panic!("sniff process timed out: {output:?}");
            }
        }
    }
}

fn assert_method_transport_failure_resumes(failure: ProviderAction, expected_error: &str) {
    let root = method_fixture();
    let journal = root.join(".sniff-journal.jsonl");
    let (endpoint, hits, requests) = spawn_provider(vec![
        ProviderAction::Json(intent_response()),
        ProviderAction::Json(clean_response()),
        failure,
        ProviderAction::Json(intent_response()),
        ProviderAction::Json(clean_response()),
    ]);

    let interrupted = wait_for_output(
        spawn_sniff(&root, &endpoint, false),
        Duration::from_secs(20),
    );
    assert!(!interrupted.status.success(), "{interrupted:?}");
    assert!(
        String::from_utf8_lossy(&interrupted.stderr).contains(expected_error),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&interrupted.stdout),
        String::from_utf8_lossy(&interrupted.stderr)
    );
    assert_eq!(completed_method_units(&journal), 1);
    assert!(!root.join("sniff-report.md").exists());

    let resumed = wait_for_output(spawn_sniff(&root, &endpoint, true), Duration::from_secs(20));
    assert!(
        resumed.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(completed_method_units(&journal), 2);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        5,
        "resume repeated a completed method; requests={:?}",
        requests.lock().expect("request log")
    );

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn http_402_resumes_without_repeating_completed_method() {
    assert_method_transport_failure_resumes(
        ProviderAction::Status(402, r#"{"error":"insufficient balance"}"#.to_string()),
        "HTTP 402",
    );
}

#[test]
fn network_loss_resumes_without_repeating_completed_method() {
    assert_method_transport_failure_resumes(ProviderAction::Disconnect, "error sending request");
}

#[test]
fn forced_process_termination_resumes_without_repeating_completed_method() {
    let root = method_fixture();
    let journal = root.join(".sniff-journal.jsonl");
    let (endpoint, hits, requests) = spawn_provider(vec![
        ProviderAction::Json(intent_response()),
        ProviderAction::Json(clean_response()),
        ProviderAction::Stall,
        ProviderAction::Json(intent_response()),
        ProviderAction::Json(clean_response()),
    ]);

    let mut interrupted = spawn_sniff(&root, &endpoint, false);
    wait_until(Duration::from_secs(15), || {
        completed_method_units(&journal) == 1 && hits.load(Ordering::SeqCst) >= 3
    });
    interrupted.kill().expect("force terminate sniff");
    interrupted.wait().expect("reap terminated sniff process");

    assert_eq!(completed_method_units(&journal), 1);
    assert!(!root.join("sniff-report.md").exists());

    let resumed = wait_for_output(spawn_sniff(&root, &endpoint, true), Duration::from_secs(20));
    assert!(
        resumed.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(completed_method_units(&journal), 2);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        5,
        "resume repeated a completed method; requests={:?}",
        requests.lock().expect("request log")
    );
    assert!(root.join("sniff-report.md").exists());

    std::fs::remove_dir_all(root).ok();
}
