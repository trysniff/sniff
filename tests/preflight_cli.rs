use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixture() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should follow the Unix epoch")
        .as_nanos();
    let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let process = std::process::id();
    let root = std::env::temp_dir().join(format!("sniff-offline-cli-{process}-{nonce}-{sequence}"));
    std::fs::create_dir_all(&root).expect("fixture directory");
    std::fs::write(
        root.join("example.py"),
        "def greet(name: str) -> str:\n    return f\"Hello, {name}\"\n",
    )
    .expect("fixture source");
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"sniff-offline-cli\"\nversion = \"0.1.0\"\n",
    )
    .expect("fixture project metadata");
    let git = std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&root)
        .output()
        .expect("git must be available for compiler fixtures");
    assert!(git.status.success(), "git init failed: {:?}", git);
    let commit = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=Sniff Tests",
            "-c",
            "user.email=sniff-tests@example.invalid",
            "add",
            ".",
        ])
        .current_dir(&root)
        .output()
        .expect("git add must be available for compiler fixtures");
    assert!(commit.status.success(), "git add failed: {:?}", commit);
    let commit = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=Sniff Tests",
            "-c",
            "user.email=sniff-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ])
        .current_dir(&root)
        .output()
        .expect("git commit must be available for compiler fixtures");
    assert!(commit.status.success(), "git commit failed: {:?}", commit);
    root
}

fn run_sniff(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sniff"))
        .args(arguments)
        .env("SNIFF_API_KEY", "offline-test-key")
        .env("SNIFF_ENDPOINT", "http://127.0.0.1:9")
        .env("SNIFF_MODEL", "offline-test-model")
        .output()
        .expect("sniff process should start")
}

fn run_sniff_with_cache(arguments: &[&str], cache: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sniff"))
        .args(arguments)
        .env("SNIFF_CACHE_DIR", cache)
        .env("SNIFF_API_KEY", "offline-test-key")
        .env("SNIFF_ENDPOINT", "http://127.0.0.1:9")
        .env("SNIFF_MODEL", "offline-test-model")
        .output()
        .expect("sniff process should start")
}

fn run_sniff_without_provider(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sniff"))
        .args(arguments)
        .env_remove("SNIFF_API_KEY")
        .env_remove("SNIFF_ENDPOINT")
        .env_remove("SNIFF_MODEL")
        .output()
        .expect("sniff process should start")
}

#[test]
fn estimate_succeeds_with_an_unreachable_provider() {
    let root = fixture();
    let output = run_sniff(&[
        "--skip-dotenv",
        "--estimate",
        root.to_str().expect("UTF-8 fixture path"),
    ]);
    std::fs::remove_dir_all(&root).ok();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no LLM requests were made"), "{stdout}");
    assert!(stdout.contains("methods: 1"), "{stdout}");
}

#[test]
fn doctor_without_probe_reports_missing_semantic_indexer_without_calling_provider() {
    let root = fixture();
    let output = run_sniff_with_cache(
        &[
            "--skip-dotenv",
            "doctor",
            root.to_str().expect("UTF-8 fixture path"),
        ],
        &root.join("missing-cache"),
    );
    std::fs::remove_dir_all(&root).ok();

    assert!(!output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[skip] provider probe"), "{stdout}");
    assert!(stdout.contains("[fail] semantic indexers"), "{stdout}");
    assert!(!stdout.contains("[paid] provider probe"), "{stdout}");
}

#[test]
fn status_reads_a_journal_without_provider_configuration() {
    let root = fixture();
    let journal = serde_json::json!({
        "version": 2,
        "scan_id": "scan",
        "stage": "method",
        "unit_id": "example.py::greet",
        "expected_units": 2,
        "source_hash": "source",
        "semantic_index_hash": "semantic",
        "prompt_contract_version": "test",
        "provider": "openai-compatible",
        "model": "offline-test-model",
        "endpoint": "https://example.invalid",
        "review_context_hash": "context",
        "status": "completed",
        "verdict": null,
        "in_tok": 10,
        "out_tok": 2,
        "cached_in_tok": 4,
        "estimated_cost_usd": 0.001,
        "timestamp_unix_ms": 1,
        "proof_level": "not_applicable",
        "retry_on_resume": false
    });
    std::fs::write(root.join(".sniff-journal.jsonl"), format!("{journal}\n"))
        .expect("journal fixture");

    let output = run_sniff_without_provider(&[
        "--skip-dotenv",
        "status",
        root.to_str().expect("UTF-8 fixture path"),
    ]);
    std::fs::remove_dir_all(&root).ok();

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Progress: 1/2 completed (50.0%)"),
        "{stderr}"
    );
    assert!(stderr.contains("Remaining: 1 (0 retryable)"), "{stderr}");
}

#[test]
fn resume_without_a_journal_fails_before_loading_provider_configuration() {
    let root = fixture();
    let output = run_sniff_without_provider(&[
        "--skip-dotenv",
        "resume",
        root.to_str().expect("UTF-8 fixture path"),
    ]);
    std::fs::remove_dir_all(&root).ok();

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No Sniff journal exists"), "{stderr}");
    assert!(!stderr.contains("SNIFF_API_KEY"), "{stderr}");
}

#[test]
fn zero_budget_creates_a_resumable_journal_without_reaching_the_provider() {
    let root = fixture();
    let output = run_sniff(&[
        "--skip-dotenv",
        "--yes",
        "--budget-usd",
        "0",
        root.to_str().expect("UTF-8 fixture path"),
    ]);

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Sniff budget pause:"), "{stderr}");
    assert!(!stderr.contains("connection refused"), "{stderr}");
    assert!(root.join(".sniff-journal.jsonl").exists());
    assert!(!root.join("sniff-report.md").exists());

    let status = run_sniff_without_provider(&[
        "--skip-dotenv",
        "status",
        root.to_str().expect("UTF-8 fixture path"),
    ]);
    std::fs::remove_dir_all(&root).ok();
    assert!(status.status.success(), "{status:?}");
    let status_stderr = String::from_utf8_lossy(&status.stderr);
    assert!(
        status_stderr.contains("Progress: 0/1 completed"),
        "{status_stderr}"
    );
}
