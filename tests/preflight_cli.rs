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
fn doctor_without_probe_succeeds_with_an_unreachable_provider() {
    let root = fixture();
    let output = run_sniff(&[
        "--skip-dotenv",
        "doctor",
        root.to_str().expect("UTF-8 fixture path"),
    ]);
    std::fs::remove_dir_all(&root).ok();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[skip] provider probe"), "{stdout}");
    assert!(
        stdout.contains("Doctor passed. No LLM request was made."),
        "{stdout}"
    );
}
