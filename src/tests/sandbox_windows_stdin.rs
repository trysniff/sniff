use super::{DEFAULT_MEMORY_LIMIT, DEFAULT_PROCESS_LIMIT, SandboxCommand};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_CHAR, FILE_TYPE_PIPE, GetFileType};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

#[path = "sandbox_windows_stdin_caller.rs"]
mod caller;

const CHILD_ENV: &str = "SNIFF_NATIVE_STDIN_FIXTURE";
const TEST_NAME: &str =
    "sandbox::windows_stdin_tests::native_child_and_grandchild_receive_eof_input";

fn assert_eof_input() {
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    assert!(!input.is_null(), "sandboxed stdin must not be null");
    assert_ne!(input, INVALID_HANDLE_VALUE, "sandboxed stdin must be valid");
    let kind = unsafe { GetFileType(input) };
    assert!(matches!(kind, FILE_TYPE_PIPE | FILE_TYPE_CHAR));
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .expect("sandboxed stdin must yield EOF without a read error");
    assert!(bytes.is_empty(), "sandbox must not inherit caller input");
}

#[test]
fn native_child_and_grandchild_receive_eof_input() {
    if let Some(kind) = std::env::var_os(CHILD_ENV) {
        assert_eof_input();
        if kind == "child" {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([TEST_NAME, "--exact", "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, "grandchild")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("launch sandboxed grandchild with inherited EOF input");
            assert!(status.success(), "sandboxed grandchild failed");
        }
        println!("stdin-eof:{}", kind.to_string_lossy());
        return;
    }

    if caller::run_broker(TEST_NAME) {
        return;
    }
    let _caller_input = caller::CallerInput::open();
    let _guard = super::sandbox_test_resource_guard();
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("sniff-stdin-fixture.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &program).unwrap();
    let command = SandboxCommand {
        root: root.path().to_path_buf(),
        workdir: PathBuf::from("."),
        program: program.to_string_lossy().into_owned(),
        args: vec![
            TEST_NAME.to_string(),
            "--exact".to_string(),
            "--nocapture".to_string(),
            "--test-threads=1".to_string(),
        ],
        read_only_paths: Vec::new(),
        writable_paths: Vec::new(),
        persistent_read_only_paths: Vec::new(),
        persistent_executable_paths: Vec::new(),
        executable_paths: Vec::new(),
        windows_virtualized_paths: Vec::new(),
        env: vec![(CHILD_ENV.to_string(), "child".to_string())],
        allow_network: false,
        timeout: Duration::from_secs(15),
        output_limit: 16 * 1024,
        memory_limit: DEFAULT_MEMORY_LIMIT,
        process_limit: DEFAULT_PROCESS_LIMIT,
    };
    let output = super::run(&command).expect("launch native Windows input regression");
    assert!(
        !output.timed_out,
        "stdin probe timed out: stdout={:?} stderr={:?}",
        output.stdout, output.stderr
    );
    assert_eq!(
        output.status_code,
        Some(0),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(output.stdout.contains("stdin-eof:child"));
    assert!(output.stdout.contains("stdin-eof:grandchild"));
}

#[test]
#[ignore = "requires Go on PATH to build the trusted native Windows input probe"]
fn native_go_child_and_grandchild_receive_eof_input() {
    if caller::run_broker(
        "sandbox::windows_stdin_tests::native_go_child_and_grandchild_receive_eof_input",
    ) {
        return;
    }
    let _caller_input = caller::CallerInput::open();
    let _guard = super::sandbox_test_resource_guard();
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let source = root.path().join("probe.go");
    let program = root.path().join("sniff-go-stdin-probe.exe");
    std::fs::write(&source, GO_PROBE).unwrap();
    let mut build = Command::new("go");
    build
        .current_dir(root.path())
        .args(["build", "-p=1", "-mod=readonly", "-buildvcs=false", "-o"])
        .arg(&program)
        .arg(&source)
        .env("GOCACHE", cache.path())
        .env("CGO_ENABLED", "0")
        .env("GOWORK", "off")
        .env("GOTOOLCHAIN", "local")
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off");
    let compiled = crate::bounded_process::run(&mut build, Duration::from_secs(120))
        .expect("Go must be installed to compile the trusted input probe");
    assert!(
        !compiled.timed_out && compiled.status.success(),
        "Go input probe compilation failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let command = SandboxCommand {
        root: root.path().to_path_buf(),
        workdir: PathBuf::from("."),
        program: program.to_string_lossy().into_owned(),
        args: Vec::new(),
        read_only_paths: Vec::new(),
        writable_paths: Vec::new(),
        persistent_read_only_paths: Vec::new(),
        persistent_executable_paths: Vec::new(),
        executable_paths: Vec::new(),
        windows_virtualized_paths: Vec::new(),
        env: Vec::new(),
        allow_network: false,
        timeout: Duration::from_secs(15),
        output_limit: 16 * 1024,
        memory_limit: DEFAULT_MEMORY_LIMIT,
        process_limit: DEFAULT_PROCESS_LIMIT,
    };
    let output = super::run(&command).expect("launch real Go input probe in AppContainer");
    assert!(
        !output.timed_out,
        "Go input probe timed out: stdout={:?} stderr={:?}",
        output.stdout, output.stderr
    );
    assert_eq!(
        output.status_code,
        Some(0),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(output.stdout.contains("stdin-eof:go-child"));
    assert!(output.stdout.contains("stdin-eof:go-grandchild"));
}

const GO_PROBE: &str = r#"package main

import (
    "fmt"
    "io"
    "os"
    "os/exec"
)

func main() {
    fmt.Fprintln(os.Stderr, "probe:before-stdin")
    data, err := io.ReadAll(os.Stdin)
    if err != nil || len(data) != 0 {
        fmt.Fprintf(os.Stderr, "invalid empty stdin: length=%d error=%v\n", len(data), err)
        os.Exit(2)
    }
    fmt.Fprintln(os.Stderr, "probe:after-stdin")
    if len(os.Args) > 1 {
        fmt.Println("stdin-eof:go-grandchild")
        return
    }
    child := exec.Command(os.Args[0], "grandchild")
    child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
    fmt.Fprintln(os.Stderr, "probe:before-grandchild")
    if err := child.Run(); err != nil {
        fmt.Fprintln(os.Stderr, "grandchild failed:", err)
        os.Exit(3)
    }
    fmt.Println("stdin-eof:go-child")
}
"#;
