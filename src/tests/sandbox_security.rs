use super::{DEFAULT_MEMORY_LIMIT, DEFAULT_PROCESS_LIMIT, SandboxCommand, run};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const HOST_SECRET_ENV: &str = "SNIFF_TEST_HOST_SECRET_DO_NOT_EXPOSE";
const HOST_SECRET_VALUE: &str = "sniff-host-secret-evidence";

#[cfg(windows)]
const JAVA_REAL_PATH_PROBE: &str = r#"
import java.nio.file.Files;
import java.nio.file.Path;

public final class SniffRealPathProbe {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]);
        Path temporary = root.resolve(".tmp/download.jar");
        Path artifact = root.resolve("cache/group/artifact.jar");
        Files.createDirectories(temporary.getParent());
        Files.createDirectories(artifact.getParent());
        Files.writeString(temporary, "sandbox path probe");
        Files.move(temporary, artifact);
        System.out.println(artifact.toRealPath());
    }
}
"#;

const MALICIOUS_WORKER: &str = r#"
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("inspect") => {
            let secret_path = args.next().expect("missing secret path");
            let outside_path = args.next().expect("missing outside path");
            let address: SocketAddr = args.next().expect("missing address").parse().unwrap();
            println!(
                "env={}",
                std::env::var("SNIFF_TEST_HOST_SECRET_DO_NOT_EXPOSE")
                    .unwrap_or_else(|_| "denied".to_string())
            );
            println!(
                "read={}",
                std::fs::read_to_string(secret_path)
                    .unwrap_or_else(|_| "denied".to_string())
            );
            println!(
                "write={}",
                if std::fs::write(outside_path, "escaped").is_ok() {
                    "allowed"
                } else {
                    "denied"
                }
            );
            println!(
                "network={}",
                if TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok() {
                    "allowed"
                } else {
                    "denied"
                }
            );
        }
        Some("flood") => {
            print!("{}", "x".repeat(16 * 1024));
            eprint!("{}", "y".repeat(16 * 1024));
            io::stdout().flush().unwrap();
            io::stderr().flush().unwrap();
        }
        Some("sleep") => std::thread::sleep(Duration::from_secs(30)),
        Some("memory") => {
            let mut chunks = Vec::new();
            for _ in 0..32 {
                let mut chunk = vec![0_u8; 16 * 1024 * 1024];
                for index in (0..chunk.len()).step_by(4096) {
                    chunk[index] = 1;
                }
                chunks.push(chunk);
            }
            println!("memory-limit-bypassed={}", chunks.len());
        }
        Some("fanout") => {
            let executable = std::env::current_exe().unwrap();
            let mut children = Vec::new();
            for _ in 0..24 {
                if let Ok(child) = Command::new(&executable)
                    .arg("child")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    children.push(child);
                }
            }
            println!("spawned={}", children.len());
            for child in &mut children {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        Some("child") => std::thread::sleep(Duration::from_secs(10)),
        _ => panic!("unknown malicious-worker mode"),
    }
}
"#;

fn compile_worker(root: &Path) -> PathBuf {
    let source = root.join("malicious-worker.rs");
    let executable = root.join(if cfg!(windows) {
        "malicious-worker.exe"
    } else {
        "malicious-worker"
    });
    std::fs::write(&source, MALICIOUS_WORKER).expect("write malicious worker source");
    let output = Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile malicious worker");
    assert!(
        output.status.success(),
        "malicious worker failed to compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

fn command(root: &Path, program: &Path, args: Vec<String>) -> SandboxCommand {
    SandboxCommand {
        root: root.to_path_buf(),
        workdir: PathBuf::from("."),
        program: program.to_string_lossy().into_owned(),
        args,
        read_only_paths: Vec::new(),
        writable_paths: Vec::new(),
        persistent_read_only_paths: Vec::new(),
        executable_paths: Vec::new(),
        virtualize_windows_root: false,
        env: Vec::new(),
        allow_network: false,
        #[cfg(target_os = "macos")]
        allow_local_network: false,
        timeout: Duration::from_secs(5),
        output_limit: 1024,
        memory_limit: DEFAULT_MEMORY_LIMIT,
        process_limit: DEFAULT_PROCESS_LIMIT,
    }
}

#[cfg(windows)]
fn compile_java_real_path_probe(root: &Path) -> (PathBuf, PathBuf) {
    let source = root.join("SniffRealPathProbe.java");
    std::fs::write(&source, JAVA_REAL_PATH_PROBE).expect("write Java path probe");
    let settings = Command::new("java")
        .args(["-XshowSettings:properties", "-version"])
        .output()
        .expect("inspect Java runtime");
    assert!(settings.status.success(), "Java runtime inspection failed");
    let diagnostics = String::from_utf8_lossy(&settings.stderr);
    let java_home = diagnostics
        .lines()
        .find_map(|line| line.trim().strip_prefix("java.home = "))
        .map(PathBuf::from)
        .expect("Java runtime did not report java.home");
    let javac = java_home.join("bin/javac.exe");
    let output = Command::new(&javac)
        .args(["-d", root.to_str().unwrap(), source.to_str().unwrap()])
        .output()
        .expect("compile Java path probe");
    assert!(
        output.status.success(),
        "Java path probe failed to compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runtime = root.join("java-runtime");
    let output = Command::new(java_home.join("bin/jlink.exe"))
        .args([
            "--add-modules",
            "java.base",
            "--output",
            runtime.to_str().unwrap(),
        ])
        .output()
        .expect("create minimal Java path-probe runtime");
    assert!(
        output.status.success(),
        "minimal Java path-probe runtime failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (runtime.join("bin/java.exe"), runtime)
}

#[cfg(windows)]
fn java_runtime_images(java_home: &Path) -> Vec<PathBuf> {
    let mut images = Vec::new();
    let mut pending = vec![java_home.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("inspect Java runtime") {
            let path = entry.expect("enumerate Java runtime").path();
            let metadata = std::fs::symlink_metadata(&path).expect("inspect Java runtime entry");
            assert!(
                !metadata.file_type().is_symlink(),
                "Java runtime must not contain symlinks: {}",
                path.display()
            );
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.extension().is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("dll")
                })
            {
                images.push(path);
            }
        }
    }
    images
}

#[cfg(windows)]
#[test]
fn windows_java_can_resolve_a_moved_sandbox_artifact() {
    let repository = tempfile::tempdir().expect("create Java path-probe repository");
    let (java, java_runtime) = compile_java_real_path_probe(repository.path());
    let mut spec = command(
        repository.path(),
        &java,
        vec![
            "-cp".to_string(),
            repository.path().to_string_lossy().into_owned(),
            "SniffRealPathProbe".to_string(),
            repository.path().to_string_lossy().into_owned(),
        ],
    );
    spec.executable_paths = java_runtime_images(&java_runtime);
    spec.virtualize_windows_root = true;

    let output = run(&spec).expect("Java path probe sandbox should start");

    assert_eq!(
        output.status_code,
        Some(0),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    let resolved = output.stdout.trim();
    assert!(resolved.ends_with(r"cache\group\artifact.jar"));
    let mapped_root = resolved
        .get(..3)
        .expect("mapped Java path has a drive root");
    assert!(
        !Path::new(mapped_root).exists(),
        "sandbox drive mapping survived process completion: {mapped_root}"
    );
}

#[test]
fn malicious_worker_cannot_reach_host_secrets_filesystem_or_network() {
    let repository = tempfile::tempdir().expect("create malicious repository");
    let host = tempfile::tempdir().expect("create host-only directory");
    let secret_path = host.path().join("secret.txt");
    let outside_path = host.path().join("escaped.txt");
    std::fs::write(&secret_path, HOST_SECRET_VALUE).expect("write host-only secret");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local network target");
    listener
        .set_nonblocking(true)
        .expect("make local target nonblocking");
    let worker = compile_worker(repository.path());
    let spec = command(
        repository.path(),
        &worker,
        vec![
            "inspect".to_string(),
            secret_path.to_string_lossy().into_owned(),
            outside_path.to_string_lossy().into_owned(),
            listener.local_addr().unwrap().to_string(),
        ],
    );

    // The worker environment is reconstructed from an allowlist, never inherited.
    unsafe { std::env::set_var(HOST_SECRET_ENV, HOST_SECRET_VALUE) };
    let output = run(&spec).expect("hardened sandbox should start");
    unsafe { std::env::remove_var(HOST_SECRET_ENV) };

    assert_eq!(
        output.status_code,
        Some(0),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(output.stdout.contains("env=denied"));
    assert!(output.stdout.contains("read=denied"));
    assert!(output.stdout.contains("write=denied"));
    assert!(output.stdout.contains("network=denied"));
    assert!(!output.stdout.contains(HOST_SECRET_VALUE));
    assert!(
        !outside_path.exists(),
        "worker wrote outside its repository"
    );
    assert!(
        listener.accept().is_err(),
        "worker reached a host-local network listener"
    );
}

#[test]
fn network_enabled_preparation_still_cannot_reach_host_secrets_or_filesystem() {
    let preparation = tempfile::tempdir().expect("create dependency-preparation root");
    let host = tempfile::tempdir().expect("create host-only directory");
    let secret_path = host.path().join("secret.txt");
    let outside_path = host.path().join("escaped.txt");
    std::fs::write(&secret_path, HOST_SECRET_VALUE).expect("write host-only secret");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local network target");
    let worker = compile_worker(preparation.path());
    let mut spec = command(
        preparation.path(),
        &worker,
        vec![
            "inspect".to_string(),
            secret_path.to_string_lossy().into_owned(),
            outside_path.to_string_lossy().into_owned(),
            listener.local_addr().unwrap().to_string(),
        ],
    );
    spec.allow_network = true;

    unsafe { std::env::set_var(HOST_SECRET_ENV, HOST_SECRET_VALUE) };
    let output = run(&spec).expect("network-enabled hardened sandbox should start");
    unsafe { std::env::remove_var(HOST_SECRET_ENV) };

    assert_eq!(
        output.status_code,
        Some(0),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(output.stdout.contains("env=denied"));
    assert!(output.stdout.contains("read=denied"));
    assert!(output.stdout.contains("write=denied"));
    assert!(!output.stdout.contains(HOST_SECRET_VALUE));
    assert!(!outside_path.exists());
}

#[test]
fn malicious_worker_output_is_bounded_on_both_streams() {
    let repository = tempfile::tempdir().expect("create malicious repository");
    let worker = compile_worker(repository.path());
    let mut spec = command(repository.path(), &worker, vec!["flood".to_string()]);
    spec.output_limit = 128;

    let output = run(&spec).expect("hardened sandbox should start");

    assert_eq!(output.status_code, Some(0));
    for stream in [&output.stdout, &output.stderr] {
        assert!(stream.contains("[output truncated by Sniff]"));
        assert!(stream.len() <= 160, "retained too much worker output");
    }
}

#[test]
fn malicious_worker_is_terminated_at_the_time_limit() {
    let repository = tempfile::tempdir().expect("create malicious repository");
    let worker = compile_worker(repository.path());
    let mut spec = command(repository.path(), &worker, vec!["sleep".to_string()]);
    spec.timeout = Duration::from_millis(100);

    let output = run(&spec).expect("hardened sandbox should start");

    assert!(output.timed_out);
    assert_ne!(output.status_code, Some(0));
}

#[test]
fn malicious_worker_cannot_exceed_its_memory_limit() {
    let repository = tempfile::tempdir().expect("create malicious repository");
    let worker = compile_worker(repository.path());
    let mut spec = command(repository.path(), &worker, vec!["memory".to_string()]);
    spec.memory_limit = 256 * 1024 * 1024;

    let output = run(&spec).expect("hardened sandbox should start");

    assert_ne!(
        output.status_code,
        Some(0),
        "worker bypassed its memory cap: stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(!output.stdout.contains("memory-limit-bypassed"));
    #[cfg(target_os = "macos")]
    assert!(
        output.stderr.contains("physical memory limit was exceeded"),
        "macOS memory monitor did not report enforcement: {:?}",
        output.stderr
    );
}

#[test]
fn malicious_worker_child_fanout_is_bounded() {
    let repository = tempfile::tempdir().expect("create malicious repository");
    let worker = compile_worker(repository.path());
    let mut spec = command(repository.path(), &worker, vec!["fanout".to_string()]);
    spec.process_limit = 8;

    let output = run(&spec).expect("hardened sandbox should start");

    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        output.status_code,
        Some(0),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    #[cfg(target_os = "macos")]
    if output.status_code != Some(0) {
        assert!(
            output.stderr.contains("process limit was exceeded"),
            "macOS process monitor did not report enforcement: {:?}",
            output.stderr
        );
        return;
    }
    let spawned = output
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("spawned="))
        .and_then(|value| value.parse::<usize>().ok())
        .expect("worker should report its bounded child count");
    assert!(spawned <= 7, "sandbox admitted {spawned} child processes");
}
