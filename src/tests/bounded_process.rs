use super::*;

const CHILD_MODE: &str = "SNIFF_BOUNDED_PROCESS_TEST_CHILD";

fn native_child(mode: &str) -> Command {
    let module = module_path!().split_once("::").unwrap().1;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &format!("{module}::native_process_fixture"),
            "--nocapture",
        ])
        .env(CHILD_MODE, mode);
    #[cfg(windows)]
    command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    command
}

#[test]
fn native_process_fixture() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    match mode.as_str() {
        "echo" => {
            io::stderr().write_all(&vec![b'e'; 512 * 1024]).unwrap();
            io::copy(&mut io::stdin().lock(), &mut io::stdout().lock()).unwrap();
        }
        "blocked" => {
            io::stderr().write_all(b"waiting-for-deadline").unwrap();
            thread::sleep(Duration::from_secs(60));
        }
        "descendant" => {
            let mut child = native_child("blocked")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            writeln!(io::stderr(), "{}", child.id()).unwrap();
            io::stderr().flush().unwrap();
            child.wait().unwrap();
        }
        "close" => {}
        _ => panic!("unknown bounded-process fixture mode"),
    }
    io::stdout().flush().unwrap();
    io::stderr().flush().unwrap();
    std::process::exit(0);
}

#[test]
fn explicit_output_limit_reports_truncation() {
    #[cfg(windows)]
    let mut command = {
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot should be defined");
        let mut command = Command::new(
            std::path::PathBuf::from(system_root)
                .join("System32")
                .join("cmd.exe"),
        );
        // Emit without a newline or PowerShell startup; EOF makes set /p fail.
        command.args(["/d", "/c", "<nul set /p =0123456789&exit /b 0"]);
        command
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 0123456789"]);
        command
    };

    let output = run_with_output_limit(&mut command, Duration::from_secs(5), 4).unwrap();
    assert!(
        !output.timed_out,
        "output fixture timed out: status={}, stderr={:?}",
        output.status, output.stderr
    );
    assert!(
        output.status.success(),
        "output fixture failed: status={}, stderr={:?}",
        output.status,
        output.stderr
    );
    assert_eq!(output.stdout, b"0123");
    assert_eq!(output.stdout_byte_count, 10);
    assert_eq!(output.stderr_byte_count, 0);
    assert_eq!(
        output.stdout_sha256,
        "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882"
    );
    assert_eq!(
        output.stderr_sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(output.stdout_truncated);
    assert!(!output.stderr_truncated);
}

#[test]
fn bounded_input_is_written_without_deadlocking_large_output() {
    let input = vec![b'x'; 2 * 1024 * 1024];
    let output = run_with_input_and_output_limit(
        &mut native_child("echo"),
        &input,
        Duration::from_secs(10),
        input.len() + 1024,
    )
    .unwrap();
    assert!(output.status.success());
    assert!(!output.timed_out);
    // The native Rust test harness writes its preamble before entering the fixture.
    assert!(output.stdout.ends_with(&input));
    assert_eq!(output.stderr, vec![b'e'; 512 * 1024]);
    assert!(!output.stdout_truncated);
    assert!(!output.stderr_truncated);
}

#[test]
fn deadline_with_blocked_stdin_retains_process_evidence() {
    let output = run_with_input_and_output_limit(
        &mut native_child("blocked"),
        &vec![b'x'; 2 * 1024 * 1024],
        Duration::from_secs(10),
        1024,
    )
    .unwrap();
    assert!(output.timed_out);
    assert!(!output.status.success());
    assert_eq!(output.stderr, b"waiting-for-deadline");
    assert_eq!(output.stderr_byte_count, output.stderr.len() as u64);
    assert_eq!(
        output.stderr_sha256,
        format!("{:x}", Sha256::digest(&output.stderr))
    );
    assert!(!output.stderr_truncated);
}

#[test]
fn early_stdin_close_without_timeout_remains_an_error() {
    let error = run_with_input_and_output_limit(
        &mut native_child("close"),
        &vec![b'x'; 2 * 1024 * 1024],
        Duration::from_secs(10),
        1024,
    )
    .err()
    .expect("an incomplete stdin write must not become successful output");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn deadline_terminates_the_complete_child_tree() {
    #[cfg(windows)]
    let mut command = native_child("descendant");
    #[cfg(unix)]
    let (mut command, survivor_marker) = {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("descendant-survived");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("(sleep 30; printf survived > \"$1\") & echo $!; wait")
            .arg("bounded-process-test")
            .arg(&marker);
        (command, (directory, marker))
    };
    let output = run(&mut command, Duration::from_secs(10)).unwrap();
    assert!(output.timed_out);
    #[cfg(windows)]
    let pid_output = output.stderr;
    #[cfg(unix)]
    let pid_output = output.stdout;
    let descendant = String::from_utf8(pid_output)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    #[cfg(windows)]
    {
        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "if(Get-Process -Id {descendant} -ErrorAction SilentlyContinue){{exit 1}}"
                ),
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }
    #[cfg(unix)]
    {
        let _ = descendant;
        thread::sleep(Duration::from_millis(1_200));
        assert!(!survivor_marker.1.exists());
    }
}
