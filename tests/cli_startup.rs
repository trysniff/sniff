use std::process::{Command, Output};
use tempfile::TempDir;

fn invoke(args: &[&str]) -> (TempDir, Output) {
    let root = TempDir::with_prefix("sniff-cli-startup-").unwrap();
    let output = command(&root, args).output().expect("real CLI must start");
    assert!(
        std::fs::read_dir(root.path()).unwrap().next().is_none(),
        "startup-only commands must not create scan artifacts"
    );
    (root, output)
}

fn command(root: &TempDir, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sniff"));
    command.current_dir(root.path()).args(args);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SNIFF_") {
            command.env_remove(key);
        }
    }
    command
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).unwrap()
}

#[test]
fn help_exits_before_banner_and_configuration() {
    let (_root, output) = invoke(&["--help"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("Usage: sniff"));
    assert!(stdout.contains("--budget-usd"));
    assert!(stdout.contains("resume"));
    assert!(output.stderr.is_empty());
}

#[test]
fn version_uses_the_package_version_without_banner() {
    let (_root, output) = invoke(&["--version"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        std::str::from_utf8(&output.stdout).unwrap().trim(),
        concat!("sniff ", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn nested_help_parses_the_complete_command_graph() {
    let (_root, output) = invoke(&["benchmark", "historical-v3", "--help"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_sniff"))
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    assert!(stdout.contains(&format!("Usage: {binary} benchmark historical-v3")));
    assert!(stdout.contains("status"));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_argument_retains_clap_exit_two_without_banner() {
    let (_root, output) = invoke(&["--not-a-sniff-option"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unexpected argument"));
    assert!(!stderr(&output).contains(r"\|_________|"));
}

#[test]
fn dispatch_error_retains_fatal_exit_two_and_banner() {
    let (_root, output) = invoke(&["--estimate", "doctor"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("Fatal error: --estimate cannot be combined with a subcommand"));
    assert_eq!(stderr.matches(r"\|_________|").count(), 1);
}

#[test]
fn offline_status_uses_library_dispatch_and_keeps_banner() {
    let (_root, output) = invoke(&["status", "."]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let stderr = stderr(&output);
    assert!(stderr.contains("No Sniff journal found for ."));
    assert_eq!(stderr.matches(r"\|_________|").count(), 1);
    assert!(output.stdout.is_empty());
}

#[test]
fn offline_status_does_not_load_invalid_scan_configuration() {
    let root = TempDir::with_prefix("sniff-cli-status-invalid-config-").unwrap();
    let config = root.path().join("sniff.config.toml");
    std::fs::write(&config, b"this is deliberately invalid TOML [[[\n").unwrap();
    let output = command(&root, &["status", "."])
        .output()
        .expect("real CLI must start");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains("No Sniff journal found for ."));
    assert_eq!(
        std::fs::read(&config).unwrap(),
        b"this is deliberately invalid TOML [[[\n"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
