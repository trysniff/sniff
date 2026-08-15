use super::non_blind_history_runtime::{HistoricalRuntimePlanError, prepare_historical_runtime};
use super::{HistoricalTestResult, HistoricalTestStepResult};
use crate::sandbox::{SandboxError, SandboxOutput};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const RAW_RESULT_SCHEMA_VERSION: u32 = 1;
const CACHE_DIRECTORY: &str = ".sniff-benchmark-history-runtime";
const GIT_TIMEOUT: Duration = Duration::from_secs(60);
const GIT_OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalTestExecution {
    pub result: HistoricalTestResult,
    pub raw_result: Vec<u8>,
    pub bounded_sanitized_stdout: String,
    pub bounded_sanitized_stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalTestExecutionOutcome {
    Completed(Box<HistoricalTestExecution>),
    RuntimeUnavailable(String),
    SandboxUnavailable(String),
}

#[derive(Debug, Clone, Serialize)]
struct RawExecutionArtifact {
    schema_version: u32,
    revision: String,
    runtime_identity: String,
    network_enabled: bool,
    preparation: Vec<RawStepArtifact>,
    test: Option<RawStepArtifact>,
}

#[derive(Debug, Clone, Serialize)]
struct RawStepArtifact {
    stage: String,
    logical_command: Vec<String>,
    launcher_kind: String,
    status_code: Option<i32>,
    timed_out: bool,
    network_enabled: bool,
    stdout_complete_sha256: String,
    stderr_complete_sha256: String,
    stdout_bounded_sanitized: String,
    stderr_bounded_sanitized: String,
}

pub fn run_historical_test(
    snapshot_root: &Path,
    revision: &str,
    preparation_commands: &[Vec<String>],
    test_command: &[String],
) -> Result<HistoricalTestExecutionOutcome, String> {
    run_test_with_network_policy(
        snapshot_root,
        revision,
        preparation_commands,
        test_command,
        true,
    )
}

pub fn run_intentional_boundary_test(
    snapshot_root: &Path,
    revision: &str,
    preparation_commands: &[Vec<String>],
    test_command: &[String],
) -> Result<HistoricalTestExecutionOutcome, String> {
    run_test_with_network_policy(
        snapshot_root,
        revision,
        preparation_commands,
        test_command,
        false,
    )
}

fn run_test_with_network_policy(
    snapshot_root: &Path,
    revision: &str,
    preparation_commands: &[Vec<String>],
    test_command: &[String],
    allow_network: bool,
) -> Result<HistoricalTestExecutionOutcome, String> {
    require_revision(revision)?;
    let root = canonical_directory(snapshot_root, "historical test snapshot")?;
    verify_snapshot(&root, revision)?;
    let cache = initialize_private_cache(&root)?;
    let execution = run_historical_test_in_cache(
        &root,
        &cache,
        revision,
        preparation_commands,
        test_command,
        allow_network,
    );
    let integrity = verify_tracked_snapshot(&root, revision);
    match (execution, integrity) {
        (Ok(execution), Ok(())) => Ok(execution),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(execution), Err(integrity)) => Err(format!(
            "{execution}; additionally, historical snapshot integrity failed: {integrity}"
        )),
    }
}

fn run_historical_test_in_cache(
    root: &Path,
    cache: &Path,
    revision: &str,
    preparation_commands: &[Vec<String>],
    test_command: &[String],
    allow_network: bool,
) -> Result<HistoricalTestExecutionOutcome, String> {
    let mut raw_preparation = Vec::new();
    let mut preparation_results = Vec::new();
    let mut runtime_identity = None::<String>;

    for (index, command) in preparation_commands.iter().enumerate() {
        let stage = format!("preparation_{}", index + 1);
        let executed = match execute_step(root, cache, command, &stage, allow_network) {
            Ok(executed) => executed,
            Err(StepError::RuntimeUnavailable(reason)) if raw_preparation.is_empty() => {
                return Ok(HistoricalTestExecutionOutcome::RuntimeUnavailable(reason));
            }
            Err(StepError::SandboxUnavailable(reason)) if raw_preparation.is_empty() => {
                return Ok(HistoricalTestExecutionOutcome::SandboxUnavailable(reason));
            }
            Err(error) => return Err(error.into_message()),
        };
        bind_runtime_identity(&mut runtime_identity, &executed.runtime_identity)?;
        preparation_results.push(step_result(command, &executed.raw)?);
        let succeeded = !executed.raw.timed_out && executed.raw.status_code == Some(0);
        raw_preparation.push(executed.raw);
        if !succeeded {
            return completed_execution(
                revision,
                preparation_results,
                test_command,
                false,
                raw_preparation,
                None,
                runtime_identity,
            );
        }
    }

    let executed = match execute_step(root, cache, test_command, "test", allow_network) {
        Ok(executed) => executed,
        Err(StepError::RuntimeUnavailable(reason)) if raw_preparation.is_empty() => {
            return Ok(HistoricalTestExecutionOutcome::RuntimeUnavailable(reason));
        }
        Err(StepError::SandboxUnavailable(reason)) if raw_preparation.is_empty() => {
            return Ok(HistoricalTestExecutionOutcome::SandboxUnavailable(reason));
        }
        Err(error) => return Err(error.into_message()),
    };
    bind_runtime_identity(&mut runtime_identity, &executed.runtime_identity)?;
    completed_execution(
        revision,
        preparation_results,
        test_command,
        true,
        raw_preparation,
        Some(executed.raw),
        runtime_identity,
    )
}

struct ExecutedStep {
    runtime_identity: String,
    raw: RawStepArtifact,
}

enum StepError {
    RuntimeUnavailable(String),
    SandboxUnavailable(String),
    Invalid(String),
    Failed(String),
}

impl StepError {
    fn into_message(self) -> String {
        match self {
            Self::RuntimeUnavailable(message)
            | Self::SandboxUnavailable(message)
            | Self::Invalid(message)
            | Self::Failed(message) => message,
        }
    }
}

fn execute_step(
    root: &Path,
    cache: &Path,
    logical_command: &[String],
    stage: &str,
    allow_network: bool,
) -> Result<ExecutedStep, StepError> {
    let mut plan =
        prepare_historical_runtime(root, cache, logical_command).map_err(|error| match error {
            HistoricalRuntimePlanError::Unavailable(message) => {
                StepError::RuntimeUnavailable(message)
            }
            HistoricalRuntimePlanError::Invalid(message) => StepError::Invalid(message),
        })?;
    plan.command.allow_network = allow_network;
    #[cfg(target_os = "macos")]
    if !allow_network {
        plan.command.allow_local_network = false;
    }
    #[cfg(windows)]
    if logical_command
        .first()
        .is_some_and(|program| program == "cargo")
    {
        ensure_windows_cargo_runtime(root, cache, &plan.command)?;
    }
    let output = crate::sandbox::run(&plan.command).map_err(map_sandbox_error)?;
    Ok(ExecutedStep {
        runtime_identity: plan.runtime_identity,
        raw: raw_step(
            root,
            stage,
            logical_command,
            plan.launcher_kind,
            allow_network,
            output,
        ),
    })
}

fn map_sandbox_error(error: SandboxError) -> StepError {
    match error {
        SandboxError::Unavailable(message) => StepError::SandboxUnavailable(message),
        SandboxError::Invalid(message) => StepError::Invalid(message),
        SandboxError::Failed(message) => StepError::Failed(message),
    }
}

#[cfg(windows)]
fn ensure_windows_cargo_runtime(
    root: &Path,
    cache: &Path,
    command: &crate::sandbox::SandboxCommand,
) -> Result<(), StepError> {
    const MARKER_CONTENT: &str = "sniff-windows-cargo-preflight-v1\n";
    let marker = cache.join("windows-cargo-preflight.ok");
    if fs::read_to_string(&marker).is_ok_and(|contents| contents == MARKER_CONTENT) {
        return Ok(());
    }

    let probe = cache.join("windows-cargo-preflight");
    let source = probe.join("src");
    fs::create_dir_all(&source).map_err(|error| {
        StepError::Failed(format!("failed to create trusted Cargo preflight: {error}"))
    })?;
    fs::write(
        probe.join("Cargo.toml"),
        "[package]\nname = \"sniff-cargo-preflight\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .map_err(|error| {
        StepError::Failed(format!("failed to write trusted Cargo preflight manifest: {error}"))
    })?;
    fs::write(source.join("lib.rs"), "pub fn sniff_cargo_preflight() {}\n").map_err(|error| {
        StepError::Failed(format!("failed to write trusted Cargo preflight: {error}"))
    })?;

    let mut preflight = command.clone();
    preflight.args = vec![
        "check".to_string(),
        "--offline".to_string(),
        "--manifest-path".to_string(),
        probe.join("Cargo.toml").to_string_lossy().into_owned(),
    ];
    let output = crate::sandbox::run(&preflight).map_err(map_sandbox_error)?;
    if output.status_code == Some(0) && !output.timed_out {
        fs::write(&marker, MARKER_CONTENT).map_err(|error| {
            StepError::Failed(format!("failed to seal trusted Cargo preflight: {error}"))
        })?;
        return Ok(());
    }
    if windows_cargo_child_launch_denied(&output.stderr) {
        return Err(StepError::SandboxUnavailable(
            "Windows AppContainer denied Cargo's compiler child during Sniff's trusted preflight; run historical assessment on a supported Linux host"
                .to_string(),
        ));
    }
    Err(StepError::Failed(format!(
        "trusted Windows Cargo preflight failed: status={:?} timed_out={} stderr={}",
        output.status_code,
        output.timed_out,
        sanitize_output(root, &output.stderr)
    )))
}

#[cfg(any(windows, test))]
fn windows_cargo_child_launch_denied(stderr: &str) -> bool {
    stderr.contains("could not execute process")
        && stderr.contains("never executed")
        && stderr.contains("Access is denied. (os error 5)")
}

fn completed_execution(
    revision: &str,
    preparation_results: Vec<HistoricalTestStepResult>,
    test_command: &[String],
    test_executed: bool,
    raw_preparation: Vec<RawStepArtifact>,
    raw_test: Option<RawStepArtifact>,
    runtime_identity: Option<String>,
) -> Result<HistoricalTestExecutionOutcome, String> {
    let runtime_identity = runtime_identity
        .ok_or_else(|| "historical execution produced no runtime identity".to_string())?;
    let representative = raw_test
        .as_ref()
        .or_else(|| raw_preparation.last())
        .ok_or_else(|| "historical execution produced no process result".to_string())?;
    let network_enabled = representative.network_enabled;
    if raw_preparation
        .iter()
        .chain(raw_test.iter())
        .any(|step| step.network_enabled != network_enabled)
    {
        return Err("historical execution changed network policy between steps".to_string());
    }
    let status_code = raw_test.as_ref().and_then(|step| step.status_code);
    let timed_out = representative.timed_out;
    let stdout_sha256 = representative.stdout_complete_sha256.clone();
    let stderr_sha256 = representative.stderr_complete_sha256.clone();
    let bounded_sanitized_stdout = representative.stdout_bounded_sanitized.clone();
    let bounded_sanitized_stderr = representative.stderr_bounded_sanitized.clone();
    let artifact = RawExecutionArtifact {
        schema_version: RAW_RESULT_SCHEMA_VERSION,
        revision: revision.to_string(),
        runtime_identity: runtime_identity.clone(),
        network_enabled,
        preparation: raw_preparation,
        test: raw_test.clone(),
    };
    let mut raw_result = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| format!("failed to serialize historical test result: {error}"))?;
    raw_result.push(b'\n');
    let aggregate_sha256 = sha256(&raw_result);
    let result = HistoricalTestResult {
        revision: revision.to_string(),
        preparation_results,
        command: test_command.to_vec(),
        test_executed,
        runtime_identity,
        status_code,
        timed_out,
        network_enabled,
        stdout_sha256,
        stderr_sha256,
        raw_result_sha256: aggregate_sha256,
    };
    Ok(HistoricalTestExecutionOutcome::Completed(Box::new(
        HistoricalTestExecution {
            result,
            raw_result,
            bounded_sanitized_stdout,
            bounded_sanitized_stderr,
        },
    )))
}

fn step_result(
    command: &[String],
    raw: &RawStepArtifact,
) -> Result<HistoricalTestStepResult, String> {
    let mut bytes = serde_json::to_vec_pretty(raw)
        .map_err(|error| format!("failed to serialize historical preparation result: {error}"))?;
    bytes.push(b'\n');
    Ok(HistoricalTestStepResult {
        command: command.to_vec(),
        status_code: raw.status_code,
        timed_out: raw.timed_out,
        network_enabled: raw.network_enabled,
        stdout_sha256: raw.stdout_complete_sha256.clone(),
        stderr_sha256: raw.stderr_complete_sha256.clone(),
        raw_result_sha256: sha256(&bytes),
    })
}

fn raw_step(
    root: &Path,
    stage: &str,
    command: &[String],
    launcher_kind: &str,
    network_enabled: bool,
    output: SandboxOutput,
) -> RawStepArtifact {
    RawStepArtifact {
        stage: stage.to_string(),
        logical_command: command.to_vec(),
        launcher_kind: launcher_kind.to_string(),
        status_code: output.status_code,
        timed_out: output.timed_out,
        network_enabled,
        stdout_complete_sha256: output.stdout_sha256,
        stderr_complete_sha256: output.stderr_sha256,
        stdout_bounded_sanitized: sanitize_output(root, &output.stdout),
        stderr_bounded_sanitized: sanitize_output(root, &output.stderr),
    }
}

fn bind_runtime_identity(current: &mut Option<String>, value: &str) -> Result<(), String> {
    match current {
        Some(current) if current != value => {
            Err("historical preparation and test resolved different runtime identities".to_string())
        }
        Some(_) => Ok(()),
        None => {
            *current = Some(value.to_string());
            Ok(())
        }
    }
}

fn initialize_private_cache(root: &Path) -> Result<PathBuf, String> {
    let cache = root.join(CACHE_DIRECTORY);
    if cache.exists() {
        return Err(format!(
            "historical test private cache already exists: {}",
            cache.display()
        ));
    }
    fs::create_dir(&cache).map_err(|error| {
        format!(
            "failed to create historical test private cache {}: {error}",
            cache.display()
        )
    })?;
    for name in [
        "bun-cache",
        "cargo-home",
        "cargo-target",
        "corepack",
        "go-build",
        "go-mod",
        "go-path",
        "gradle",
        "home",
        "npm",
        "pip",
        "pycache",
        "tmp",
        "xdg-cache",
    ] {
        fs::create_dir(cache.join(name)).map_err(|error| {
            format!("failed to create private historical cache {name}: {error}")
        })?;
    }
    for name in ["gitconfig", "npmrc"] {
        fs::write(cache.join(name), [])
            .map_err(|error| format!("failed to initialize private historical {name}: {error}"))?;
    }
    canonical_directory(&cache, "historical test private cache")
}

fn verify_snapshot(root: &Path, revision: &str) -> Result<(), String> {
    let head = git_text(root, &["rev-parse", "HEAD"])?;
    let shallow = git_text(root, &["rev-parse", "--is-shallow-repository"])?;
    let sparse = git_optional_text(root, &["config", "--bool", "core.sparseCheckout"])?;
    let promisor = git_optional_text(
        root,
        &["config", "--get-regexp", "^remote\\..*\\.promisor$"],
    )?;
    let status = git_text(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )?;
    if head != revision
        || shallow != "false"
        || sparse.as_deref().is_some_and(|value| value != "false")
        || promisor.is_some_and(|value| !value.is_empty())
        || !status.is_empty()
    {
        return Err(format!(
            "historical test snapshot is dirty, shallow, sparse, partial, or not at revision {revision}"
        ));
    }
    Ok(())
}

fn verify_tracked_snapshot(root: &Path, revision: &str) -> Result<(), String> {
    let head = git_text(root, &["rev-parse", "HEAD"])?;
    let changed = git_text(root, &["diff", "--name-only", "HEAD", "--"])?;
    if head != revision || !changed.is_empty() {
        return Err(format!(
            "historical test changed its revision or tracked files: expected {revision}, found {head}, changed={changed:?}"
        ));
    }
    Ok(())
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    git_output(root, args, false)?.ok_or_else(|| format!("git {} failed", args.join(" ")))
}

fn git_optional_text(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    git_output(root, args, true)
}

fn git_output(root: &Path, args: &[&str], optional: bool) -> Result<Option<String>, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output =
        crate::bounded_process::run_with_output_limit(&mut command, GIT_TIMEOUT, GIT_OUTPUT_LIMIT)
            .map_err(|error| format!("historical test snapshot requires git: {error}"))?;
    if output.timed_out || output.stdout_truncated || output.stderr_truncated {
        return Err(format!(
            "git {} did not return bounded output",
            args.join(" ")
        ));
    }
    if !output.status.success() {
        if optional {
            return Ok(None);
        }
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-UTF-8 output", args.join(" ")))?;
    Ok(Some(value.trim().to_string()))
}

fn sanitize_output(root: &Path, output: &str) -> String {
    let mut sanitized = output.replace(&root.to_string_lossy().to_string(), "$REPOSITORY");
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        sanitized = sanitized.replace(
            &PathBuf::from(home).to_string_lossy().to_string(),
            "$HOST_HOME",
        );
    }
    sanitized
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_dir() {
        return Err(format!(
            "{label} is not an existing directory: {}",
            path.display()
        ));
    }
    fs::canonicalize(path)
        .map(normalize_path)
        .map_err(|error| format!("failed to resolve {label}: {error}"))
}

fn require_revision(value: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err("historical tested revision must be a lowercase complete Git SHA".to_string())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(windows)]
fn normalize_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    text.strip_prefix(r"\\?\").map_or(path, PathBuf::from)
}

#[cfg(not(windows))]
fn normalize_path(path: PathBuf) -> PathBuf {
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_revision_fails_before_creating_a_cache() {
        let root = tempfile::tempdir().unwrap();
        let error =
            run_historical_test(root.path(), "HEAD", &[], &["true".to_string()]).unwrap_err();

        assert!(error.contains("lowercase complete Git SHA"));
        assert!(!root.path().join(CACHE_DIRECTORY).exists());
    }

    #[test]
    fn complete_stream_hashes_bind_the_raw_step() {
        let root = tempfile::tempdir().unwrap();
        let raw = raw_step(
            root.path(),
            "test",
            &["tool".to_string()],
            "direct",
            false,
            SandboxOutput {
                status_code: Some(0),
                stdout: "visible".to_string(),
                stderr: String::new(),
                stdout_sha256: "a".repeat(64),
                stderr_sha256: "b".repeat(64),
                timed_out: false,
            },
        );
        let result = step_result(&["tool".to_string()], &raw).unwrap();

        assert_eq!(result.stdout_sha256, "a".repeat(64));
        assert_eq!(result.stderr_sha256, "b".repeat(64));
        assert!(!result.network_enabled);
        assert_eq!(result.raw_result_sha256.len(), 64);
    }

    #[test]
    fn cargo_child_denial_requires_the_complete_host_signature() {
        let denial = "error: could not execute process `rustc -vV` (never executed)\n\nCaused by:\n  Access is denied. (os error 5)\n";

        assert!(windows_cargo_child_launch_denied(denial));
        assert!(!windows_cargo_child_launch_denied(
            "candidate test failed: Access is denied. (os error 5)"
        ));
        assert!(!windows_cargo_child_launch_denied(
            "error: could not execute process `rustc -vV` (never executed): file not found"
        ));
    }

    #[test]
    fn clean_snapshot_executes_once_through_the_real_sandbox() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "main"]);
        git(
            root.path(),
            &["config", "user.email", "fixture@example.test"],
        );
        git(root.path(), &["config", "user.name", "Fixture"]);
        fs::write(root.path().join("README.md"), "fixture\n").unwrap();
        #[cfg(windows)]
        fs::write(root.path().join("fixture.bat"), "@exit /b 0\r\n").unwrap();
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-m", "fixture"]);
        let revision = git_value(root.path(), &["rev-parse", "HEAD"]);
        #[cfg(windows)]
        let command = vec!["./fixture.bat".to_string()];
        #[cfg(not(windows))]
        let command = vec!["true".to_string()];

        let outcome = run_historical_test(root.path(), &revision, &[], &command).unwrap();
        let HistoricalTestExecutionOutcome::Completed(execution) = outcome else {
            panic!("real sandbox was unavailable");
        };

        assert!(execution.result.test_executed);
        assert_eq!(execution.result.status_code, Some(0));
        assert!(execution.result.network_enabled);
        assert_eq!(execution.result.command, command);
        assert_eq!(
            execution.result.raw_result_sha256,
            sha256(&execution.raw_result)
        );
    }

    #[test]
    fn tracked_snapshot_mutation_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "main"]);
        git(
            root.path(),
            &["config", "user.email", "fixture@example.test"],
        );
        git(root.path(), &["config", "user.name", "Fixture"]);
        fs::write(root.path().join("README.md"), "before\n").unwrap();
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-m", "fixture"]);
        let revision = git_value(root.path(), &["rev-parse", "HEAD"]);

        fs::write(root.path().join("README.md"), "after\n").unwrap();

        let error = verify_tracked_snapshot(root.path(), &revision).unwrap_err();
        assert!(error.contains("changed its revision or tracked files"));
        assert!(error.contains("README.md"));
    }

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_value(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
}
