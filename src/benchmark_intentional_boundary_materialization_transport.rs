use super::{IntentionalBoundaryMaterializationError, failed, invalid, unavailable};
use reqwest::{Client, StatusCode};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const GIT_TIMEOUT: Duration = Duration::from_secs(600);
const GIT_VERIFY_TIMEOUT: Duration = Duration::from_secs(300);
const ATTEMPTS: usize = 3;

pub(super) async fn probe_repository(
    api_url: &str,
    github_token: Option<&str>,
) -> Result<StatusCode, IntentionalBoundaryMaterializationError> {
    let client = Client::builder()
        .user_agent("trysniff-intentional-boundary-collector/1")
        .build()
        .map_err(|error| unavailable(format!("failed to build GitHub client: {error}")))?;
    let mut last_error = None;
    for attempt in 0..ATTEMPTS {
        let mut request = client.get(api_url);
        if let Some(token) = github_token {
            request = request.bearer_auth(token);
        }
        match request.send().await {
            Ok(response)
                if response.status().is_success()
                    || matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) =>
            {
                return Ok(response.status());
            }
            Ok(response)
                if response.status() == StatusCode::TOO_MANY_REQUESTS
                    || response.status().is_server_error() =>
            {
                last_error = Some(format!(
                    "GitHub repository probe returned retryable status {}",
                    response.status()
                ));
            }
            Ok(response) => {
                return Err(failed(format!(
                    "GitHub repository probe returned status {}",
                    response.status()
                )));
            }
            Err(error) => last_error = Some(format!("GitHub repository probe failed: {error}")),
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1_u64 << attempt)).await;
        }
    }
    Err(failed(last_error.unwrap_or_else(|| {
        "GitHub repository probe failed without evidence".to_string()
    })))
}

pub(super) fn clone_complete_repository(
    source_url: &str,
    destination: &Path,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    clone_repository(source_url, destination, true)
}

pub(super) fn clone_repository_for_exact_revision(
    source_url: &str,
    destination: &Path,
    revision: &str,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    clone_repository(source_url, destination, false)?;
    let revision_commit = format!("{revision}^{{commit}}");
    git_success(
        destination,
        &["cat-file", "-e", &revision_commit],
        GIT_VERIFY_TIMEOUT,
        "verify frozen revision is available",
    )?;
    Ok(())
}

fn clone_repository(
    source_url: &str,
    destination: &Path,
    single_branch: bool,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| failed(format!("failed to create materialization parent: {error}")))?;
    }
    let mut last_error = String::new();
    for attempt in 0..ATTEMPTS {
        remove_partial(destination)?;
        let mut command = Command::new("git");
        command.args([
            "-c",
            "core.autocrlf=false",
            "clone",
            "--no-checkout",
            "--no-tags",
        ]);
        if single_branch {
            command.arg("--single-branch");
        }
        command.arg("--").arg(source_url).arg(destination);
        let output = crate::bounded_process::run(&mut command, GIT_TIMEOUT).map_err(|error| {
            unavailable(format!(
                "intentional-boundary materialization requires git: {error}"
            ))
        })?;
        if output.status.success() && !output.timed_out {
            return Ok(());
        }
        last_error = command_failure("clone complete repository", &output);
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(Duration::from_secs(1_u64 << attempt));
        }
    }
    remove_partial(destination)?;
    Err(failed(last_error))
}

pub(super) struct CheckoutFacts {
    pub(super) revision: String,
    pub(super) object_format: String,
    pub(super) tree_oid: String,
}

pub(super) fn inspect_checkout(
    root: &Path,
    repository: &str,
    canonical_clone_url: &str,
) -> Result<CheckoutFacts, IntentionalBoundaryMaterializationError> {
    if git_text(root, &["rev-parse", "--is-inside-work-tree"])?.trim() != "true"
        || git_text(root, &["rev-parse", "--is-shallow-repository"])?.trim() != "false"
        || !git_text(root, &["status", "--porcelain=v1", "--untracked-files=all"])?
            .trim()
            .is_empty()
        || git_text(root, &["remote", "get-url", "origin"])?.trim() != canonical_clone_url
    {
        return Err(invalid(
            "intentional-boundary checkout is not complete, clean, and canonical",
        ));
    }
    let revision = git_text(root, &["rev-parse", "--verify", "HEAD"])?
        .trim()
        .to_ascii_lowercase();
    let object_format = git_text(root, &["rev-parse", "--show-object-format"])?
        .trim()
        .to_string();
    let expected_length = match object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        other => return Err(invalid(format!("unsupported Git object format {other}"))),
    };
    if revision.len() != expected_length || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "intentional-boundary revision has an invalid object identity",
        ));
    }
    let tree_oid = git_text(root, &["rev-parse", "HEAD^{tree}"])?
        .trim()
        .to_ascii_lowercase();
    if tree_oid.len() != expected_length || !tree_oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "intentional-boundary tree has an invalid object identity",
        ));
    }
    git_success(
        root,
        &["fsck", "--connectivity-only", "--no-dangling", &revision],
        GIT_VERIFY_TIMEOUT,
        "verify complete repository connectivity",
    )?;
    if super::super::source_selection::normalize_repository(canonical_clone_url).map_err(invalid)?
        != repository
    {
        return Err(invalid(
            "intentional-boundary clone URL does not match the ranked repository",
        ));
    }
    Ok(CheckoutFacts {
        revision,
        object_format,
        tree_oid,
    })
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, IntentionalBoundaryMaterializationError> {
    let output = git_success(root, args, GIT_VERIFY_TIMEOUT, "inspect repository")?;
    String::from_utf8(output.stdout)
        .map_err(|_| invalid("intentional-boundary Git output is not UTF-8"))
}

pub(super) fn git_optional_text(
    root: &Path,
    args: &[&str],
) -> Result<Option<String>, IntentionalBoundaryMaterializationError> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output =
        crate::bounded_process::run(&mut command, GIT_VERIFY_TIMEOUT).map_err(|error| {
            unavailable(format!(
                "intentional-boundary materialization requires git: {error}"
            ))
        })?;
    if output.timed_out {
        return Err(failed(command_failure(
            "inspect optional Git identity",
            &output,
        )));
    }
    if !output.status.success() {
        return Ok(None);
    }
    String::from_utf8(output.stdout)
        .map(Some)
        .map_err(|_| invalid("intentional-boundary Git output is not UTF-8"))
}

pub(super) fn git_success(
    root: &Path,
    args: &[&str],
    timeout: Duration,
    label: &str,
) -> Result<crate::bounded_process::BoundedOutput, IntentionalBoundaryMaterializationError> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output = crate::bounded_process::run(&mut command, timeout).map_err(|error| {
        unavailable(format!(
            "intentional-boundary materialization requires git: {error}"
        ))
    })?;
    if output.timed_out || !output.status.success() {
        return Err(failed(command_failure(label, &output)));
    }
    Ok(output)
}

fn command_failure(label: &str, output: &crate::bounded_process::BoundedOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let retained = stderr.chars().take(1024).collect::<String>();
    format!(
        "{label} failed: exit={:?}, timed_out={}, stdout_sha256={}, stderr_sha256={}, stderr={retained}",
        output.status.code(),
        output.timed_out,
        output.stdout_sha256,
        output.stderr_sha256
    )
}

pub(super) fn remove_partial(
    destination: &Path,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    if destination.exists() {
        fs::remove_dir_all(destination).map_err(|error| {
            failed(format!("failed to remove partial materialization: {error}"))
        })?;
    }
    Ok(())
}

pub(super) const fn git_timeout() -> Duration {
    GIT_TIMEOUT
}
