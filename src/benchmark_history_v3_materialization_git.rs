use super::{
    HistoricalV3GitCommandEvidence, HistoricalV3MaterializationError, failed,
    infrastructure_unavailable,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const COMMAND_OUTPUT_LIMIT: usize = 256 * 1024 * 1024;
const ATTEMPTS: u32 = 4;

pub(super) struct RepositoryFacts {
    pub object_format: String,
    pub base_tree: String,
    pub head_tree: String,
    pub merge_tree: String,
    pub merge_parents: Vec<String>,
}

pub(super) fn create_destination(path: &Path) -> Result<PathBuf, HistoricalV3MaterializationError> {
    if !path.is_absolute() || path.exists() {
        return Err(failed(format!(
            "historical-v3 materialization root must be a new absolute path: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| failed("historical-v3 materialization root has no parent"))?;
    if !parent.is_dir() {
        return Err(failed(format!(
            "historical-v3 materialization parent does not exist: {}",
            parent.display()
        )));
    }
    let parent = fs::canonicalize(parent)
        .map(normalize_path)
        .map_err(|error| failed(format!("failed to resolve materialization parent: {error}")))?;
    let name = path
        .file_name()
        .ok_or_else(|| failed("historical-v3 materialization root has no name"))?;
    let resolved = parent.join(name);
    fs::create_dir(&resolved)
        .map_err(|error| failed(format!("failed to create materialization root: {error}")))?;
    Ok(resolved)
}

pub(super) fn remove_destination(path: &Path) -> Result<(), HistoricalV3MaterializationError> {
    if !path.exists() {
        return Ok(());
    }
    let resolved = fs::canonicalize(path)
        .map(normalize_path)
        .map_err(|error| failed(format!("failed to resolve materialization root: {error}")))?;
    if !resolved.is_dir() || resolved.parent().is_none() {
        return Err(failed("refusing to remove unsafe materialization root"));
    }
    fs::remove_dir_all(&resolved)
        .map_err(|error| failed(format!("failed to remove materialization root: {error}")))
}

pub(super) fn clone_repository(
    source_url: &str,
    repository_root: &Path,
) -> Result<(), HistoricalV3MaterializationError> {
    let mut last_failure = String::new();
    for attempt in 0..ATTEMPTS {
        if repository_root.exists() {
            fs::remove_dir_all(repository_root)
                .map_err(|error| failed(format!("failed to clear partial Git clone: {error}")))?;
        }
        let mut command = Command::new("git");
        command.args([
            "-c",
            "core.autocrlf=false",
            "clone",
            "--no-checkout",
            "--no-tags",
            "--",
            source_url,
        ]);
        command.arg(repository_root);
        let output = run(&mut command, "clone historical-v3 repository")?;
        if output.status.success() {
            return Ok(());
        }
        last_failure = command_failure("clone historical-v3 repository", &output);
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(Duration::from_secs(1_u64 << attempt));
        }
    }
    Err(failed(last_failure))
}

pub(super) fn fetch_pull_head(
    repository_root: &Path,
    pull_request_number: u64,
) -> Result<(), HistoricalV3MaterializationError> {
    let remote = format!("refs/pull/{pull_request_number}/head");
    let refspec = format!("+{remote}:refs/sniff/historical-v3-head");
    let mut last_failure = String::new();
    for attempt in 0..ATTEMPTS {
        let mut command = git_command(repository_root);
        command.args(["fetch", "--no-tags", "--force", "origin", &refspec]);
        let output = run(&mut command, "fetch historical-v3 pull-request head")?;
        if output.status.success() {
            return Ok(());
        }
        last_failure = command_failure("fetch historical-v3 pull-request head", &output);
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(Duration::from_secs(1_u64 << attempt));
        }
    }
    Err(failed(last_failure))
}

pub(super) fn set_origin(
    repository_root: &Path,
    canonical_url: &str,
) -> Result<(), HistoricalV3MaterializationError> {
    let mut command = git_command(repository_root);
    command.args(["remote", "set-url", "origin", canonical_url]);
    success_output(&mut command, "set historical-v3 canonical origin").map(|_| ())
}

pub(super) fn origin_url(
    repository_root: &Path,
) -> Result<String, HistoricalV3MaterializationError> {
    git_text(repository_root, &["remote", "get-url", "origin"])
}

pub(super) fn inspect_repository(
    repository_root: &Path,
    base: &str,
    head: &str,
    merge: &str,
) -> Result<RepositoryFacts, HistoricalV3MaterializationError> {
    let object_format = git_text(repository_root, &["rev-parse", "--show-object-format"])?;
    let base_tree = revision_tree(repository_root, base)?;
    let head_tree = revision_tree(repository_root, head)?;
    let merge_tree = revision_tree(repository_root, merge)?;
    let parents = git_text(
        repository_root,
        &["rev-list", "--parents", "-n", "1", merge],
    )?;
    let mut fields = parents.split_ascii_whitespace();
    if fields.next() != Some(merge) {
        return Err(failed("historical-v3 merge parent record changed identity"));
    }
    let merge_parents = fields.map(str::to_string).collect::<Vec<_>>();
    if merge_parents.is_empty() {
        return Err(failed("historical-v3 merge commit has no parent"));
    }
    Ok(RepositoryFacts {
        object_format,
        base_tree,
        head_tree,
        merge_tree,
        merge_parents,
    })
}

pub(super) fn revision_exists(
    repository_root: &Path,
    revision: &str,
) -> Result<bool, HistoricalV3MaterializationError> {
    let object = format!("{revision}^{{commit}}");
    let mut command = git_command(repository_root);
    command.args(["cat-file", "-e", &object]);
    Ok(run(&mut command, "verify historical-v3 revision")?
        .status
        .success())
}

pub(super) fn fetch_exact_revision(
    repository_root: &Path,
    revision: &str,
    local_ref: &str,
) -> Result<Option<HistoricalV3GitCommandEvidence>, HistoricalV3MaterializationError> {
    if revision_exists(repository_root, revision)? {
        return Ok(None);
    }
    let refspec = format!("+{revision}:{local_ref}");
    let label = "fetch exact historical-v3 revision";
    let mut last_rejection = None;
    for attempt in 0..ATTEMPTS {
        let mut command = git_command(repository_root);
        command.args(["fetch", "--no-tags", "--force", "origin", &refspec]);
        let output = run(&mut command, label)?;
        if output.status.success() {
            if revision_exists(repository_root, revision)? {
                return Ok(None);
            }
            return Err(failed(
                "exact historical-v3 revision fetch succeeded without materializing its object",
            ));
        }
        last_rejection = Some(rejection_evidence(label, &output));
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(Duration::from_secs(1_u64 << attempt));
        }
    }
    Ok(last_rejection)
}

pub(super) fn pull_head(
    repository_root: &Path,
) -> Result<String, HistoricalV3MaterializationError> {
    git_text(
        repository_root,
        &[
            "rev-parse",
            "--verify",
            "refs/sniff/historical-v3-head^{commit}",
        ],
    )
}

pub(super) fn is_ancestor(
    repository_root: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool, HistoricalV3MaterializationError> {
    let mut command = git_command(repository_root);
    command.args(["merge-base", "--is-ancestor", ancestor, descendant]);
    let output = run(&mut command, "verify historical-v3 commit ancestry")?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(failed(command_failure(
            "verify historical-v3 commit ancestry",
            &output,
        ))),
    }
}

pub(super) fn binary_patch(
    repository_root: &Path,
    base: &str,
    merge: &str,
) -> Result<Vec<u8>, HistoricalV3MaterializationError> {
    let mut command = git_command(repository_root);
    command.args([
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        base,
        merge,
        "--",
    ]);
    success_output(&mut command, "derive historical-v3 patch")
}

pub(super) fn add_worktree(
    repository_root: &Path,
    destination: &Path,
    revision: &str,
) -> Result<(), HistoricalV3MaterializationError> {
    let mut command = git_command(repository_root);
    command.args([
        "-c",
        "core.autocrlf=false",
        "worktree",
        "add",
        "--detach",
        "--force",
    ]);
    command.arg(destination).arg(revision);
    success_output(&mut command, "materialize historical-v3 worktree").map(|_| ())
}

pub(super) fn apply_patch(
    checkout: &Path,
    patch_path: &Path,
) -> Result<bool, HistoricalV3MaterializationError> {
    for check_only in [true, false] {
        let mut command = git_command(checkout);
        command.arg("apply");
        if check_only {
            command.arg("--check");
        }
        command.args(["--index", "--whitespace=nowarn", "--"]);
        command.arg(patch_path);
        let output = run(&mut command, "apply historical-v3 patch")?;
        if !output.status.success() {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn write_tree(checkout: &Path) -> Result<String, HistoricalV3MaterializationError> {
    git_text(checkout, &["write-tree"])
}

pub(super) fn head_revision(checkout: &Path) -> Result<String, HistoricalV3MaterializationError> {
    git_text(checkout, &["rev-parse", "--verify", "HEAD"])
}

pub(super) fn worktree_matches_index(
    checkout: &Path,
) -> Result<bool, HistoricalV3MaterializationError> {
    let mut command = git_command(checkout);
    command.args(["diff", "--quiet", "--"]);
    let output = run(&mut command, "verify historical-v3 reproduced worktree")?;
    let tracked_matches = match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        _ => {
            return Err(failed(command_failure(
                "verify historical-v3 reproduced worktree",
                &output,
            )));
        }
    };
    let untracked = git_text(checkout, &["ls-files", "--others", "--exclude-standard"])?;
    Ok(tracked_matches && untracked.is_empty())
}

pub(super) fn validate_checkout(
    checkout: &Path,
    revision: &str,
    tree: &str,
) -> Result<(), HistoricalV3MaterializationError> {
    if git_text(checkout, &["rev-parse", "--verify", "HEAD"])? != revision
        || git_text(checkout, &["rev-parse", "HEAD^{tree}"])? != tree
        || !git_text(
            checkout,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
    {
        return Err(failed(
            "historical-v3 materialized checkout changed immutable identity",
        ));
    }
    Ok(())
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn revision_tree(
    repository_root: &Path,
    revision: &str,
) -> Result<String, HistoricalV3MaterializationError> {
    git_text(
        repository_root,
        &["rev-parse", &format!("{revision}^{{tree}}")],
    )
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, HistoricalV3MaterializationError> {
    let mut command = git_command(root);
    command.args(args);
    let output = success_output(&mut command, &format!("git {}", args.join(" ")))?;
    String::from_utf8(output)
        .map(|text| text.trim().to_string())
        .map_err(|_| failed("historical-v3 Git output is not UTF-8"))
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(root);
    command
}

fn success_output(
    command: &mut Command,
    label: &str,
) -> Result<Vec<u8>, HistoricalV3MaterializationError> {
    let output = run(command, label)?;
    if !output.status.success() {
        return Err(failed(command_failure(label, &output)));
    }
    Ok(output.stdout)
}

fn run(
    command: &mut Command,
    label: &str,
) -> Result<crate::bounded_process::BoundedOutput, HistoricalV3MaterializationError> {
    let output = crate::bounded_process::run_with_output_limit(
        command,
        COMMAND_TIMEOUT,
        COMMAND_OUTPUT_LIMIT,
    )
    .map_err(|error| {
        infrastructure_unavailable(format!(
            "historical-v3 materialization requires Git: {error}"
        ))
    })?;
    if output.timed_out {
        return Err(failed(format!(
            "{label} exceeded its {}-second deadline",
            COMMAND_TIMEOUT.as_secs()
        )));
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err(failed(format!(
            "{label} exceeded its {COMMAND_OUTPUT_LIMIT}-byte output limit"
        )));
    }
    Ok(output)
}

fn command_failure(label: &str, output: &crate::bounded_process::BoundedOutput) -> String {
    let retained = String::from_utf8_lossy(&output.stderr)
        .chars()
        .take(2048)
        .collect::<String>();
    format!(
        "{label} failed: exit={:?}, stdout_sha256={}, stderr_sha256={}, stderr={retained}",
        output.status.code(),
        output.stdout_sha256,
        output.stderr_sha256
    )
}

fn rejection_evidence(
    label: &str,
    output: &crate::bounded_process::BoundedOutput,
) -> HistoricalV3GitCommandEvidence {
    HistoricalV3GitCommandEvidence {
        command_label: label.to_string(),
        exit_code: output.status.code(),
        stdout_sha256: output.stdout_sha256.clone(),
        stderr_sha256: output.stderr_sha256.clone(),
        retained_stderr: String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(4096)
            .collect(),
        stdout_truncated: output.stdout_truncated,
        stderr_truncated: output.stderr_truncated,
    }
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
