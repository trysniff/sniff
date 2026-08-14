use super::source_selection::normalize_repository;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub const INTENTIONAL_BOUNDARY_INVENTORY_SCHEMA_VERSION: u32 = 1;
const INVENTORY_CONTRACT: &str = "sniffbench-intentional-boundary-git-inventory-v1";
const GIT_TIMEOUT: Duration = Duration::from_secs(300);
const GIT_OUTPUT_LIMIT: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BoundaryGitObjectFormat {
    Sha1,
    Sha256,
}

impl BoundaryGitObjectFormat {
    fn object_id_length(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryGitEntryKind {
    RegularBlob,
    ExecutableBlob,
    SymbolicLink,
    Gitlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryTrackedEntry {
    pub repository_path: String,
    pub mode: String,
    pub kind: BoundaryGitEntryKind,
    pub object_id: String,
    pub byte_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryRepositoryInventory {
    pub schema_version: u32,
    pub inventory_contract: String,
    pub repository: String,
    pub revision: String,
    pub git_object_format: BoundaryGitObjectFormat,
    pub tracked_entries: Vec<IntentionalBoundaryTrackedEntry>,
    pub inventory_sha256: String,
}

pub fn inventory_intentional_boundary_repository(
    repository: &str,
    revision: &str,
    root: &Path,
) -> Result<IntentionalBoundaryRepositoryInventory, String> {
    let repository = normalize_repository(repository)?;
    let root = require_complete_checkout(&repository, revision, root)?;
    let object_format = match git_text(&root, &["rev-parse", "--show-object-format"])?.trim() {
        "sha1" => BoundaryGitObjectFormat::Sha1,
        "sha256" => BoundaryGitObjectFormat::Sha256,
        other => return Err(format!("unsupported Git object format: {other}")),
    };
    require_revision("intentional-boundary revision", revision, object_format)?;
    let tree = git_bytes(
        &root,
        &["ls-tree", "-r", "-l", "-z", "--full-tree", revision],
    )?;
    let tracked_entries = parse_tree(&tree, object_format)?;
    let mut inventory = IntentionalBoundaryRepositoryInventory {
        schema_version: INTENTIONAL_BOUNDARY_INVENTORY_SCHEMA_VERSION,
        inventory_contract: INVENTORY_CONTRACT.to_string(),
        repository,
        revision: revision.to_ascii_lowercase(),
        git_object_format: object_format,
        tracked_entries,
        inventory_sha256: String::new(),
    };
    inventory.inventory_sha256 = compute_inventory_sha256(&inventory)?;
    Ok(inventory)
}

pub fn validate_intentional_boundary_repository_inventory(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<(), String> {
    let expected = inventory_intentional_boundary_repository(repository, revision, root)?;
    if inventory != &expected {
        return Err("intentional-boundary Git inventory changed its immutable tree".to_string());
    }
    Ok(())
}

pub(super) fn read_intentional_boundary_git_blob(
    root: &Path,
    object_id: &str,
    expected_length: u64,
) -> Result<Vec<u8>, String> {
    let bytes = git_bytes(root, &["cat-file", "blob", object_id])?;
    if bytes.len() as u64 != expected_length {
        return Err(format!(
            "intentional-boundary Git blob {object_id} changed its committed length"
        ));
    }
    Ok(bytes)
}

fn require_complete_checkout(
    repository: &str,
    revision: &str,
    root: &Path,
) -> Result<std::path::PathBuf, String> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        format!(
            "failed to resolve intentional-boundary checkout {}: {error}",
            root.display()
        )
    })?;
    if git_text(&canonical_root, &["rev-parse", "--is-inside-work-tree"])?.trim() != "true" {
        return Err("intentional-boundary source is not a Git worktree".to_string());
    }
    let top = git_text(&canonical_root, &["rev-parse", "--show-toplevel"])?;
    let canonical_top = fs::canonicalize(top.trim())
        .map_err(|error| format!("failed to resolve Git repository root: {error}"))?;
    if canonical_top != canonical_root {
        return Err("intentional-boundary checkout must be the Git repository root".to_string());
    }
    if !git_text(
        &canonical_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?
    .trim()
    .is_empty()
    {
        return Err("intentional-boundary source worktree is dirty".to_string());
    }
    if git_text(&canonical_root, &["rev-parse", "--is-shallow-repository"])?.trim() != "false" {
        return Err("intentional-boundary source repository is shallow".to_string());
    }
    if git_optional_text(
        &canonical_root,
        &["config", "--bool", "core.sparseCheckout"],
    )?
    .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
    {
        return Err("intentional-boundary source repository uses sparse checkout".to_string());
    }
    if git_optional_text(
        &canonical_root,
        &["config", "--get-regexp", "^remote\\..*\\.promisor$"],
    )?
    .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "intentional-boundary source repository depends on a promisor remote".to_string(),
        );
    }
    let origin = git_text(&canonical_root, &["remote", "get-url", "origin"])?;
    if normalize_repository(origin.trim())? != repository {
        return Err(
            "intentional-boundary source origin does not match its ranked repository".to_string(),
        );
    }
    let head = git_text(&canonical_root, &["rev-parse", "--verify", "HEAD"])?;
    if !head.trim().eq_ignore_ascii_case(revision) {
        return Err(format!(
            "intentional-boundary source revision mismatch: expected {revision}, found {}",
            head.trim()
        ));
    }
    git_bytes(
        &canonical_root,
        &["fsck", "--connectivity-only", "--no-dangling", revision],
    )?;
    Ok(canonical_root)
}

fn parse_tree(
    bytes: &[u8],
    object_format: BoundaryGitObjectFormat,
) -> Result<Vec<IntentionalBoundaryTrackedEntry>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let records = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    if !records.last().is_some_and(|record| record.is_empty()) {
        return Err("intentional-boundary Git tree is not NUL-terminated".to_string());
    }
    let mut entries = Vec::with_capacity(records.len().saturating_sub(1));
    let mut paths = BTreeSet::new();
    for record in &records[..records.len() - 1] {
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| "intentional-boundary Git tree record has no path".to_string())?;
        let header = std::str::from_utf8(&record[..separator])
            .map_err(|_| "intentional-boundary Git tree header is not UTF-8".to_string())?;
        let path = std::str::from_utf8(&record[separator + 1..])
            .map_err(|_| "intentional-boundary Git path is not UTF-8".to_string())?;
        validate_git_path(path)?;
        if !paths.insert(path.to_string()) {
            return Err(format!("intentional-boundary Git tree repeats path {path}"));
        }
        let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(
                "intentional-boundary Git tree header has an invalid field count".to_string(),
            );
        }
        let (kind, expected_type, expects_size) = match fields[0] {
            "100644" => (BoundaryGitEntryKind::RegularBlob, "blob", true),
            "100755" => (BoundaryGitEntryKind::ExecutableBlob, "blob", true),
            "120000" => (BoundaryGitEntryKind::SymbolicLink, "blob", true),
            "160000" => (BoundaryGitEntryKind::Gitlink, "commit", false),
            mode => return Err(format!("unsupported Git tree mode {mode} for {path}")),
        };
        if fields[1] != expected_type {
            return Err(format!(
                "Git tree mode {} requires object type {expected_type} for {path}",
                fields[0]
            ));
        }
        require_object_id("intentional-boundary Git object", fields[2], object_format)?;
        let byte_length = if expects_size {
            Some(fields[3].parse::<u64>().map_err(|_| {
                format!("intentional-boundary Git blob has invalid size for {path}")
            })?)
        } else if fields[3] == "-" {
            None
        } else {
            return Err(format!(
                "intentional-boundary Gitlink has an unexpected size for {path}"
            ));
        };
        entries.push(IntentionalBoundaryTrackedEntry {
            repository_path: path.to_string(),
            mode: fields[0].to_string(),
            kind,
            object_id: fields[2].to_ascii_lowercase(),
            byte_length,
        });
    }
    entries.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    Ok(entries)
}

fn validate_git_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(format!("intentional-boundary Git path is unsafe: {path}"));
    }
    Ok(())
}

fn compute_inventory_sha256(
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        inventory.schema_version,
        &inventory.inventory_contract,
        &inventory.repository,
        &inventory.revision,
        inventory.git_object_format,
        &inventory.tracked_entries,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary Git inventory: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    String::from_utf8(git_bytes(root, args)?)
        .map_err(|_| format!("git {} returned non-UTF-8 text", args.join(" ")))
}

fn git_optional_text(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = run_git(root, args)?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| format!("git {} returned non-UTF-8 text", args.join(" ")))
    } else {
        Ok(None)
    }
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = run_git(root, args)?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed for {}: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(1024)
                .collect::<String>()
        ));
    }
    Ok(output.stdout)
}

fn run_git(root: &Path, args: &[&str]) -> Result<crate::bounded_process::BoundedOutput, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output =
        crate::bounded_process::run_with_output_limit(&mut command, GIT_TIMEOUT, GIT_OUTPUT_LIMIT)
            .map_err(|error| format!("intentional-boundary inventory requires git: {error}"))?;
    if output.timed_out {
        return Err(format!(
            "git {} exceeded its {}-second deadline",
            args.join(" "),
            GIT_TIMEOUT.as_secs()
        ));
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err(format!(
            "git {} exceeded the {GIT_OUTPUT_LIMIT}-byte inventory limit",
            args.join(" ")
        ));
    }
    Ok(output)
}

fn require_revision(
    label: &str,
    value: &str,
    object_format: BoundaryGitObjectFormat,
) -> Result<(), String> {
    require_object_id(label, value, object_format)
}

fn require_object_id(
    label: &str,
    value: &str,
    object_format: BoundaryGitObjectFormat,
) -> Result<(), String> {
    if value.len() == object_format.object_id_length()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a complete lowercase object ID"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn repository() -> (TempDir, String) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "--quiet"]);
        git(root.path(), &["config", "user.name", "SniffBench"]);
        git(
            root.path(),
            &["config", "user.email", "bench@example.invalid"],
        );
        git(
            root.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example/repo.git",
            ],
        );
        fs::create_dir_all(root.path().join("src/generated")).unwrap();
        fs::create_dir_all(root.path().join("tests")).unwrap();
        fs::write(
            root.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/generated/model.rs"),
            "pub struct Model;\n",
        )
        .unwrap();
        fs::write(
            root.path().join("tests/value.rs"),
            "#[test] fn value() {}\n",
        )
        .unwrap();
        fs::write(root.path().join("Cargo.toml"), "[package]\nname='sample'\n").unwrap();
        let mut executable = fs::File::create(root.path().join("tool.sh")).unwrap();
        executable.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        drop(executable);
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
        let revision = git(root.path(), &["rev-parse", "HEAD"]);
        (root, revision)
    }

    #[test]
    fn inventories_every_tracked_role_from_the_immutable_git_tree() {
        let (root, revision) = repository();
        let inventory = inventory_intentional_boundary_repository(
            "github.com/example/repo",
            &revision,
            root.path(),
        )
        .unwrap();
        let paths = inventory
            .tracked_entries
            .iter()
            .map(|entry| entry.repository_path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            [
                "Cargo.toml",
                "src/generated/model.rs",
                "src/lib.rs",
                "tests/value.rs",
                "tool.sh",
            ]
        );
        assert_eq!(inventory.repository, "github.com/example/repo");
        assert_eq!(inventory.revision, revision);
        assert_eq!(inventory.inventory_sha256.len(), 64);
        validate_intentional_boundary_repository_inventory(
            "github.com/example/repo",
            &revision,
            root.path(),
            &inventory,
        )
        .unwrap();
    }

    #[test]
    fn rejects_dirty_sparse_promisor_wrong_revision_and_wrong_origin_checkouts() {
        let (dirty, revision) = repository();
        fs::write(dirty.path().join("untracked.txt"), "dirty").unwrap();
        assert!(
            inventory_intentional_boundary_repository(
                "github.com/example/repo",
                &revision,
                dirty.path(),
            )
            .unwrap_err()
            .contains("dirty")
        );

        let (sparse, revision) = repository();
        git(sparse.path(), &["config", "core.sparseCheckout", "true"]);
        assert!(
            inventory_intentional_boundary_repository(
                "github.com/example/repo",
                &revision,
                sparse.path(),
            )
            .unwrap_err()
            .contains("sparse")
        );

        let (promisor, revision) = repository();
        git(
            promisor.path(),
            &["config", "remote.origin.promisor", "true"],
        );
        assert!(
            inventory_intentional_boundary_repository(
                "github.com/example/repo",
                &revision,
                promisor.path(),
            )
            .unwrap_err()
            .contains("promisor")
        );

        let (wrong, revision) = repository();
        let replacement = if revision.ends_with('0') { "1" } else { "0" };
        let other_revision = format!("{}{replacement}", &revision[..revision.len() - 1]);
        assert!(
            inventory_intentional_boundary_repository(
                "github.com/example/repo",
                &other_revision,
                wrong.path(),
            )
            .unwrap_err()
            .contains("revision mismatch")
        );
        assert!(
            inventory_intentional_boundary_repository(
                "github.com/another/repo",
                &revision,
                wrong.path(),
            )
            .unwrap_err()
            .contains("origin")
        );
    }

    #[test]
    fn replay_validation_rejects_inventory_tampering() {
        let (root, revision) = repository();
        let mut inventory = inventory_intentional_boundary_repository(
            "github.com/example/repo",
            &revision,
            root.path(),
        )
        .unwrap();
        inventory.tracked_entries[0].byte_length = Some(999);

        assert!(
            validate_intentional_boundary_repository_inventory(
                "github.com/example/repo",
                &revision,
                root.path(),
                &inventory,
            )
            .unwrap_err()
            .contains("immutable tree")
        );
    }

    #[test]
    fn tree_parser_preserves_blob_symlink_executable_and_gitlink_kinds() {
        let blob = "a".repeat(40);
        let commit = "b".repeat(40);
        let tree = format!(
            "100755 blob {blob} 12\tbin/tool\0\
             100644 blob {blob} 3\tsrc/lib.rs\0\
             120000 blob {blob} 7\tlink\0\
             160000 commit {commit} -\tvendor/dependency\0"
        );
        let entries = parse_tree(tree.as_bytes(), BoundaryGitObjectFormat::Sha1).unwrap();

        assert_eq!(entries[0].kind, BoundaryGitEntryKind::ExecutableBlob);
        assert_eq!(entries[1].kind, BoundaryGitEntryKind::SymbolicLink);
        assert_eq!(entries[2].kind, BoundaryGitEntryKind::RegularBlob);
        assert_eq!(entries[3].kind, BoundaryGitEntryKind::Gitlink);
        assert_eq!(entries[3].byte_length, None);

        let unsafe_tree = format!("100644 blob {blob} 1\t../escape\0");
        assert!(
            parse_tree(unsafe_tree.as_bytes(), BoundaryGitObjectFormat::Sha1)
                .unwrap_err()
                .contains("unsafe")
        );
    }
}
