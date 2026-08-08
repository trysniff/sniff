use crate::sandbox::{self, SandboxCommand};
use crate::slop_cases::{CounterfactualEdit, ProofLevel, SlopCase};
use crate::types::{FileRecord, FindingTier};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SAFE_MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "pyproject.toml",
    "pytest.ini",
    "tox.ini",
    "setup.cfg",
    "setup.py",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
];

pub(crate) struct RepositoryProofContext<'a> {
    pub(crate) repository_root: &'a Path,
    pub(crate) test_command: Option<&'a [String]>,
}

/// Execute the explicitly configured repository test command against the
/// original and counterfactual snapshots. No command means no test claim.
pub(crate) fn validate_repository_tests(
    cases: &[SlopCase],
    files: &[FileRecord],
    context: RepositoryProofContext<'_>,
) -> Vec<SlopCase> {
    let Some(test_command) = context.test_command else {
        return cases.to_vec();
    };
    if test_command.is_empty() {
        return mark_unresolved(
            cases,
            "repository test proof was requested with an empty test command",
        );
    }

    cases
        .iter()
        .map(|case| {
            if case.tier == FindingTier::Unresolved || case.counterfactual_edits.is_empty() {
                return case.clone();
            }
            match run_case_tests(case, files, context.repository_root, test_command) {
                Ok(()) => {
                    let mut output = case.clone();
                    if output.proof_level < ProofLevel::P2TestsValidated {
                        output.proof_level = ProofLevel::P2TestsValidated;
                    }
                    output
                        .provenance
                        .push("counterfactual:tests_validated".to_string());
                    output
                }
                Err(reason) => unresolved_case(case, reason),
            }
        })
        .collect()
}

fn run_case_tests(
    case: &SlopCase,
    files: &[FileRecord],
    repository_root: &Path,
    test_command: &[String],
) -> Result<(), String> {
    let original_root = create_snapshot(files, repository_root, "original")?;
    let candidate_root = create_snapshot(files, repository_root, "candidate")?;
    let result = (|| {
        apply_edits_to_snapshot(&candidate_root, files, &case.counterfactual_edits)?;
        let original = run_test_command(&original_root, test_command)?;
        if original.status_code != Some(0) {
            return Err(format!(
                "baseline repository test command did not pass (status {:?})",
                original.status_code
            ));
        }
        let candidate = run_test_command(&candidate_root, test_command)?;
        if candidate.status_code != Some(0) {
            return Err(format!(
                "counterfactual repository test command did not pass (status {:?})",
                candidate.status_code
            ));
        }
        Ok(())
    })();
    let original_cleanup = std::fs::remove_dir_all(&original_root);
    let candidate_cleanup = std::fs::remove_dir_all(&candidate_root);
    match (result, original_cleanup, candidate_cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(()), Ok(())) => Err(error),
        (Ok(()), original, candidate) => Err(format!(
            "repository proof cleanup failed (original: {:?}, candidate: {:?})",
            original.err(),
            candidate.err()
        )),
        (Err(error), original, candidate) => Err(format!(
            "{error}; repository proof cleanup failed (original: {:?}, candidate: {:?})",
            original.err(),
            candidate.err()
        )),
    }
}

fn run_test_command(root: &Path, command: &[String]) -> Result<sandbox::SandboxOutput, String> {
    let program = command
        .first()
        .ok_or_else(|| "repository test command is empty".to_string())?;
    if program.contains('\0') || command.iter().any(|argument| argument.contains('\0')) {
        return Err("repository test command contains a NUL byte".to_string());
    }
    let output = sandbox::run(&SandboxCommand {
        root: root.to_path_buf(),
        workdir: PathBuf::from("."),
        program: program.clone(),
        args: command.iter().skip(1).cloned().collect(),
        timeout: Duration::from_secs(300),
        output_limit: sandbox::DEFAULT_OUTPUT_LIMIT,
    })
    .map_err(|error| format!("repository test proof unavailable: {error}"))?;
    if output.timed_out {
        return Err("repository test command timed out after 300 seconds".to_string());
    }
    Ok(output)
}

fn create_snapshot(
    files: &[FileRecord],
    repository_root: &Path,
    label: &str,
) -> Result<PathBuf, String> {
    if !repository_root.is_dir() {
        return Err(format!(
            "repository proof root is not a directory: {}",
            repository_root.display()
        ));
    }
    let root = unique_temp_root(label)?;
    let result = (|| {
        let mut written = HashMap::<PathBuf, String>::new();
        for file in files {
            let relative = safe_relative_path(&file.file_path)?;
            let destination = root.join(&relative);
            if let Some(existing) = written.get(&relative) {
                if existing != &file.source {
                    return Err(format!(
                        "repository proof has conflicting source for {}",
                        file.file_path
                    ));
                }
                continue;
            }
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "failed to create proof directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            std::fs::write(&destination, &file.source).map_err(|error| {
                format!(
                    "failed to materialize proof file {}: {error}",
                    file.file_path
                )
            })?;
            written.insert(relative, file.source.clone());
        }
        for manifest in SAFE_MANIFESTS {
            let source = repository_root.join(manifest);
            let destination = root.join(manifest);
            if !source.is_file() || destination.exists() {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
                format!(
                    "failed to inspect proof manifest {}: {error}",
                    source.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "repository proof refuses symlinked manifest {}",
                    source.display()
                ));
            }
            std::fs::copy(&source, &destination).map_err(|error| {
                format!(
                    "failed to copy proof manifest {}: {error}",
                    source.display()
                )
            })?;
        }
        Ok(root.clone())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&root);
    }
    result
}

fn apply_edits_to_snapshot(
    root: &Path,
    files: &[FileRecord],
    edits: &[CounterfactualEdit],
) -> Result<(), String> {
    let sources = files
        .iter()
        .map(|file| (file.file_path.as_str(), file.source.as_str()))
        .collect::<HashMap<_, _>>();
    let mut by_file = HashMap::<&str, Vec<&CounterfactualEdit>>::new();
    for edit in edits {
        safe_relative_path(&edit.file_path)?;
        if !sources.contains_key(edit.file_path.as_str()) {
            return Err(format!(
                "repository proof edit references unknown file {}",
                edit.file_path
            ));
        }
        by_file.entry(&edit.file_path).or_default().push(edit);
    }
    for (file_path, mut file_edits) in by_file {
        file_edits.sort_by_key(|edit| (edit.start_line, edit.end_line));
        for pair in file_edits.windows(2) {
            if pair[0].start_line <= pair[1].end_line && pair[1].start_line <= pair[0].end_line {
                return Err(format!("repository proof edits overlap in {file_path}"));
            }
        }
        let mut source = sources[file_path].to_string();
        for edit in file_edits.into_iter().rev() {
            let (start, end) = line_byte_range(&source, edit.start_line, edit.end_line)?;
            source.replace_range(start..end, &edit.replacement);
        }
        let destination = root.join(safe_relative_path(file_path)?);
        std::fs::write(destination, source)
            .map_err(|error| format!("failed to write candidate edit {file_path}: {error}"))?;
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "repository proof path escapes the snapshot: {path}"
        ));
    }
    if candidate.as_os_str().is_empty() {
        return Err("repository proof path is empty".to_string());
    }
    Ok(candidate.to_path_buf())
}

fn line_byte_range(
    source: &str,
    start_line: usize,
    end_line: usize,
) -> Result<(usize, usize), String> {
    if start_line == 0 || end_line < start_line {
        return Err(format!(
            "invalid repository proof line range {start_line}-{end_line}"
        ));
    }
    let mut starts = vec![0usize];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' && index + 1 < source.len() {
            starts.push(index + 1);
        }
    }
    if end_line > starts.len() {
        return Err(format!(
            "repository proof line range {start_line}-{end_line} exceeds {} source lines",
            starts.len()
        ));
    }
    let start = starts[start_line - 1];
    let end = starts.get(end_line).copied().unwrap_or(source.len());
    Ok((start, end))
}

fn unique_temp_root(label: &str) -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("repository proof clock failed: {error}"))?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "sniff-repository-proof-{label}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root)
        .map_err(|error| format!("failed to create repository proof snapshot: {error}"))?;
    Ok(root)
}

fn unresolved_case(case: &SlopCase, reason: String) -> SlopCase {
    let mut output = case.clone();
    output.tier = FindingTier::Unresolved;
    output.pattern = crate::product_contract::SlopPattern::None;
    output.counterfactual_edits.clear();
    output.unresolved_assumptions.push(reason);
    output
        .provenance
        .push("counterfactual:tests_unresolved".to_string());
    output
}

fn mark_unresolved(cases: &[SlopCase], reason: &str) -> Vec<SlopCase> {
    cases
        .iter()
        .map(|case| unresolved_case(case, reason.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{RepositoryProofContext, create_snapshot, safe_relative_path};
    use crate::types::FileRecord;
    use std::path::Path;

    fn file(path: &str, source: &str) -> FileRecord {
        FileRecord {
            file_path: path.to_string(),
            source: source.to_string(),
            language: "python".to_string(),
            methods: Vec::new(),
        }
    }

    #[test]
    fn snapshot_rejects_parent_paths() {
        let root = std::env::temp_dir();
        let error = create_snapshot(&[file("../secret.py", "x")], &root, "escape")
            .expect_err("parent path must fail closed");
        assert!(error.contains("escapes"));
    }

    #[test]
    fn snapshot_materializes_only_declared_source_and_safe_manifests() {
        let repository_root =
            std::env::temp_dir().join(format!("sniff-proof-source-{}", std::process::id()));
        std::fs::create_dir_all(&repository_root).unwrap();
        std::fs::write(repository_root.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(repository_root.join(".env"), "SECRET=do-not-copy\n").unwrap();
        let snapshot = create_snapshot(
            &[file("tests/example.py", "def test_example(): pass\n")],
            &repository_root,
            "safe",
        )
        .unwrap();
        assert!(snapshot.join("tests/example.py").is_file());
        assert!(snapshot.join("Cargo.toml").is_file());
        assert!(!snapshot.join(".env").exists());
        let _ = std::fs::remove_dir_all(snapshot);
        let _ = std::fs::remove_dir_all(repository_root);
    }

    #[test]
    fn context_requires_a_repository_root_and_explicit_command() {
        let context = RepositoryProofContext {
            repository_root: Path::new("."),
            test_command: None,
        };
        assert!(context.test_command.is_none());
        assert_eq!(
            safe_relative_path("src/main.py").unwrap().to_string_lossy(),
            "src/main.py"
        );
    }
}
