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
    pub(crate) differential_command: Option<&'a [String]>,
}

#[derive(Debug)]
struct RepositoryProofResult {
    tests_validated: bool,
    differential_validated: bool,
}

type ProofExecutor = dyn Fn(&Path, &[String]) -> Result<sandbox::SandboxOutput, String>;

/// Execute the explicitly configured repository test command against the
/// original and counterfactual snapshots. No command means no test claim.
pub(crate) fn validate_repository_tests(
    cases: &[SlopCase],
    files: &[FileRecord],
    context: RepositoryProofContext<'_>,
) -> Vec<SlopCase> {
    if context.test_command.is_none() && context.differential_command.is_none() {
        return cases.to_vec();
    }
    if context
        .test_command
        .is_some_and(|command| command.is_empty())
        || context
            .differential_command
            .is_some_and(|command| command.is_empty())
    {
        return mark_unresolved(
            cases,
            "repository proof was requested with an empty command",
        );
    }

    cases
        .iter()
        .map(|case| {
            if case.tier == FindingTier::Unresolved || case.counterfactual_edits.is_empty() {
                return case.clone();
            }
            match run_case_tests(
                case,
                files,
                context.repository_root,
                context.test_command,
                context.differential_command,
            ) {
                Ok(proof) => {
                    let mut output = case.clone();
                    if proof.differential_validated {
                        output.proof_level = ProofLevel::P4DifferentialValidated;
                    } else if proof.tests_validated
                        && output.proof_level < ProofLevel::P2TestsValidated
                    {
                        output.proof_level = ProofLevel::P2TestsValidated;
                    }
                    if proof.tests_validated {
                        output
                            .provenance
                            .push("counterfactual:tests_validated".to_string());
                    }
                    if proof.differential_validated {
                        output
                            .provenance
                            .push("counterfactual:differential_validated".to_string());
                    }
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
    test_command: Option<&[String]>,
    differential_command: Option<&[String]>,
) -> Result<RepositoryProofResult, String> {
    run_case_tests_with_executor(
        case,
        files,
        repository_root,
        test_command,
        differential_command,
        &run_proof_command,
    )
}

fn run_case_tests_with_executor(
    case: &SlopCase,
    files: &[FileRecord],
    repository_root: &Path,
    test_command: Option<&[String]>,
    differential_command: Option<&[String]>,
    execute: &ProofExecutor,
) -> Result<RepositoryProofResult, String> {
    if test_command.is_none() && differential_command.is_none() {
        return Ok(RepositoryProofResult {
            tests_validated: false,
            differential_validated: false,
        });
    }
    let original_root = create_snapshot(files, repository_root, "original")?;
    let candidate_root = create_snapshot(files, repository_root, "candidate")?;
    let result = (|| {
        apply_edits_to_snapshot(
            &candidate_root,
            files,
            repository_root,
            &case.counterfactual_edits,
        )?;
        let tests_validated = if let Some(test_command) = test_command {
            let original = execute(&original_root, test_command)?;
            if original.status_code != Some(0) {
                return Err(format!(
                    "baseline repository test command did not pass (status {:?})",
                    original.status_code
                ));
            }
            let candidate = execute(&candidate_root, test_command)?;
            if candidate.status_code != Some(0) {
                return Err(format!(
                    "counterfactual repository test command did not pass (status {:?})",
                    candidate.status_code
                ));
            }
            true
        } else {
            false
        };
        let differential_validated = if let Some(differential_command) = differential_command {
            let original = execute(&original_root, differential_command)?;
            if original.status_code != Some(0) {
                return Err(format!(
                    "baseline differential command did not pass (status {:?})",
                    original.status_code
                ));
            }
            let candidate = execute(&candidate_root, differential_command)?;
            if candidate.status_code != Some(0) {
                return Err(format!(
                    "counterfactual differential command did not pass (status {:?})",
                    candidate.status_code
                ));
            }
            if original != candidate {
                return Err(
                    "differential command produced different status or bounded output".to_string(),
                );
            }
            true
        } else {
            false
        };
        if !tests_validated && !differential_validated {
            return Err("repository proof produced no validated execution result".to_string());
        }
        Ok(RepositoryProofResult {
            tests_validated,
            differential_validated,
        })
    })();
    let original_cleanup = std::fs::remove_dir_all(&original_root);
    let candidate_cleanup = std::fs::remove_dir_all(&candidate_root);
    match (result, original_cleanup, candidate_cleanup) {
        (Ok(proof), Ok(()), Ok(())) => Ok(proof),
        (Err(error), Ok(()), Ok(())) => Err(error),
        (Ok(_proof), original, candidate) => Err(format!(
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

fn run_proof_command(root: &Path, command: &[String]) -> Result<sandbox::SandboxOutput, String> {
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
        read_only_paths: Vec::new(),
        env: Vec::new(),
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
            let relative = repository_relative_path(&file.file_path, repository_root)?;
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
    repository_root: &Path,
    edits: &[CounterfactualEdit],
) -> Result<(), String> {
    let sources = files
        .iter()
        .map(|file| {
            repository_relative_path(&file.file_path, repository_root)
                .map(|path| (path, file.source.as_str()))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    let mut by_file = HashMap::<PathBuf, Vec<&CounterfactualEdit>>::new();
    for edit in edits {
        let relative = repository_relative_path(&edit.file_path, repository_root)?;
        if !sources.contains_key(&relative) {
            return Err(format!(
                "repository proof edit references unknown file {}",
                edit.file_path
            ));
        }
        by_file.entry(relative).or_default().push(edit);
    }
    for (file_path, mut file_edits) in by_file {
        file_edits.sort_by_key(|edit| (edit.start_line, edit.end_line));
        for pair in file_edits.windows(2) {
            if pair[0].start_line <= pair[1].end_line && pair[1].start_line <= pair[0].end_line {
                return Err(format!(
                    "repository proof edits overlap in {}",
                    file_path.display()
                ));
            }
        }
        let mut source = sources[&file_path].to_string();
        for edit in file_edits.into_iter().rev() {
            let (start, end) = line_byte_range(&source, edit.start_line, edit.end_line)?;
            source.replace_range(start..end, &edit.replacement);
        }
        let destination = root.join(&file_path);
        std::fs::write(&destination, source).map_err(|error| {
            format!(
                "failed to write candidate edit {}: {error}",
                file_path.display()
            )
        })?;
    }
    Ok(())
}

fn repository_relative_path(path: &str, repository_root: &Path) -> Result<PathBuf, String> {
    let candidate = Path::new(path);
    let relative = if candidate.is_absolute() {
        candidate
            .strip_prefix(repository_root)
            .map_err(|_| format!("repository proof path escapes the snapshot: {path}"))?
    } else {
        candidate
    };
    safe_relative_path(&relative.to_string_lossy())
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
    use super::{
        RepositoryProofContext, create_snapshot, repository_relative_path,
        run_case_tests_with_executor, safe_relative_path,
    };
    use crate::slop_cases::{CounterfactualEdit, ProofLevel, SlopCase};
    use crate::types::FileRecord;
    use crate::{product_contract::SlopPattern, sandbox::SandboxOutput};
    use std::path::Path;
    use std::path::PathBuf;

    fn file(path: &str, source: &str) -> FileRecord {
        FileRecord {
            file_path: path.to_string(),
            source: source.to_string(),
            language: "python".to_string(),
            methods: Vec::new(),
        }
    }

    fn proof_case() -> SlopCase {
        SlopCase {
            case_id: "case-proof".to_string(),
            tier: crate::types::FindingTier::Slop,
            pattern: SlopPattern::CeremonialLogic,
            mechanism: "The branch adds no distinct behavior.".to_string(),
            intent: "Return the value.".to_string(),
            evidence: Vec::new(),
            affected_units: vec!["case-proof".to_string()],
            contract_boundary: "The return contract is unchanged.".to_string(),
            counterfactual: "Return the value directly.".to_string(),
            counterfactual_edits: vec![CounterfactualEdit {
                file_path: "src/demo.py".to_string(),
                start_line: 2,
                end_line: 2,
                replacement: "    return 1\n".to_string(),
            }],
            proof_level: ProofLevel::P0SourceReasoning,
            unresolved_assumptions: Vec::new(),
            provenance: Vec::new(),
        }
    }

    fn output(stdout: &str) -> SandboxOutput {
        SandboxOutput {
            status_code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
            timed_out: false,
        }
    }

    fn proof_root(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("sniff-proof-test-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        root
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
    fn snapshot_normalizes_absolute_repository_paths() {
        let repository_root = std::env::temp_dir().join(format!(
            "sniff-proof-absolute-source-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(repository_root.join("src")).unwrap();
        let absolute_path = repository_root.join("src/demo.py");
        let snapshot = create_snapshot(
            &[file(&absolute_path.to_string_lossy(), "def demo(): pass\n")],
            &repository_root,
            "absolute",
        )
        .unwrap();
        assert!(snapshot.join("src/demo.py").is_file());
        assert_eq!(
            repository_relative_path(&absolute_path.to_string_lossy(), &repository_root)
                .unwrap()
                .to_string_lossy(),
            "src/demo.py"
        );
        let _ = std::fs::remove_dir_all(snapshot);
        let _ = std::fs::remove_dir_all(repository_root);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_symlinked_manifests() {
        use std::os::unix::fs::symlink;

        let repository_root =
            std::env::temp_dir().join(format!("sniff-proof-symlink-{}", std::process::id()));
        std::fs::create_dir_all(&repository_root).unwrap();
        let target = repository_root.join("real-manifest.toml");
        std::fs::write(&target, "[package]\n").unwrap();
        symlink(&target, repository_root.join("Cargo.toml")).unwrap();

        let error = create_snapshot(
            &[file("tests/example.py", "def test_example(): pass\n")],
            &repository_root,
            "symlink",
        )
        .expect_err("symlinked manifests must fail closed");
        assert!(error.contains("refuses symlinked manifest"));
        let _ = std::fs::remove_dir_all(repository_root);
    }

    #[test]
    fn context_requires_a_repository_root_and_explicit_command() {
        let context = RepositoryProofContext {
            repository_root: Path::new("."),
            test_command: None,
            differential_command: None,
        };
        assert!(context.test_command.is_none());
        assert_eq!(
            safe_relative_path("src/main.py").unwrap().to_string_lossy(),
            "src/main.py"
        );
    }

    #[test]
    fn differential_fixture_upgrades_only_when_both_snapshots_match() {
        let root = proof_root("differential");
        let files = vec![file("src/demo.py", "def demo():\n    return 1\n")];
        let command = vec!["python".to_string(), "probe.py".to_string()];
        let case = proof_case();
        let result =
            run_case_tests_with_executor(&case, &files, &root, None, Some(&command), &|_, _| {
                Ok(output("same\n"))
            })
            .unwrap();
        assert!(!result.tests_validated);
        assert!(result.differential_validated);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn differential_fixture_rejects_changed_output() {
        let root = proof_root("differential-mismatch");
        let files = vec![file("src/demo.py", "def demo():\n    return 1\n")];
        let command = vec!["python".to_string(), "probe.py".to_string()];
        let case = proof_case();
        let result = run_case_tests_with_executor(
            &case,
            &files,
            &root,
            None,
            Some(&command),
            &|snapshot, _| {
                if snapshot
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains("candidate"))
                {
                    Ok(output("changed\n"))
                } else {
                    Ok(output("same\n"))
                }
            },
        );
        assert!(
            result
                .expect_err("changed differential output must fail closed")
                .contains("different status or bounded output")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn differential_fixture_rejects_matching_failed_commands() {
        let root = proof_root("differential-failed");
        let files = vec![file("src/demo.py", "def demo():\n    return 1\n")];
        let command = vec!["python".to_string(), "probe.py".to_string()];
        let case = proof_case();
        let result =
            run_case_tests_with_executor(&case, &files, &root, None, Some(&command), &|_, _| {
                Ok(SandboxOutput {
                    status_code: Some(1),
                    stdout: "same failure\n".to_string(),
                    stderr: String::new(),
                    timed_out: false,
                })
            });
        assert!(
            result
                .expect_err("matching failed probes must not earn P4")
                .contains("baseline differential command did not pass")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_fixture_requires_both_baseline_and_candidate_to_pass() {
        let root = proof_root("tests");
        let files = vec![file("src/demo.py", "def demo():\n    return 1\n")];
        let command = vec!["python".to_string(), "-m".to_string(), "pytest".to_string()];
        let case = proof_case();
        let result =
            run_case_tests_with_executor(&case, &files, &root, Some(&command), None, &|_, _| {
                Ok(output("passed\n"))
            })
            .unwrap();
        assert!(result.tests_validated);
        assert!(!result.differential_validated);
        let _ = std::fs::remove_dir_all(root);
    }
}
