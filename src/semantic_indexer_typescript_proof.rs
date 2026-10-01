use super::*;
use serde::Deserialize;

const SIDECAR: &[u8] = include_bytes!("../assets/typescript-standalone-proof.js");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompilerProofResult {
    schema_version: u32,
    candidate: String,
    error_count: usize,
}

pub(crate) fn run_standalone_typescript_proof(
    root: &Path,
    candidate: &Path,
) -> Result<bool, String> {
    run_with_store(&SemanticIndexerStore::for_user()?, root, candidate)
}

fn run_with_store(
    store: &SemanticIndexerStore,
    root: &Path,
    candidate: &Path,
) -> Result<bool, String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(candidate).map_err(|error| error.to_string())?;
    let candidate = fs::canonicalize(candidate).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || !candidate.starts_with(&root) {
        return Err("TypeScript proof candidate is not a plain sandbox file".to_string());
    }
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript)?;
    let installed = store.verify(spec)?;
    let compiler = resolve_compiler(&installed)?;
    let empty_types = root.join(INDEXER_TEMP_DIR).join("empty-types");
    fs::create_dir_all(&empty_types).map_err(|error| error.to_string())?;
    let sidecar = root
        .join(INDEXER_TEMP_DIR)
        .join("typescript-standalone-proof.js");
    fs::write(&sidecar, SIDECAR).map_err(|error| error.to_string())?;
    let candidate_argument = candidate
        .strip_prefix(&root)
        .map_err(|error| error.to_string())?
        .to_string_lossy()
        .into_owned();
    let mut prepared = build_indexer_sandbox_command(spec, &root, &installed, Vec::new(), None)?;
    prepared.command.args =
        compiler_arguments(&root, &sidecar, &compiler, &candidate, &empty_types);
    prepared.command.timeout = Duration::from_secs(30);
    prepared.command.memory_limit = crate::sandbox::DEFAULT_MEMORY_LIMIT;
    prepared.command.process_limit = crate::sandbox::DEFAULT_PROCESS_LIMIT;
    prepared.command.output_limit = crate::sandbox::DEFAULT_OUTPUT_LIMIT;
    #[cfg(windows)]
    prepared
        .command
        .windows_virtualized_paths
        .push(root.clone());
    prepared
        .runtime_files
        .extend([compiler, candidate, sidecar]);
    let before = runtime_file_identities(&prepared.runtime_files)?;
    let result = crate::sandbox::run(&prepared.command).map_err(|error| error.to_string());
    let integrity = runtime_file_identities(&prepared.runtime_files)
        .and_then(|after| verify_runtime_identities_unchanged("TypeScript proof", &before, &after))
        .and_then(|()| {
            let after = store.verify(spec)?;
            if after != installed {
                return Err(
                    "pinned TypeScript installation changed during compiler proof".to_string(),
                );
            }
            Ok(())
        });
    let output = combine_run_and_integrity(result, integrity)?;
    compiler_outcome(&output, &candidate_argument)
}

fn resolve_compiler(installed: &InstalledIndexer) -> Result<PathBuf, String> {
    fs::canonicalize(
        installed
            .root
            .join("node_modules/typescript/lib/typescript.js"),
    )
    .map_err(|error| format!("failed to resolve pinned TypeScript compiler API: {error}"))
}

fn compiler_outcome(
    output: &crate::sandbox::SandboxOutput,
    candidate: &str,
) -> Result<bool, String> {
    if output.timed_out || output.memory_limit_exceeded || output.process_limit_exceeded {
        return Err("standalone TypeScript compiler proof exceeded its sandbox limits".to_string());
    }
    if output.status_code != Some(0) {
        return Err(format!(
            "standalone TypeScript compiler failed with {:?}: {}",
            output.status_code,
            compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
        ));
    }
    let result: CompilerProofResult = serde_json::from_str(&output.stdout)
        .map_err(|error| format!("invalid standalone TypeScript compiler result: {error}"))?;
    if result.schema_version != 1 || result.candidate != candidate {
        return Err(
            "standalone TypeScript compiler changed its result contract/candidate".to_string(),
        );
    }
    Ok(result.error_count == 0)
}

fn compiler_arguments(
    root: &Path,
    sidecar: &Path,
    compiler: &Path,
    candidate: &Path,
    empty_types: &Path,
) -> Vec<String> {
    let mut args = Vec::new();
    if cfg!(windows) {
        args.extend([
            "--preserve-symlinks".to_string(),
            "--preserve-symlinks-main".to_string(),
        ]);
    }
    args.push(sandbox_repository_argument(
        root,
        &sidecar.to_string_lossy(),
    ));
    args.push(compiler.to_string_lossy().into_owned());
    // Relative identities remain stable when Windows virtualizes the sandbox root.
    args.push(
        candidate
            .strip_prefix(root)
            .expect("sandbox candidate")
            .to_string_lossy()
            .into_owned(),
    );
    args.push(
        empty_types
            .strip_prefix(root)
            .expect("private type roots")
            .to_string_lossy()
            .into_owned(),
    );
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_target_the_actual_tsx_file_without_global_tsc() {
        let root = Path::new("proof-root");
        let args = compiler_arguments(
            root,
            &root.join("proof.js"),
            Path::new("pinned/lib/typescript.js"),
            &root.join("candidate.tsx"),
            &root.join("empty-types"),
        );
        assert!(args.iter().any(|arg| arg == "pinned/lib/typescript.js"));
        assert_eq!(args[args.len() - 2], "candidate.tsx");
        assert!(!args.iter().any(|arg| arg == "candidate.ts" || arg == "tsc"));
        assert_eq!(args.last().unwrap(), "empty-types");
    }

    #[test]
    fn compiler_path_is_canonical_even_when_the_installation_root_is_relative() {
        let root = tempfile::TempDir::new_in(".").unwrap();
        let compiler = root
            .path()
            .join("node_modules/typescript/lib/typescript.js");
        fs::create_dir_all(compiler.parent().unwrap()).unwrap();
        fs::write(&compiler, "fixture").unwrap();
        let installed = InstalledIndexer {
            root: PathBuf::from(root.path().file_name().unwrap()),
            entrypoint: compiler,
            tree_sha256: String::new(),
        };
        assert!(!installed.root.is_absolute());
        assert_eq!(
            resolve_compiler(&installed).unwrap(),
            fs::canonicalize(&installed.entrypoint).unwrap()
        );
        assert!(resolve_compiler(&installed).unwrap().is_absolute());
    }

    fn output(status_code: Option<i32>, stdout: &str) -> crate::sandbox::SandboxOutput {
        crate::sandbox::SandboxOutput {
            status_code,
            stdout: stdout.to_string(),
            stderr: String::new(),
            stdout_sha256: String::new(),
            stderr_sha256: String::new(),
            timed_out: false,
            memory_limit_exceeded: false,
            process_limit_exceeded: false,
        }
    }

    #[test]
    fn runtime_failures_and_missing_or_mismatched_results_cannot_be_diagnostics() {
        let clean = r#"{"schema_version":1,"candidate":"candidate.ts","error_count":0}"#;
        for failed in [
            output(Some(1), clean),
            output(None, clean),
            output(Some(0), ""),
            output(
                Some(0),
                r#"{"schema_version":1,"candidate":"other.ts","error_count":0}"#,
            ),
            output(
                Some(0),
                r#"{"schema_version":2,"candidate":"candidate.ts","error_count":0}"#,
            ),
        ] {
            assert!(compiler_outcome(&failed, "candidate.ts").is_err());
        }
        for resource in 0..3 {
            let mut limited = output(Some(0), clean);
            match resource {
                0 => limited.timed_out = true,
                1 => limited.memory_limit_exceeded = true,
                _ => limited.process_limit_exceeded = true,
            }
            assert!(compiler_outcome(&limited, "candidate.ts").is_err());
        }
        assert!(compiler_outcome(&output(Some(0), clean), "candidate.ts").unwrap());
        assert!(
            !compiler_outcome(
                &output(
                    Some(0),
                    r#"{"schema_version":1,"candidate":"candidate.ts","error_count":1}"#
                ),
                "candidate.ts"
            )
            .unwrap()
        );
    }

    #[test]
    fn missing_pinned_installation_fails_without_a_compiler_fallback() {
        let root = tempfile::TempDir::new().unwrap();
        let candidate = root.path().join("candidate.ts");
        fs::write(&candidate, "export const answer = 42;").unwrap();
        let store = SemanticIndexerStore::at(root.path().join("missing-store"));
        let error = run_with_store(&store, root.path(), &candidate).unwrap_err();
        assert!(
            error.contains("pinned semantic indexer is not installed"),
            "{error}"
        );
    }

    #[test]
    fn pinned_compiler_accepts_ts_and_rejects_type_errors_in_the_native_sandbox() {
        let _guard = crate::sandbox::sandbox_test_resource_guard();
        for (source, accepted) in [
            ("export const answer: number = 42;", true),
            ("export const answer: number = 'wrong';", false),
        ] {
            let root = tempfile::TempDir::new().unwrap();
            let candidate = root.path().join("candidate.ts");
            fs::write(&candidate, source).unwrap();
            assert_eq!(
                run_standalone_typescript_proof(root.path(), &candidate).unwrap(),
                accepted
            );
            assert_eq!(fs::read_to_string(candidate).unwrap(), source);
        }
    }

    #[test]
    fn pinned_compiler_checks_tsx_and_ignores_repository_config_and_ambient_types() {
        let _guard = crate::sandbox::sandbox_test_resource_guard();
        let root = tempfile::TempDir::new().unwrap();
        let candidate = root.path().join("candidate.tsx");
        fs::write(&candidate, "declare namespace JSX { interface IntrinsicElements { div: {}; } }\nexport const view = <div />;").unwrap();
        fs::write(root.path().join("tsconfig.json"), "not valid JSON").unwrap();
        let ambient = root.path().join("node_modules/@types/invalid");
        fs::create_dir_all(&ambient).unwrap();
        fs::write(ambient.join("index.d.ts"), "not valid TypeScript").unwrap();
        assert!(run_standalone_typescript_proof(root.path(), &candidate).unwrap());
    }
}
