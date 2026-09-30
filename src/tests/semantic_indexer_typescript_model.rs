use super::*;
use tempfile::TempDir;

fn write(root: &Path, path: &str, source: &str) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, source).unwrap();
}

#[test]
fn normal_config_census_does_not_require_git_and_includes_nested_roots() {
    let root = TempDir::new().unwrap();
    for path in [
        "tsconfig.json",
        "packages/ui/tsconfig.build.json",
        "packages/js/jsconfig.json",
        "node_modules/dependency/tsconfig.json",
        ".sniff/tsconfig.json",
    ] {
        write(root.path(), path, "{}");
    }
    assert_eq!(
        discover_configs(root.path()).unwrap(),
        vec![
            "packages/js/jsconfig.json",
            "packages/ui/tsconfig.build.json",
            "tsconfig.json",
        ]
    );
    assert!(!root.path().join(".git").exists());
}

#[test]
fn configuration_directory_is_not_silently_ignored() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("tsconfig.json")).unwrap();
    assert!(
        discover_configs(root.path())
            .unwrap_err()
            .contains("plain repository file")
    );
}

#[test]
fn sidecar_command_uses_exact_pinned_compiler_without_indexer_bootstrap() {
    let root = TempDir::new().unwrap();
    let sidecar = root
        .path()
        .join(INDEXER_TEMP_DIR)
        .join("typescript-project-model.js");
    let input = root.path().join(INDEXER_TEMP_DIR).join("input.json");
    let compiler = root.path().parent().unwrap().join("pinned/typescript.js");
    let args = model_arguments(root.path(), &sidecar, &compiler, &input);
    assert!(
        !args
            .iter()
            .any(|arg| arg == "-e" || arg == WINDOWS_SCIP_NODE_BOOTSTRAP)
    );
    assert_eq!(
        args[args.len() - 3],
        sandbox_repository_argument(root.path(), &sidecar.to_string_lossy())
    );
    assert_eq!(args[args.len() - 2], compiler.to_string_lossy());
    assert_eq!(
        args[args.len() - 1],
        sandbox_repository_argument(root.path(), &input.to_string_lossy())
    );
    if cfg!(windows) {
        assert_eq!(
            &args[..2],
            ["--preserve-symlinks", "--preserve-symlinks-main"]
        );
    }
}

#[tokio::test]
async fn normal_discovery_rejects_stale_ast_before_installation_or_compiler_execution() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("index.ts");
    write(
        root.path(),
        "index.ts",
        "export function value() { return 1; }\n",
    );
    let file = crate::parser::parse_file_checked(source.to_str().unwrap()).unwrap();
    fs::write(&source, "export function value() { return 2; }\n").unwrap();
    let failure = run_required_indexers_with_discovered_worlds(
        root.path(),
        std::slice::from_ref(&file),
        std::slice::from_ref(&file),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::IntegrityVerification
    );
    assert!(
        failure
            .detail
            .contains("differs from parsed source snapshot")
    );
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}

#[tokio::test]
#[ignore = "requires the installed checksum-pinned scip-typescript runtime, Node.js, and native sandbox"]
async fn normal_scan_discovers_and_indexes_reference_world_without_git_or_model_calls() {
    let root = TempDir::new().unwrap();
    for (path, source) in [
        (
            "tsconfig.json",
            r#"{"files":["main.ts"],"references":[{"path":"./packages/core/build.json"}]}"#,
        ),
        (
            "packages/core/build.json",
            r#"{"compilerOptions":{"composite":true},"files":["core.ts"]}"#,
        ),
        ("main.ts", "export function main(): number { return 1; }\n"),
        (
            "packages/core/core.ts",
            "export function core(): number { return 2; }\n",
        ),
    ] {
        write(root.path(), path, source);
    }
    let files = ["main.ts", "packages/core/core.ts"]
        .iter()
        .map(|path| {
            crate::parser::parse_file_checked(root.path().join(path).to_str().unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    let outcome = run_required_indexers_with_discovered_worlds(root.path(), &files, &files)
        .await
        .unwrap();
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    let crate::semantic_index::SemanticIndexSet::Qualified { variants } =
        &outcome.indexes[&SemanticIndexerKind::TypeScriptJavaScript]
    else {
        panic!("normal scan used an unqualified TypeScript index");
    };
    assert_eq!(variants.len(), 1);
    let evidence = crate::semantic_method_join::build_compiler_method_evidence(
        root.path(),
        &files,
        &outcome.indexes,
    )
    .unwrap();
    assert_eq!(evidence.contexts.len(), 2);
    assert!(!root.path().join(".git").exists());
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}
