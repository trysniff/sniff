use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundaryProjectModelBindingOutcome,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceCensus,
};
use std::cell::Cell;
use std::fs;
use std::process::Command;
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

fn repository() -> (TempDir, IntentionalBoundaryRepositoryInventory) {
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
            "https://github.com/example/go-model.git",
        ],
    );
    for (path, source) in [
        ("go.mod", "module example.com/sample\n\ngo 1.22\n"),
        ("api/api.go", "package api\nfunc Public() {}\n"),
        ("api/more.go", "package api\nfunc More() {}\n"),
        ("api/api_windows.go", "package api\nfunc WindowsOnly() {}\n"),
        (
            "cmd/tool/main.go",
            "package main\nfunc helper() {}\nfunc main() {}\n",
        ),
        ("cmd/tool/support.go", "package main\nfunc support() {}\n"),
        (
            "tools/go.mod",
            "module example.com/sample/tools\n\ngo 1.22\n",
        ),
        (
            "tools/library/library.go",
            "package library\nfunc ToolAPI() {}\n",
        ),
    ] {
        let target = root.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(target, source).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/go-model",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, inventory)
}

fn emitted_path(root: &Path, relative: &str) -> String {
    fs::canonicalize(root.join(relative))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn model_path(root: &Path, emitted_root: Option<&str>, relative: &str) -> String {
    match emitted_root {
        Some(emitted_root) if relative.is_empty() => emitted_root.to_string(),
        Some(emitted_root) => format!("{}/{relative}", emitted_root.trim_end_matches('/')),
        None => emitted_path(root, relative),
    }
}

struct PackageFixture<'a> {
    module_directory: &'a str,
    module_path: &'a str,
    package_directory: &'a str,
    import_path: &'a str,
    name: &'a str,
    go_files: &'a [&'a str],
    ignored_go_files: &'a [&'a str],
}

fn package_json(
    root: &Path,
    emitted_root: Option<&str>,
    fixture: PackageFixture<'_>,
) -> serde_json::Value {
    let manifest = if fixture.module_directory.is_empty() {
        "go.mod".to_string()
    } else {
        format!("{}/go.mod", fixture.module_directory)
    };
    serde_json::json!({
        "Dir": model_path(root, emitted_root, fixture.package_directory),
        "ImportPath": fixture.import_path,
        "Name": fixture.name,
        "GoFiles": fixture.go_files,
        "CgoFiles": [],
        "IgnoredGoFiles": fixture.ignored_go_files,
        "TestGoFiles": ["ignored_test.go"],
        "Module": {
            "Path": fixture.module_path,
            "Version": "",
            "Dir": model_path(root, emitted_root, fixture.module_directory),
            "GoMod": model_path(root, emitted_root, &manifest),
            "Main": true
        },
        "future_field": {"ignored": true}
    })
}

fn go_list_output(root: &Path, manifest: &str) -> Vec<u8> {
    go_list_output_at(root, manifest, None)
}

fn go_list_output_at(root: &Path, manifest: &str, emitted_root: Option<&str>) -> Vec<u8> {
    let packages = match manifest {
        "go.mod" => vec![
            package_json(
                root,
                emitted_root,
                PackageFixture {
                    module_directory: "",
                    module_path: "example.com/sample",
                    package_directory: "api",
                    import_path: "example.com/sample/api",
                    name: "api",
                    go_files: &["api.go", "more.go"],
                    ignored_go_files: &["api_windows.go"],
                },
            ),
            package_json(
                root,
                emitted_root,
                PackageFixture {
                    module_directory: "",
                    module_path: "example.com/sample",
                    package_directory: "cmd/tool",
                    import_path: "example.com/sample/cmd/tool",
                    name: "main",
                    go_files: &["main.go", "support.go"],
                    ignored_go_files: &[],
                },
            ),
        ],
        "tools/go.mod" => vec![package_json(
            root,
            emitted_root,
            PackageFixture {
                module_directory: "tools",
                module_path: "example.com/sample/tools",
                package_directory: "tools/library",
                import_path: "example.com/sample/tools/library",
                name: "library",
                go_files: &["library.go"],
                ignored_go_files: &[],
            },
        )],
        other => panic!("unexpected manifest {other}"),
    };
    packages
        .into_iter()
        .map(|package| serde_json::to_string(&package).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

fn semantic_censuses(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
) {
    let source = super::super::census_intentional_boundary_repository(
        &inventory.repository,
        &inventory.revision,
        root,
        inventory,
    )
    .unwrap();
    let methods = source
        .source_files
        .iter()
        .flat_map(|file| {
            file.methods.iter().map(|method| {
                let range = IntentionalBoundarySemanticRange {
                    repository_path: file.repository_path.clone(),
                    start_line_zero_based: (method.start_line - 1) as u32,
                    start_character_zero_based: 0,
                    end_line_zero_based: (method.start_line - 1) as u32,
                    end_character_zero_based: 1,
                };
                IntentionalBoundarySemanticMethod {
                    parser_unit_id: method.parser_unit_id.clone(),
                    repository_path: file.repository_path.clone(),
                    symbol_name: method.symbol_name.clone(),
                    start_line: method.start_line,
                    end_line: method.end_line,
                    indexer: IntentionalBoundaryIndexerKind::Go,
                    status: IntentionalBoundarySemanticMethodStatus::Resolved {
                        symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                            symbol_id: format!(
                                "go fixture {} {}",
                                file.repository_path, method.symbol_name
                            ),
                            provider_identity: format!(
                                "go fixture {} {}",
                                file.repository_path, method.symbol_name
                            ),
                            display_name: Some(method.symbol_name.clone()),
                            category: IntentionalBoundarySemanticSymbolCategory::Callable,
                            provider_kind: "function".to_string(),
                            documentation: Vec::new(),
                            signatures: Vec::new(),
                            owner: None,
                            definitions: vec![range.clone()],
                            visibility: if method.is_exported {
                                IntentionalBoundarySemanticVisibility::Public
                            } else {
                                IntentionalBoundarySemanticVisibility::Private
                            },
                            surfaces: Vec::new(),
                            origin: IntentionalBoundarySemanticOrigin::Repository,
                            ambiguity_notes: Vec::new(),
                        }),
                        joined_definition: Some(range),
                    },
                    occurrences: Vec::new(),
                    calls: Vec::new(),
                    relationships: Vec::new(),
                    imports: Vec::new(),
                    test_relationships: Vec::new(),
                }
            })
        })
        .collect::<Vec<_>>();
    let mut semantic = IntentionalBoundarySemanticCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
            .to_string(),
        repository: source.repository.clone(),
        revision: source.revision.clone(),
        source_census_sha256: source.census_sha256.clone(),
        indexers: vec![IntentionalBoundarySemanticIndexerCensus {
            indexer: IntentionalBoundaryIndexerKind::Go,
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            semantic_facts_sha256: "3".repeat(64),
            diagnostic_count: 0,
            diagnostics_sha256: "4".repeat(64),
            document_count: source.source_file_count,
            symbol_count: methods.len(),
            relationship_count: 0,
            import_count: 0,
            call_count: 0,
            test_relationship_count: 0,
            unresolved_edge_count: 0,
        }],
        source_references: Vec::new(),
        resolved_method_count: methods.len(),
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        methods,
        semantic_census_sha256: String::new(),
    };
    semantic.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(&semantic)
            .unwrap();
    (source, semantic)
}

#[test]
fn normalizes_go_packages_as_exact_multi_file_boundaries() {
    let (root, inventory) = repository();
    let output = go_list_output(root.path(), "go.mod");
    let census = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"a".repeat(64),
        &output,
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 2);
    let api = census
        .targets
        .iter()
        .find(|target| target.target_name.ends_with("/api"))
        .unwrap();
    assert_eq!(
        api.source_repository_paths,
        ["api/api.go", "api/api_windows.go", "api/more.go"]
    );
    assert!(matches!(
        api.target_status,
        TargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
            ..
        }
    ));
    let command = census
        .targets
        .iter()
        .find(|target| target.target_name.ends_with("/cmd/tool"))
        .unwrap();
    assert!(matches!(
        command.target_status,
        TargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
            ..
        }
    ));
    assert!(
        census
            .targets
            .iter()
            .all(|target| target.package_version == format!("git:{}", inventory.revision))
    );
    validate_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"a".repeat(64),
        &output,
        &census,
    )
    .unwrap();
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn maps_sandbox_emitted_paths_back_to_the_immutable_snapshot() {
    let (root, inventory) = repository();
    let output = go_list_output_at(root.path(), "go.mod", Some("/workspace"));

    let census = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"a".repeat(64),
        &output,
    )
    .unwrap();

    assert_eq!(census.targets.len(), 2);
    assert!(census.targets.iter().all(|target| {
        target
            .source_repository_paths
            .iter()
            .all(|path| !path.starts_with('/') && !path.contains("workspace"))
    }));
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn go_project_model_identity_ignores_checkout_location() {
    let (root, inventory) = repository();
    let clone = tempfile::tempdir().unwrap();
    let output = Command::new("git")
        .arg("clone")
        .arg("--quiet")
        .arg(root.path())
        .arg(clone.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let left = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"b".repeat(64),
        &go_list_output(root.path(), "go.mod"),
    )
    .unwrap();
    let right = parse_intentional_boundary_go_list(
        clone.path(),
        &inventory,
        "go.mod",
        &"b".repeat(64),
        &go_list_output(clone.path(), "go.mod"),
    )
    .unwrap();

    assert_eq!(left, right);
}

#[test]
fn records_untracked_go_sources_as_unresolved_without_losing_commitment() {
    let (root, inventory) = repository();
    fs::write(root.path().join("api/untracked.go"), "package api\n").unwrap();
    let package = package_json(
        root.path(),
        None,
        PackageFixture {
            module_directory: "",
            module_path: "example.com/sample",
            package_directory: "api",
            import_path: "example.com/sample/api",
            name: "api",
            go_files: &["api.go", "untracked.go"],
            ignored_go_files: &[],
        },
    );
    let census = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"c".repeat(64),
        serde_json::to_string(&package).unwrap().as_bytes(),
    )
    .unwrap();

    assert!(matches!(
        census.targets[0].target_status,
        TargetStatus::Unresolved {
            reason: UnresolvedReason::SourceNotTracked,
            ..
        }
    ));
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn rejects_incomplete_or_malformed_go_project_models() {
    let (root, inventory) = repository();
    let mut package = package_json(
        root.path(),
        None,
        PackageFixture {
            module_directory: "",
            module_path: "example.com/sample",
            package_directory: "api",
            import_path: "example.com/sample/api",
            name: "api",
            go_files: &["api.go"],
            ignored_go_files: &[],
        },
    );
    package["Incomplete"] = serde_json::Value::Bool(true);
    package["Error"] = serde_json::json!({"Err": "missing dependency"});
    let error = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"d".repeat(64),
        serde_json::to_string(&package).unwrap().as_bytes(),
    )
    .unwrap_err();
    assert!(error.contains("incomplete"));

    let error = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"d".repeat(64),
        br#"{"Dir": "unfinished""#,
    )
    .unwrap_err();
    assert!(error.contains("parse"));

    let mut escaped = package_json(
        root.path(),
        Some("/workspace"),
        PackageFixture {
            module_directory: "",
            module_path: "example.com/sample",
            package_directory: "api",
            import_path: "example.com/sample/api",
            name: "api",
            go_files: &["api.go"],
            ignored_go_files: &[],
        },
    );
    escaped["Dir"] = serde_json::Value::String("/outside/api".to_string());
    let error = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"d".repeat(64),
        serde_json::to_string(&escaped).unwrap().as_bytes(),
    )
    .unwrap_err();
    assert!(error.contains("outside the emitted repository"));
}

#[test]
fn collector_executes_every_tracked_go_module_exactly_once() {
    let (root, inventory) = repository();
    let call_count = Cell::new(0);
    let mut manifests = Vec::new();
    let census = census_go_project_models_with_executor(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
        |execution_root, manifest| {
            call_count.set(call_count.get() + 1);
            manifests.push(manifest.to_string());
            Ok(GoListExecutionOutput {
                toolchain_identity_sha256: "e".repeat(64),
                stdout: String::from_utf8(go_list_output(execution_root, manifest)).unwrap(),
            })
        },
    )
    .unwrap();

    assert_eq!(call_count.get(), 2);
    assert_eq!(manifests, ["go.mod", "tools/go.mod"]);
    assert_eq!(census.executions.len(), 2);
    assert_eq!(census.targets.len(), 3);
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn collector_rejects_repository_mutation_by_go_list_boundary() {
    let (root, inventory) = repository();
    let error = census_go_project_models_with_executor(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
        |_, manifest| {
            fs::write(root.path().join("api/api.go"), "package api\n").unwrap();
            Ok(GoListExecutionOutput {
                toolchain_identity_sha256: "f".repeat(64),
                stdout: String::from_utf8(go_list_output(root.path(), manifest)).unwrap(),
            })
        },
    )
    .unwrap_err();

    assert!(error.contains("changed") || error.contains("dirty"));
}

#[test]
fn binds_go_package_source_sets_to_exact_compiler_subjects() {
    let (root, inventory) = repository();
    let project_model = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"1".repeat(64),
        &go_list_output(root.path(), "go.mod"),
    )
    .unwrap();
    let (source, semantic) = semantic_censuses(root.path(), &inventory);
    let bindings = super::super::bind_intentional_boundary_project_models(
        &inventory,
        &source,
        &semantic,
        &project_model,
    )
    .unwrap();

    assert_eq!(bindings.bound_target_count, 2);
    assert_eq!(bindings.binding_unresolved_target_count, 0);
    let subject_names = bindings
        .bindings
        .iter()
        .flat_map(|binding| match &binding.outcome {
            IntentionalBoundaryProjectModelBindingOutcome::Bound { subjects } => subjects
                .iter()
                .map(|subject| subject.subject_symbol_id.as_str())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect::<Vec<_>>();
    assert!(subject_names.iter().any(|name| name.ends_with(" Public")));
    assert!(subject_names.iter().any(|name| name.ends_with(" More")));
    assert!(
        subject_names
            .iter()
            .any(|name| name.ends_with(" WindowsOnly"))
    );
    assert_eq!(
        subject_names
            .iter()
            .filter(|name| name.ends_with(" main"))
            .count(),
        1
    );
    super::super::validate_intentional_boundary_project_model_bindings(
        &inventory,
        &source,
        &semantic,
        &project_model,
        &bindings,
    )
    .unwrap();
}

#[test]
fn real_go_list_is_sandboxed_or_fails_as_typed_unavailable() {
    let (root, inventory) = repository();
    let go_available = Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success());
    let result = census_intentional_boundary_go_project_models(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
    );
    if go_available {
        let census = result.unwrap();
        assert_eq!(census.executions.len(), 2);
        assert_eq!(census.targets.len(), 3);
        validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
    } else {
        let error = result.unwrap_err();
        assert!(
            error.contains("runtime is unavailable"),
            "unexpected missing-Go error: {error}"
        );
    }
}
