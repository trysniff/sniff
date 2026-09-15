use super::*;
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

fn repository() -> (TempDir, String, IntentionalBoundaryRepositoryInventory) {
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
            "https://github.com/example/typescript-model.git",
        ],
    );
    for (path, source) in [
        (
            "tsconfig.json",
            r#"{"extends":"./tsconfig.base.json","files":["src/index.ts"],"references":[{"path":"packages/core"}]}"#,
        ),
        (
            "tsconfig.base.json",
            r#"{"compilerOptions":{"strict":true}}"#,
        ),
        (
            "packages/core/tsconfig.json",
            r#"{"compilerOptions":{"composite":true},"files":["src/core.ts"]}"#,
        ),
        ("src/index.ts", "export function main(): void {}\n"),
        (
            "packages/core/src/core.ts",
            "export function core(): void {}\n",
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
        "github.com/example/typescript-model",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, revision, inventory)
}

fn compiler_output() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 2,
        "typescriptVersion": "5.6.2",
        "worlds": [{
            "rootConfig": "tsconfig.json",
            "inferred": false,
            "configClosure": ["packages/core/tsconfig.json", "tsconfig.json"],
            "diagnostics": [],
            "projects": [
                {
                    "configPath": "packages/core/tsconfig.json",
                    "configReads": ["packages/core/tsconfig.json"],
                    "diagnostics": [],
                    "effectiveOptions": {"composite": true},
                    "references": [],
                    "selectedSourceFiles": ["packages/core/src/core.ts"]
                },
                {
                    "configPath": "tsconfig.json",
                    "configReads": ["tsconfig.base.json", "tsconfig.json"],
                    "diagnostics": [],
                    "effectiveOptions": {"configFilePath": "<repo>/tsconfig.json"},
                    "references": ["packages/core/tsconfig.json"],
                    "selectedSourceFiles": ["src/index.ts"]
                }
            ],
            "rootSourceFiles": ["packages/core/src/core.ts", "src/index.ts"],
            "selectedSourceFiles": ["packages/core/src/core.ts", "src/index.ts"],
            "ignoredSourceFiles": []
        }]
    })
}

#[test]
fn compiler_project_world_commits_reference_closure_options_and_source_partition() {
    let (root, revision, inventory) = repository();
    let required = vec![
        "packages/core/src/core.ts".to_string(),
        "src/index.ts".to_string(),
    ];
    let census = census_typescript_project_models_with_executor(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &required,
        |_, configs, sources| {
            assert_eq!(
                configs,
                &[
                    "packages/core/tsconfig.json",
                    "tsconfig.base.json",
                    "tsconfig.json"
                ]
            );
            assert_eq!(sources, required);
            Ok(TypeScriptCompilerExecutionOutput {
                toolchain_identity_sha256: "a".repeat(64),
                stdout: compiler_output().to_string(),
            })
        },
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 2);
    assert_eq!(
        census.execution_count_by_provider,
        std::collections::BTreeMap::from([(Provider::TypeScriptCompilerApi, 1)])
    );
    let IntentionalBoundaryProjectModelVariant::TypeScript {
        root_config_repository_path,
        projects,
        selected_source_repository_paths,
        ignored_source_repository_paths,
        ..
    } = &census.executions[0].variant
    else {
        panic!("expected TypeScript project-model variant");
    };
    assert_eq!(
        root_config_repository_path.as_deref(),
        Some("tsconfig.json")
    );
    assert_eq!(projects.len(), 2);
    assert_eq!(selected_source_repository_paths, &required);
    assert!(ignored_source_repository_paths.is_empty());
    super::super::validate_intentional_boundary_project_model_census_commitment(
        &inventory, &census,
    )
    .unwrap();
}

#[test]
fn target_validation_reconstructs_the_matching_compiler_project_partition() {
    let (root, revision, inventory) = repository();
    let required = vec![
        "packages/core/src/core.ts".to_string(),
        "src/index.ts".to_string(),
    ];
    let census = census_typescript_project_models_with_executor(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &required,
        |_, _, _| {
            Ok(TypeScriptCompilerExecutionOutput {
                toolchain_identity_sha256: "a".repeat(64),
                stdout: compiler_output().to_string(),
            })
        },
    )
    .unwrap();
    let mut target = census.targets[0].clone();
    target.source_repository_paths = required;

    assert!(!validate_typescript_target_classification(
        &inventory,
        &target,
        &census.executions[0],
    ));
}

#[test]
fn compiler_diagnostics_cannot_become_a_committed_project_world() {
    let (root, revision, inventory) = repository();
    let mut output = compiler_output();
    output["worlds"][0]["diagnostics"] = serde_json::json!([{
        "category": "error",
        "code": 5083,
        "message": "Cannot read file"
    }]);
    let error = census_typescript_project_models_with_executor(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &["src/index.ts".to_string()],
        |_, _, _| {
            Ok(TypeScriptCompilerExecutionOutput {
                toolchain_identity_sha256: "a".repeat(64),
                stdout: output.to_string(),
            })
        },
    )
    .unwrap_err();

    assert!(error.contains("diagnostics"), "{error}");
}

#[test]
fn omitted_required_source_fails_closed() {
    let (root, revision, inventory) = repository();
    let mut output = compiler_output();
    output["worlds"][0]["selectedSourceFiles"] = serde_json::json!(["src/index.ts"]);
    output["worlds"][0]["rootSourceFiles"] = serde_json::json!(["src/index.ts"]);
    output["worlds"][0]["ignoredSourceFiles"] = serde_json::json!(["packages/core/src/core.ts"]);
    output["worlds"][0]["projects"][0]["selectedSourceFiles"] = serde_json::json!([]);
    let error = census_typescript_project_models_with_executor(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &[
            "packages/core/src/core.ts".to_string(),
            "src/index.ts".to_string(),
        ],
        |_, _, _| {
            Ok(TypeScriptCompilerExecutionOutput {
                toolchain_identity_sha256: "a".repeat(64),
                stdout: output.to_string(),
            })
        },
    )
    .unwrap_err();

    assert!(error.contains("selected no valid context"), "{error}");
}

#[test]
fn explicit_loose_world_covers_sources_omitted_by_repository_configs() {
    let (root, _, _) = repository();
    fs::write(
        root.path().join("src/index.test.ts"),
        "export function testMain(): void {}\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(
        root.path(),
        &["commit", "--quiet", "-m", "add loose source"],
    );
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
    )
    .unwrap();
    let mut output = compiler_output();
    output["worlds"][0]["ignoredSourceFiles"] = serde_json::json!(["src/index.test.ts"]);
    output["worlds"].as_array_mut().unwrap().push(serde_json::json!({
        "rootConfig": null,
        "inferred": true,
        "configClosure": [],
        "diagnostics": [],
        "projects": [{
            "configPath": null,
            "configReads": [],
            "diagnostics": [],
            "effectiveOptions": {"configFilePath": "<repo>/.sniff-typescript-loose-project.json", "noEmit": true},
            "references": [],
            "selectedSourceFiles": ["src/index.test.ts"]
        }],
        "rootSourceFiles": ["src/index.test.ts"],
        "selectedSourceFiles": ["src/index.test.ts"],
        "ignoredSourceFiles": ["packages/core/src/core.ts", "src/index.ts"]
    }));
    let required = vec![
        "packages/core/src/core.ts".to_string(),
        "src/index.test.ts".to_string(),
        "src/index.ts".to_string(),
    ];

    let census = census_typescript_project_models_with_executor(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &required,
        |_, _, _| {
            Ok(TypeScriptCompilerExecutionOutput {
                toolchain_identity_sha256: "c".repeat(64),
                stdout: output.to_string(),
            })
        },
    )
    .unwrap();

    assert_eq!(census.executions.len(), 2);
    let loose = census
        .executions
        .iter()
        .find(|execution| {
            matches!(
                &execution.variant,
                IntentionalBoundaryProjectModelVariant::TypeScript {
                    root_config_repository_path: None,
                    ..
                }
            )
        })
        .unwrap();
    let IntentionalBoundaryProjectModelVariant::TypeScript {
        selected_source_repository_paths,
        ignored_source_repository_paths,
        ..
    } = &loose.variant
    else {
        unreachable!();
    };
    assert_eq!(selected_source_repository_paths, &["src/index.test.ts"]);
    assert_eq!(
        ignored_source_repository_paths,
        &["packages/core/src/core.ts", "src/index.ts"]
    );
}

#[test]
fn inferred_world_is_explicit_and_bound_to_a_real_source_anchor() {
    let (root, _, _) = repository();
    git(
        root.path(),
        &[
            "rm",
            "tsconfig.json",
            "tsconfig.base.json",
            "packages/core/tsconfig.json",
        ],
    );
    git(root.path(), &["commit", "--quiet", "-m", "remove configs"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
    )
    .unwrap();
    let output = serde_json::json!({
        "schemaVersion": 2,
        "typescriptVersion": "5.6.2",
        "worlds": [{
            "rootConfig": null,
            "inferred": true,
            "configClosure": [],
            "diagnostics": [],
            "projects": [{
                "configPath": null,
                "configReads": [],
                "diagnostics": [],
                "effectiveOptions": {},
                "references": [],
                "selectedSourceFiles": ["src/index.ts"]
            }],
            "rootSourceFiles": ["src/index.ts"],
            "selectedSourceFiles": ["src/index.ts"],
            "ignoredSourceFiles": []
        }]
    });
    let census = census_typescript_project_models_with_executor(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &["src/index.ts".to_string()],
        |_, configs, _| {
            assert!(configs.is_empty());
            Ok(TypeScriptCompilerExecutionOutput {
                toolchain_identity_sha256: "b".repeat(64),
                stdout: output.to_string(),
            })
        },
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert_eq!(
        census.executions[0].invocation_anchor_repository_path,
        "src/index.ts"
    );
}

#[test]
#[ignore = "requires installed pinned TypeScript indexer and native sandbox"]
fn real_pinned_compiler_api_emits_the_reference_world() {
    let (root, revision, inventory) = repository();
    let census = census_intentional_boundary_typescript_project_models_typed(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &[
            "packages/core/src/core.ts".to_string(),
            "src/index.ts".to_string(),
        ],
    )
    .unwrap_or_else(|error| panic!("{error:#?}"));

    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 2);
}

#[test]
#[ignore = "requires installed pinned TypeScript indexer and native sandbox"]
fn real_pinned_compiler_api_emits_an_exact_loose_source_world() {
    let (root, _, _) = repository();
    for (path, source) in [
        ("src/index.test.ts", "export function testMain(): void {}\n"),
        ("rollup.config.js", "export default {};\n"),
    ] {
        fs::write(root.path().join(path), source).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(
        root.path(),
        &["commit", "--quiet", "-m", "add loose compiler sources"],
    );
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
    )
    .unwrap();
    let required = vec![
        "packages/core/src/core.ts".to_string(),
        "rollup.config.js".to_string(),
        "src/index.test.ts".to_string(),
        "src/index.ts".to_string(),
    ];

    let census = census_intentional_boundary_typescript_project_models_typed(
        "github.com/example/typescript-model",
        &revision,
        root.path(),
        &inventory,
        &required,
    )
    .unwrap_or_else(|error| panic!("{error:#?}"));

    assert_eq!(census.executions.len(), 2);
    assert_eq!(census.targets.len(), 3);
    let loose = census
        .executions
        .iter()
        .find(|execution| {
            matches!(
                execution.variant,
                IntentionalBoundaryProjectModelVariant::TypeScript {
                    root_config_repository_path: None,
                    ..
                }
            )
        })
        .unwrap();
    let IntentionalBoundaryProjectModelVariant::TypeScript {
        root_source_repository_paths,
        selected_source_repository_paths,
        ..
    } = &loose.variant
    else {
        unreachable!();
    };
    assert_eq!(
        root_source_repository_paths,
        &["rollup.config.js", "src/index.test.ts"]
    );
    assert_eq!(
        selected_source_repository_paths,
        root_source_repository_paths
    );
}
