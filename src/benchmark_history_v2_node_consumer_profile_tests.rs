use super::super::IntentionalBoundaryProjectModelExecution;
use super::*;
use std::fs;
use std::process::Command;

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

fn fixture() -> (
    tempfile::TempDir,
    IntentionalBoundaryRepositoryInventory,
    HistoricalV2NodePackageSurfaceCensus,
    IntentionalBoundaryProjectModelCensus,
) {
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
            "https://github.com/example/node-consumer.git",
        ],
    );
    fs::create_dir_all(root.path().join("packages/pkg/src")).unwrap();
    fs::write(
        root.path().join("packages/pkg/package.json"),
        r#"{
  "name": "@example/pkg",
  "exports": {
    ".": {
      "types": "./src/index.ts",
      "development": "./src/development.ts",
      "default": "./dist/index.js"
    }
  }
}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/pkg/src/index.ts"),
        "export const value: number = 1;\n",
    )
    .unwrap();
    fs::write(
        root.path().join("packages/pkg/src/development.ts"),
        "export const value = 2;\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/node-consumer";
    let inventory =
        super::super::inventory_intentional_boundary_repository(repository, &revision, root.path())
            .unwrap();
    let packages =
        super::super::history_v2_node_package_surface::census_historical_v2_node_package_surfaces(
            repository,
            &revision,
            root.path(),
            &inventory,
        )
        .unwrap();
    let config_object_id = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == "packages/pkg/package.json")
        .unwrap()
        .object_id
        .clone();
    let project_model = IntentionalBoundaryProjectModelCensus {
        schema_version: 7,
        project_model_contract: "fixture".to_string(),
        repository: repository.to_string(),
        revision,
        inventory_sha256: inventory.inventory_sha256.clone(),
        executions: vec![IntentionalBoundaryProjectModelExecution {
            execution_id: "typescript-world".to_string(),
            provider: IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi,
            variant: IntentionalBoundaryProjectModelVariant::TypeScript {
                root_config_repository_path: None,
                compiler_version: "5.6.2".to_string(),
                projects: vec![IntentionalBoundaryProjectModelTypeScriptProject {
                    config_repository_path: None,
                    config_object_id: None,
                    config_reads: Vec::new(),
                    project_references: Vec::new(),
                    effective_compiler_options_json:
                        r#"{"customConditions":["development"],"moduleResolution":99}"#.to_string(),
                    source_repository_paths: vec!["packages/pkg/src/index.ts".to_string()],
                }],
                selected_source_repository_paths: vec![
                    "packages/pkg/src/development.ts".to_string(),
                    "packages/pkg/src/index.ts".to_string(),
                ],
                ignored_source_repository_paths: Vec::new(),
            },
            invocation_anchor_repository_path: "packages/pkg/package.json".to_string(),
            invocation_anchor_object_id: config_object_id,
            toolchain_identity_sha256: "a".repeat(64),
            command_contract: "fixture".to_string(),
            normalized_model_sha256: "b".repeat(64),
            covered_manifest_repository_paths: Vec::new(),
            target_count: 1,
        }],
        targets: Vec::new(),
        execution_count_by_provider: BTreeMap::from([(
            IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi,
            1,
        )]),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: "c".repeat(64),
    };
    (root, inventory, packages, project_model)
}

fn custom_fixture(
    package_json: &str,
    files: &[(&str, &str)],
    compiler_options_json: &str,
    project_sources: &[&str],
) -> (
    tempfile::TempDir,
    IntentionalBoundaryRepositoryInventory,
    HistoricalV2NodePackageSurfaceCensus,
    IntentionalBoundaryProjectModelCensus,
) {
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
            "https://github.com/example/node-consumer.git",
        ],
    );
    let package = root.path().join("packages/pkg/package.json");
    fs::create_dir_all(package.parent().unwrap()).unwrap();
    fs::write(&package, package_json).unwrap();
    for (repository_path, contents) in files {
        let path = root.path().join(repository_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/node-consumer";
    let inventory =
        super::super::inventory_intentional_boundary_repository(repository, &revision, root.path())
            .unwrap();
    let packages =
        super::super::history_v2_node_package_surface::census_historical_v2_node_package_surfaces(
            repository,
            &revision,
            root.path(),
            &inventory,
        )
        .unwrap();
    let manifest_object_id = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == "packages/pkg/package.json")
        .unwrap()
        .object_id
        .clone();
    let project_model = IntentionalBoundaryProjectModelCensus {
        schema_version: 7,
        project_model_contract: "fixture".to_string(),
        repository: repository.to_string(),
        revision,
        inventory_sha256: inventory.inventory_sha256.clone(),
        executions: vec![IntentionalBoundaryProjectModelExecution {
            execution_id: "typescript-world".to_string(),
            provider: IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi,
            variant: IntentionalBoundaryProjectModelVariant::TypeScript {
                root_config_repository_path: None,
                compiler_version: "5.6.2".to_string(),
                projects: vec![IntentionalBoundaryProjectModelTypeScriptProject {
                    config_repository_path: None,
                    config_object_id: None,
                    config_reads: Vec::new(),
                    project_references: Vec::new(),
                    effective_compiler_options_json: compiler_options_json.to_string(),
                    source_repository_paths: project_sources
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect(),
                }],
                selected_source_repository_paths: project_sources
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                ignored_source_repository_paths: Vec::new(),
            },
            invocation_anchor_repository_path: "packages/pkg/package.json".to_string(),
            invocation_anchor_object_id: manifest_object_id,
            toolchain_identity_sha256: "a".repeat(64),
            command_contract: "fixture".to_string(),
            normalized_model_sha256: "b".repeat(64),
            covered_manifest_repository_paths: Vec::new(),
            target_count: 1,
        }],
        targets: Vec::new(),
        execution_count_by_provider: BTreeMap::from([(
            IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi,
            1,
        )]),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: "c".repeat(64),
    };
    (root, inventory, packages, project_model)
}

fn resolved_fixture_census() -> (
    tempfile::TempDir,
    IntentionalBoundaryRepositoryInventory,
    HistoricalV2NodePackageSurfaceCensus,
    IntentionalBoundaryProjectModelCensus,
    HistoricalV2NodeConsumerProfileCensus,
) {
    let (root, inventory, packages, project_model) = fixture();
    let census = census_node_consumer_profiles_with_executor(
        &inventory,
        &packages,
        &project_model,
        |request| {
            let compiler = request
                .exposures
                .iter()
                .find(|exposure| {
                    exposure
                        .conditions
                        .iter()
                        .any(|value| value.name == "types")
                })
                .unwrap();
            let runtime = request
                .exposures
                .iter()
                .find(|exposure| {
                    exposure
                        .conditions
                        .iter()
                        .any(|value| value.name == "development")
                })
                .unwrap();
            let output = serde_json::json!({
                "schemaVersion": 1,
                "typescriptVersion": "5.6.2",
                "nodeVersion": "22.0.0",
                "compilerModuleResolution": "NodeNext",
                "compilerConditions": [
                    match request.mode {
                        HistoricalV2NodeConsumerMode::Import => "import",
                        HistoricalV2NodeConsumerMode::Require => "require",
                    },
                    "types",
                    "node",
                    "development"
                ],
                "customConditions": ["development"],
                "compiler": {
                    "selectedExposureId": compiler.exposure_id,
                    "ambiguous": false,
                    "resolvedRepositoryPath": "packages/pkg/src/index.ts",
                    "evidenceSha256": "d".repeat(64)
                },
                "runtime": {
                    "selectedExposureId": runtime.exposure_id,
                    "ambiguous": false,
                    "resolvedRepositoryPath": "packages/pkg/src/development.ts",
                    "evidenceSha256": "e".repeat(64)
                }
            });
            Ok(ConsumerProfileExecutorOutput {
                node_runtime_sha256: "f".repeat(64),
                toolchain_identity_sha256: "1".repeat(64),
                stdout: serde_json::to_string(&output).unwrap(),
            })
        },
    )
    .unwrap();
    (root, inventory, packages, project_model, census)
}

#[test]
fn compiler_and_runtime_branches_remain_distinct_per_consumer_mode() {
    let (_root, inventory, packages, project_model) = fixture();
    let types = packages
        .exposures
        .iter()
        .find(|exposure| {
            exposure
                .conditions
                .iter()
                .any(|value| value.name == "types")
        })
        .unwrap()
        .exposure_id
        .clone();
    let runtime = packages
        .exposures
        .iter()
        .find(|exposure| {
            exposure
                .conditions
                .iter()
                .any(|value| value.name == "development")
        })
        .unwrap()
        .exposure_id
        .clone();

    let census = census_node_consumer_profiles_with_executor(
        &inventory,
        &packages,
        &project_model,
        |request| {
            assert_eq!(request.specifier, "@example/pkg");
            assert_eq!(request.exposures.len(), 3);
            let output = serde_json::json!({
                "schemaVersion": 1,
                "typescriptVersion": "5.6.2",
                "nodeVersion": "22.0.0",
                "compilerModuleResolution": "NodeNext",
                "compilerConditions": [
                    match request.mode {
                        HistoricalV2NodeConsumerMode::Import => "import",
                        HistoricalV2NodeConsumerMode::Require => "require",
                    },
                    "types",
                    "node",
                    "development"
                ],
                "customConditions": ["development"],
                "compiler": {
                    "selectedExposureId": types,
                    "ambiguous": false,
                    "resolvedRepositoryPath": "packages/pkg/src/index.ts",
                    "evidenceSha256": "d".repeat(64)
                },
                "runtime": {
                    "selectedExposureId": runtime,
                    "ambiguous": false,
                    "resolvedRepositoryPath": "packages/pkg/src/development.ts",
                    "evidenceSha256": "e".repeat(64)
                }
            });
            Ok(ConsumerProfileExecutorOutput {
                node_runtime_sha256: "f".repeat(64),
                toolchain_identity_sha256: "1".repeat(64),
                stdout: serde_json::to_string(&output).unwrap(),
            })
        },
    )
    .unwrap();

    assert_eq!(census.profiles.len(), 2);
    assert_eq!(census.unresolved_resolution_count, 0);
    assert_ne!(
        census.profiles[0].consumer_surface_slot_id,
        census.profiles[1].consumer_surface_slot_id
    );
    for profile in &census.profiles {
        assert!(matches!(
            profile.compiler,
            HistoricalV2NodeConsumerResolution::Resolved { .. }
        ));
        assert!(matches!(
            profile.runtime,
            HistoricalV2NodeConsumerResolution::Resolved { .. }
        ));
    }
    validate_historical_v2_node_consumer_profile_census_commitment(
        &inventory,
        &packages,
        &project_model,
        &census,
    )
    .unwrap();
}

#[test]
fn ambiguous_compiler_branch_is_committed_as_unresolved() {
    let (_root, inventory, packages, project_model) = fixture();
    let census = census_node_consumer_profiles_with_executor(
        &inventory,
        &packages,
        &project_model,
        |_request| {
            Ok(ConsumerProfileExecutorOutput {
                node_runtime_sha256: "f".repeat(64),
                toolchain_identity_sha256: "1".repeat(64),
                stdout: serde_json::to_string(&serde_json::json!({
                    "schemaVersion": 1,
                    "typescriptVersion": "5.6.2",
                    "nodeVersion": "22.0.0",
                    "compilerModuleResolution": "NodeNext",
                    "compilerConditions": [
                        match _request.mode {
                            HistoricalV2NodeConsumerMode::Import => "import",
                            HistoricalV2NodeConsumerMode::Require => "require",
                        },
                        "types",
                        "node",
                        "development"
                    ],
                    "customConditions": ["development"],
                    "compiler": {
                        "selectedExposureId": null,
                        "ambiguous": true,
                        "resolvedRepositoryPath": "packages/pkg/src/index.ts",
                        "evidenceSha256": "d".repeat(64)
                    },
                    "runtime": {
                        "selectedExposureId": null,
                        "ambiguous": false,
                        "resolvedRepositoryPath": null,
                        "evidenceSha256": "e".repeat(64)
                    }
                }))
                .unwrap(),
            })
        },
    )
    .unwrap();

    assert_eq!(census.unresolved_resolution_count, 4);
    assert!(census.profiles.iter().all(|profile| matches!(
        profile.compiler,
        HistoricalV2NodeConsumerResolution::Unresolved {
            reason: HistoricalV2NodeConsumerUnresolvedReason::CompilerBranchAmbiguous,
            ..
        }
    )));
}

#[test]
fn unresolved_profiles_do_not_invent_a_node_runtime_identity() {
    let (_root, inventory, mut packages, project_model) = fixture();
    packages.documents[0].package_name = None;
    let census = census_node_consumer_profiles_with_executor(
        &inventory,
        &packages,
        &project_model,
        |_request| panic!("resolver must not run without a package specifier"),
    )
    .unwrap();

    assert!(!census.profiles.is_empty());
    assert!(census.node_runtime_version.is_none());
    assert!(census.node_runtime_sha256.is_none());
    assert!(
        census
            .profiles
            .iter()
            .all(|profile| profile.toolchain_identity_sha256.is_none())
    );
}

#[test]
fn unresolved_package_identity_preserves_every_compiler_project_and_mode() {
    let (_root, inventory, mut packages, mut project_model) = fixture();
    packages.documents[0].package_name = None;
    let IntentionalBoundaryProjectModelVariant::TypeScript { projects, .. } =
        &mut project_model.executions[0].variant
    else {
        panic!("fixture lost its TypeScript world")
    };
    let mut second = projects[0].clone();
    second.config_repository_path = Some("packages/pkg/tsconfig.secondary.json".to_string());
    projects.push(second);

    let census = census_node_consumer_profiles_with_executor(
        &inventory,
        &packages,
        &project_model,
        |_request| panic!("resolver must not run without a package specifier"),
    )
    .unwrap();

    assert_eq!(census.profiles.len(), 4);
    assert_eq!(
        census
            .profiles
            .iter()
            .map(|profile| (
                profile.compiler_project_config_repository_path.as_deref(),
                profile.mode,
            ))
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
}

#[test]
fn validation_rebinds_compiler_options_to_the_exact_project() {
    let (_root, inventory, packages, project_model, mut census) = resolved_fixture_census();
    census.profiles[0].compiler_options_sha256 = Some("9".repeat(64));
    census.profiles[0].profile_id = profile_id(&census.profiles[0]).unwrap();
    census.profiles.sort();
    census.census_sha256 = consumer_profile_census_sha256(&census).unwrap();

    let error = validate_historical_v2_node_consumer_profile_census_commitment(
        &inventory,
        &packages,
        &project_model,
        &census,
    )
    .unwrap_err();
    assert!(error.contains("commitment changed"));
}

#[test]
fn validation_reconstructs_complete_mode_and_project_coverage() {
    let (_root, inventory, packages, project_model, mut census) = resolved_fixture_census();
    census.profiles.pop();
    census.profile_count_by_mode = count_by_mode(&census.profiles);
    census.unresolved_resolution_count = unresolved_count(&census.profiles);
    census.census_sha256 = consumer_profile_census_sha256(&census).unwrap();

    let error = validate_historical_v2_node_consumer_profile_census_commitment(
        &inventory,
        &packages,
        &project_model,
        &census,
    )
    .unwrap_err();
    assert!(error.contains("coverage changed"), "{error}");
}

#[test]
fn validation_reconstructs_compiler_conditions_from_project_options() {
    let (_root, inventory, packages, project_model, mut census) = resolved_fixture_census();
    census.profiles[0]
        .compiler_conditions
        .retain(|condition| condition != "development");
    census.profiles[0].custom_conditions.clear();
    census.profiles[0].profile_id = profile_id(&census.profiles[0]).unwrap();
    census.profiles.sort();
    census.census_sha256 = consumer_profile_census_sha256(&census).unwrap();

    assert!(
        validate_historical_v2_node_consumer_profile_census_commitment(
            &inventory,
            &packages,
            &project_model,
            &census,
        )
        .is_err()
    );
}

#[test]
fn unsupported_compiler_module_resolution_fails_closed() {
    let (_root, inventory, packages, project_model) = fixture();
    let error = census_node_consumer_profiles_with_executor(
        &inventory,
        &packages,
        &project_model,
        |_request| {
            Ok(ConsumerProfileExecutorOutput {
                node_runtime_sha256: "f".repeat(64),
                toolchain_identity_sha256: "1".repeat(64),
                stdout: serde_json::to_string(&serde_json::json!({
                    "schemaVersion": 1,
                    "typescriptVersion": "5.6.2",
                    "nodeVersion": "22.0.0",
                    "compilerModuleResolution": "FutureResolver",
                    "compilerConditions": [],
                    "customConditions": [],
                    "compiler": {
                        "selectedExposureId": null,
                        "ambiguous": false,
                        "resolvedRepositoryPath": null,
                        "evidenceSha256": "d".repeat(64)
                    },
                    "runtime": {
                        "selectedExposureId": null,
                        "ambiguous": false,
                        "resolvedRepositoryPath": null,
                        "evidenceSha256": "e".repeat(64)
                    }
                }))
                .unwrap(),
            })
        },
    )
    .unwrap_err();

    assert!(error.contains("unsupported TypeScript compiler module resolution"));
}

#[test]
#[ignore = "requires Node and the checksum-pinned TypeScript compiler installation"]
fn real_typescript_and_node_resolvers_select_the_active_conditions() {
    let (root, inventory, packages, project_model) = fixture();

    let census = census_historical_v2_node_consumer_profiles(
        root.path(),
        &inventory,
        &packages,
        &project_model,
    )
    .unwrap();
    let repeated = census_historical_v2_node_consumer_profiles(
        root.path(),
        &inventory,
        &packages,
        &project_model,
    )
    .unwrap();

    assert_eq!(census, repeated);
    assert_eq!(census.profiles.len(), 2);
    assert_eq!(census.unresolved_resolution_count, 0);
    assert_eq!(census.typescript_compiler_version.as_deref(), Some("5.6.2"));
    assert!(census.node_runtime_version.is_some());
    for profile in &census.profiles {
        assert!(profile.compiler_conditions.contains(&"types".to_string()));
        assert!(
            profile
                .compiler_conditions
                .contains(&"development".to_string())
        );
        let HistoricalV2NodeConsumerResolution::Resolved {
            declared_target_repository_path,
            resolved_repository_path,
            ..
        } = &profile.compiler
        else {
            panic!("compiler profile is unresolved")
        };
        assert_eq!(declared_target_repository_path, "packages/pkg/src/index.ts");
        assert_eq!(resolved_repository_path, "packages/pkg/src/index.ts");
        let HistoricalV2NodeConsumerResolution::Resolved {
            declared_target_repository_path,
            resolved_repository_path,
            ..
        } = &profile.runtime
        else {
            panic!("runtime profile is unresolved")
        };
        assert_eq!(
            declared_target_repository_path,
            "packages/pkg/src/development.ts"
        );
        assert_eq!(resolved_repository_path, "packages/pkg/src/development.ts");
    }
}

#[test]
#[ignore = "requires Node and the checksum-pinned TypeScript compiler installation"]
fn real_resolvers_preserve_null_array_fallback_identity_without_executing_targets() {
    let (root, inventory, packages, project_model) = custom_fixture(
        r#"{
  "name": "@example/pkg",
  "type": "module",
  "exports": {
    ".": {
      "types": [null, "./src/index.ts"],
      "default": [null, "./src/runtime.js"]
    }
  }
}"#,
        &[
            (
                "packages/pkg/src/index.ts",
                "export const value: number = 1;\n",
            ),
            (
                "packages/pkg/src/runtime.js",
                "throw new Error('resolution must not execute package code');\n",
            ),
        ],
        r#"{"module":199,"moduleResolution":99}"#,
        &["packages/pkg/src/index.ts", "packages/pkg/src/runtime.js"],
    );

    let census = census_historical_v2_node_consumer_profiles(
        root.path(),
        &inventory,
        &packages,
        &project_model,
    )
    .unwrap();

    assert_eq!(census.profiles.len(), 2);
    assert_eq!(census.unresolved_resolution_count, 0);
    for profile in &census.profiles {
        for resolution in [&profile.compiler, &profile.runtime] {
            let HistoricalV2NodeConsumerResolution::Resolved {
                selected_exposure_id,
                ..
            } = resolution
            else {
                panic!("array fallback profile is unresolved")
            };
            let exposure = packages
                .exposures
                .iter()
                .find(|value| value.exposure_id == *selected_exposure_id)
                .unwrap();
            assert_eq!(exposure.fallback_indices, vec![1]);
        }
    }
}

#[test]
#[ignore = "requires Node and the checksum-pinned TypeScript compiler installation"]
fn real_resolvers_apply_legacy_typings_and_main_precedence() {
    let (root, inventory, packages, project_model) = custom_fixture(
        r#"{
  "name": "@example/pkg",
  "types": "./src/index.ts",
  "typings": "./src/obsolete.ts",
  "module": "./src/ignored.mjs",
  "main": "./src/runtime.cjs"
}"#,
        &[
            (
                "packages/pkg/src/index.ts",
                "export const value: number = 1;\n",
            ),
            (
                "packages/pkg/src/obsolete.ts",
                "export const obsolete = true;\n",
            ),
            (
                "packages/pkg/src/ignored.mjs",
                "export const ignored = true;\n",
            ),
            (
                "packages/pkg/src/runtime.cjs",
                "throw new Error('resolution must not execute package code');\n",
            ),
        ],
        r#"{"module":199,"moduleResolution":99}"#,
        &["packages/pkg/src/index.ts", "packages/pkg/src/obsolete.ts"],
    );

    let census = census_historical_v2_node_consumer_profiles(
        root.path(),
        &inventory,
        &packages,
        &project_model,
    )
    .unwrap();

    assert_eq!(census.unresolved_resolution_count, 0);
    for profile in &census.profiles {
        let HistoricalV2NodeConsumerResolution::Resolved {
            declared_target_repository_path,
            ..
        } = &profile.compiler
        else {
            panic!("legacy compiler profile is unresolved")
        };
        assert_eq!(
            declared_target_repository_path,
            "packages/pkg/src/obsolete.ts"
        );
        let HistoricalV2NodeConsumerResolution::Resolved {
            declared_target_repository_path,
            ..
        } = &profile.runtime
        else {
            panic!("legacy runtime profile is unresolved")
        };
        assert_eq!(
            declared_target_repository_path,
            "packages/pkg/src/runtime.cjs"
        );
    }
}

#[test]
#[ignore = "requires Node and the checksum-pinned TypeScript compiler installation"]
fn real_compiler_maps_generated_declarations_back_to_exact_source_identity() {
    let (root, inventory, packages, project_model) = custom_fixture(
        r#"{
  "name": "@example/pkg",
  "type": "module",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    }
  }
}"#,
        &[(
            "packages/pkg/src/index.ts",
            "export const value: number = 1;\n",
        )],
        r#"{"module":199,"moduleResolution":99,"rootDir":"<repo>/packages/pkg/src","outDir":"<repo>/packages/pkg/dist","declaration":true}"#,
        &["packages/pkg/src/index.ts"],
    );

    let census = census_historical_v2_node_consumer_profiles(
        root.path(),
        &inventory,
        &packages,
        &project_model,
    )
    .unwrap();

    assert_eq!(census.unresolved_resolution_count, 0);
    for profile in &census.profiles {
        let HistoricalV2NodeConsumerResolution::Resolved {
            declared_target_repository_path,
            resolved_repository_path,
            compiler_source_substitution,
            ..
        } = &profile.compiler
        else {
            panic!("generated declaration compiler profile is unresolved")
        };
        assert_eq!(
            declared_target_repository_path,
            "packages/pkg/dist/index.d.ts"
        );
        assert_eq!(resolved_repository_path, "packages/pkg/src/index.ts");
        assert!(*compiler_source_substitution);
        let HistoricalV2NodeConsumerResolution::Resolved {
            resolved_object_id, ..
        } = &profile.runtime
        else {
            panic!("generated runtime profile is unresolved")
        };
        assert!(resolved_object_id.is_none());
    }
}
