use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundaryProjectModelBindingOutcome,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceCensus,
};
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
            "https://github.com/example/gradle-model.git",
        ],
    );
    for (path, source) in [
        (
            "settings.gradle.kts",
            "rootProject.name = \"fixture\"\ninclude(\":app\", \":library\", \":misc\")\n",
        ),
        ("build.gradle.kts", "plugins { base }\n"),
        (
            "app/build.gradle.kts",
            "plugins { application; kotlin(\"jvm\") version \"2.2.0\" }\n",
        ),
        (
            "app/src/main/kotlin/App.kt",
            "package fixture.app\nfun helper() = 1\nfun main() {}\n",
        ),
        (
            "library/build.gradle.kts",
            "plugins { `java-library`; kotlin(\"jvm\") version \"2.2.0\" }\n",
        ),
        (
            "library/src/main/kotlin/Api.kt",
            "package fixture.library\nfun publicApi() = 1\n",
        ),
        (
            "library/src/main/kotlin/More.kt",
            "package fixture.library\nfun moreApi() = 2\n",
        ),
        (
            "misc/build.gradle.kts",
            "plugins { kotlin(\"jvm\") version \"2.2.0\" }\n",
        ),
        (
            "misc/src/main/kotlin/Misc.kt",
            "package fixture.misc\nfun misc() = 3\n",
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
        "github.com/example/gradle-model",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, inventory)
}

fn runtime_repository() -> (TempDir, IntentionalBoundaryRepositoryInventory) {
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
            "https://github.com/example/gradle-runtime-model.git",
        ],
    );
    for (path, source) in [
        (
            "settings.gradle.kts",
            "rootProject.name = \"runtime-fixture\"\n",
        ),
        ("build.gradle.kts", "plugins { application }\n"),
        (
            "src/main/java/example/Main.java",
            "package example; public final class Main { public static void main(String[] args) {} }\n",
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
        "github.com/example/gradle-runtime-model",
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

fn project_json(
    root: &Path,
    emitted_root: Option<&str>,
    path: &str,
    name: &str,
    directory: &str,
    kinds: &[&str],
    sources: &[&str],
) -> serde_json::Value {
    let build_file = if directory.is_empty() {
        "build.gradle.kts".to_string()
    } else {
        format!("{directory}/build.gradle.kts")
    };
    serde_json::json!({
        "project_path": path,
        "project_name": name,
        "group_name": "com.example",
        "project_version": "1.2.3",
        "project_directory": model_path(root, emitted_root, directory),
        "build_file": model_path(root, emitted_root, &build_file),
        "build_file_exists": true,
        "provider_kinds": kinds,
        "production_source_files": sources
            .iter()
            .map(|source| model_path(root, emitted_root, source))
            .collect::<Vec<_>>(),
        "producer_tasks": []
    })
}

fn tooling_output(root: &Path) -> Vec<u8> {
    tooling_output_at(root, None)
}

fn tooling_output_at(root: &Path, emitted_root: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "contract": "sniff-gradle-tooling-project-model-v4",
        "tooling_api_version": "8.8",
        "gradle_version": "8.8",
        "settings_directory": model_path(root, emitted_root, ""),
        "projects": [
            project_json(root, emitted_root, ":", "fixture", "", &["unclassified"], &[]),
            project_json(
                root,
                emitted_root,
                ":app",
                "app",
                "app",
                &["application"],
                &["app/src/main/kotlin/App.kt"],
            ),
            project_json(
                root,
                emitted_root,
                ":library",
                "library",
                "library",
                &["java_library", "publication"],
                &[
                    "library/src/main/kotlin/Api.kt",
                    "library/src/main/kotlin/More.kt",
                ],
            ),
            project_json(
                root,
                emitted_root,
                ":misc",
                "misc",
                "misc",
                &["unclassified"],
                &["misc/src/main/kotlin/Misc.kt"],
            )
        ]
    }))
    .unwrap()
}

fn library_producer(root: &Path, emitted_root: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "task_path": ":library:writeGenerated",
        "task_type": "org.gradle.api.DefaultTask",
        "output_files": [model_path(root, emitted_root, "library/src/main/kotlin")],
        "production_source_files": [
            model_path(root, emitted_root, "library/src/main/kotlin/Api.kt"),
            model_path(root, emitted_root, "library/src/main/kotlin/More.kt"),
        ]
    })
}

fn tooling_output_with_library_producer(root: &Path, emitted_root: Option<&str>) -> Vec<u8> {
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output_at(root, emitted_root)).unwrap();
    model["projects"][2]["producer_tasks"] =
        serde_json::Value::Array(vec![library_producer(root, emitted_root)]);
    serde_json::to_vec(&model).unwrap()
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
                    indexer: IntentionalBoundaryIndexerKind::Kotlin,
                    status: IntentionalBoundarySemanticMethodStatus::Resolved {
                        symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                            symbol_id: format!(
                                "kotlin fixture {} {}",
                                file.repository_path, method.symbol_name
                            ),
                            provider_identity: format!(
                                "kotlin fixture {} {}",
                                file.repository_path, method.symbol_name
                            ),
                            display_name: Some(method.symbol_name.clone()),
                            category: IntentionalBoundarySemanticSymbolCategory::Callable,
                            provider_kind: "function".to_string(),
                            documentation: Vec::new(),
                            signature: None,
                            signature_referenced_symbols: Vec::new(),
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
            indexer: IntentionalBoundaryIndexerKind::Kotlin,
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
fn normalizes_gradle_roles_and_exact_production_source_sets() {
    let (root, inventory) = repository();
    let output = tooling_output(root.path());
    let census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        &output,
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 3);
    assert_eq!(
        census.executions[0].covered_manifest_repository_paths.len(),
        5
    );
    assert!(census.targets.iter().any(|target| matches!(
        target.target_status,
        TargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
            ..
        }
    )));
    assert!(census.targets.iter().any(|target| matches!(
        target.target_status,
        TargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
            ..
        }
    )));
    assert!(census.targets.iter().any(|target| matches!(
        target.target_status,
        TargetStatus::Unresolved {
            reason: UnresolvedReason::UnknownTargetKind,
            ..
        }
    )));
    validate_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        &output,
        &census,
    )
    .unwrap();
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn normalizes_exact_gradle_producer_tasks_from_the_tooling_model() {
    let (root, inventory) = repository();
    let census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        &tooling_output_with_library_producer(root.path(), None),
    )
    .unwrap();

    let library = census
        .targets
        .iter()
        .find(|target| target.target_name == ":library")
        .unwrap();
    assert_eq!(library.producer_tasks.len(), 1);
    assert_eq!(
        library.producer_tasks[0].task_path,
        ":library:writeGenerated"
    );
    assert_eq!(
        library.producer_tasks[0].source_repository_paths,
        [
            "library/src/main/kotlin/Api.kt",
            "library/src/main/kotlin/More.kt"
        ]
    );
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn normalizes_declared_gradle_outputs_that_do_not_exist_until_execution() {
    let (root, inventory) = repository();
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output_with_library_producer(root.path(), None)).unwrap();
    model["projects"][2]["producer_tasks"][0]["output_files"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(format!(
            "{}/library/build/generated/prepared.txt",
            emitted_path(root.path(), "")
                .trim_end_matches('/')
                .trim_end_matches('\\')
        )));
    let census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        serde_json::to_string(&model).unwrap().as_bytes(),
    )
    .unwrap();
    let library = census
        .targets
        .iter()
        .find(|target| target.target_name == ":library")
        .unwrap();

    assert!(
        library.producer_tasks[0]
            .output_repository_paths
            .contains(&"library/build/generated/prepared.txt".to_string())
    );
}

#[test]
fn rejects_gradle_producer_outputs_outside_the_repository_or_at_project_root() {
    let (root, inventory) = repository();
    let mut escaped: serde_json::Value = serde_json::from_slice(
        &tooling_output_with_library_producer(root.path(), Some("/workspace")),
    )
    .unwrap();
    escaped["projects"][2]["producer_tasks"][0]["output_files"][0] =
        serde_json::Value::String("/outside/generated".to_string());
    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        serde_json::to_string(&escaped).unwrap().as_bytes(),
    )
    .unwrap_err();
    assert!(error.contains("outside the emitted repository"));

    let mut broad: serde_json::Value =
        serde_json::from_slice(&tooling_output_with_library_producer(root.path(), None)).unwrap();
    broad["projects"][2]["producer_tasks"][0]["output_files"][0] =
        serde_json::Value::String(emitted_path(root.path(), "library"));
    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        serde_json::to_string(&broad).unwrap().as_bytes(),
    )
    .unwrap_err();
    assert!(error.contains("entire project"));
}

#[test]
fn rejects_gradle_producer_sources_not_owned_by_the_compiler_target() {
    let (root, inventory) = repository();
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output_with_library_producer(root.path(), None)).unwrap();
    model["projects"][2]["producer_tasks"][0]["production_source_files"][0] =
        serde_json::Value::String(emitted_path(root.path(), "app/src/main/kotlin/App.kt"));
    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        serde_json::to_string(&model).unwrap().as_bytes(),
    )
    .unwrap_err();

    assert!(error.contains("changed ownership"));
}

#[test]
fn rejects_duplicate_gradle_producer_tasks_without_collapsing_them() {
    let (root, inventory) = repository();
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output_with_library_producer(root.path(), None)).unwrap();
    let producer = model["projects"][2]["producer_tasks"][0].clone();
    model["projects"][2]["producer_tasks"]
        .as_array_mut()
        .unwrap()
        .push(producer);
    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        serde_json::to_string(&model).unwrap().as_bytes(),
    )
    .unwrap_err();

    assert!(error.contains("repeated a producer task"));
}

#[test]
fn recommitted_tampered_gradle_producer_changes_the_model_commitment() {
    let (root, inventory) = repository();
    let mut census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        &tooling_output_with_library_producer(root.path(), None),
    )
    .unwrap();
    let library = census
        .targets
        .iter_mut()
        .find(|target| target.target_name == ":library")
        .unwrap();
    library.producer_tasks[0].task_path = ":library:invented".to_string();

    assert!(
        validate_intentional_boundary_project_model_census_commitment(&inventory, &census)
            .unwrap_err()
            .contains("changed")
    );
}

#[test]
fn gradle_producer_identity_ignores_checkout_location() {
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
    let parse = |checkout: &Path| {
        parse_intentional_boundary_gradle_tooling_model(
            checkout,
            &inventory,
            "settings.gradle.kts",
            &"b".repeat(64),
            &tooling_output_with_library_producer(checkout, None),
        )
        .unwrap()
    };

    assert_eq!(parse(root.path()), parse(clone.path()));
}

#[test]
fn maps_gradle_sandbox_paths_back_to_the_immutable_snapshot() {
    let (root, inventory) = repository();
    let output = tooling_output_at(root.path(), Some("/workspace"));

    let census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        &output,
    )
    .unwrap();

    assert_eq!(census.targets.len(), 3);
    assert!(census.targets.iter().all(|target| {
        target
            .source_repository_paths
            .iter()
            .all(|path| !path.starts_with('/') && !path.contains("workspace"))
    }));
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn gradle_model_identity_ignores_checkout_location() {
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
    let parse = |checkout: &Path| {
        parse_intentional_boundary_gradle_tooling_model(
            checkout,
            &inventory,
            "settings.gradle.kts",
            &"b".repeat(64),
            &tooling_output(checkout),
        )
        .unwrap()
    };

    assert_eq!(parse(root.path()), parse(clone.path()));
}

#[test]
fn untracked_gradle_sources_remain_typed_unresolved() {
    let (root, inventory) = repository();
    fs::write(
        root.path().join("library/src/main/kotlin/Untracked.kt"),
        "package fixture.library\n",
    )
    .unwrap();
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output(root.path())).unwrap();
    model["projects"][2]["production_source_files"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::Value::String(emitted_path(
            root.path(),
            "library/src/main/kotlin/Untracked.kt",
        )));
    let census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"c".repeat(64),
        serde_json::to_string(&model).unwrap().as_bytes(),
    )
    .unwrap();

    let library = census
        .targets
        .iter()
        .find(|target| target.target_name == ":library")
        .unwrap();
    assert!(matches!(
        library.target_status,
        TargetStatus::Unresolved {
            reason: UnresolvedReason::SourceNotTracked,
            ..
        }
    ));
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn rejects_unpinned_or_malformed_gradle_models() {
    let (root, inventory) = repository();
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output(root.path())).unwrap();
    model["gradle_version"] = serde_json::Value::String("9.0".to_string());
    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"d".repeat(64),
        serde_json::to_string(&model).unwrap().as_bytes(),
    )
    .unwrap_err();
    assert!(error.contains("pinned version"));

    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"d".repeat(64),
        br#"{"contract":"unfinished""#,
    )
    .unwrap_err();
    assert!(error.contains("parse"));

    let mut escaped: serde_json::Value =
        serde_json::from_slice(&tooling_output_at(root.path(), Some("/workspace"))).unwrap();
    escaped["projects"][1]["production_source_files"][0] =
        serde_json::Value::String("/outside/App.kt".to_string());
    let error = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"d".repeat(64),
        serde_json::to_string(&escaped).unwrap().as_bytes(),
    )
    .unwrap_err();
    assert!(error.contains("outside the emitted repository"));
}

#[test]
fn accepts_gradle_owned_non_ascii_project_names_without_guessing_a_policy() {
    let (root, inventory) = repository();
    let mut model: serde_json::Value =
        serde_json::from_slice(&tooling_output(root.path())).unwrap();
    model["projects"][2]["project_path"] =
        serde_json::Value::String(":library with unicode-ç".to_string());
    model["projects"][2]["project_name"] =
        serde_json::Value::String("library with unicode-ç".to_string());

    let census = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"d".repeat(64),
        serde_json::to_string(&model).unwrap().as_bytes(),
    )
    .unwrap();

    assert!(
        census
            .targets
            .iter()
            .any(|target| target.target_name == ":library with unicode-ç")
    );
}

#[test]
fn binds_gradle_boundaries_only_to_exact_compiler_subjects() {
    let (root, inventory) = repository();
    let project_model = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"e".repeat(64),
        &tooling_output(root.path()),
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
    assert_eq!(bindings.upstream_unresolved_target_count, 1);
    assert_eq!(bindings.binding_unresolved_target_count, 0);
    let subjects = bindings
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
    assert!(
        subjects
            .iter()
            .any(|subject| subject.ends_with(" publicApi"))
    );
    assert!(subjects.iter().any(|subject| subject.ends_with(" moreApi")));
    assert_eq!(
        subjects
            .iter()
            .filter(|subject| subject.ends_with(" main"))
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
fn collector_executes_every_gradle_settings_root_and_preserves_inventory() {
    let (root, inventory) = repository();
    let mut calls = Vec::new();
    let census = census_gradle_project_models_with_executor(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
        |execution_root, settings| {
            calls.push(settings.to_string());
            Ok(GradleToolingExecutionOutput {
                toolchain_identity_sha256: "f".repeat(64),
                stdout: String::from_utf8(tooling_output(execution_root)).unwrap(),
            })
        },
    )
    .unwrap();

    assert_eq!(calls, ["settings.gradle.kts"]);
    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 3);
    validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
}

#[test]
fn collector_rejects_repository_mutation_by_gradle_boundary() {
    let (root, inventory) = repository();
    let error = census_gradle_project_models_with_executor(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
        |execution_root, _| {
            fs::write(
                root.path().join("library/src/main/kotlin/Api.kt"),
                "package changed\n",
            )
            .unwrap();
            Ok(GradleToolingExecutionOutput {
                toolchain_identity_sha256: "1".repeat(64),
                stdout: String::from_utf8(tooling_output(execution_root)).unwrap(),
            })
        },
    )
    .unwrap_err();

    assert!(error.contains("changed") || error.contains("dirty"));
}

#[test]
fn real_gradle_tooling_model_is_sandboxed_or_typed_unavailable() {
    let (root, inventory) = runtime_repository();
    let gradle_available = Command::new("gradle")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    let result = census_intentional_boundary_gradle_project_models(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
    );
    if gradle_available {
        let census = result.unwrap();
        assert_eq!(census.executions.len(), 1);
        assert_eq!(census.targets.len(), 1);
        assert!(matches!(
            census.targets[0].target_status,
            TargetStatus::Boundary {
                declaration_kind: IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
                ..
            }
        ));
        validate_intentional_boundary_project_model_census_commitment(&inventory, &census).unwrap();
    } else {
        let error = result.unwrap_err();
        assert!(
            error.contains("runtime is unavailable"),
            "unexpected missing-Gradle error: {error}"
        );
    }
}
