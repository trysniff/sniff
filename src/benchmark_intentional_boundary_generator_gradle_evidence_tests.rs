use super::super::{ExpectedOutput, ReplaySuccess};
use crate::benchmark::release::{
    IntentionalBoundaryEvidenceProof, IntentionalBoundaryGeneratorEvidenceInputs,
    IntentionalBoundaryGeneratorExecution, IntentionalBoundaryGeneratorOutput,
    IntentionalBoundaryIndexerKind, IntentionalBoundaryProjectModelProofKind,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceCensus,
    bind_intentional_boundary_manifests, census_intentional_boundary_kotlin_ast,
    census_intentional_boundary_manifests, census_intentional_boundary_repository,
    compose_intentional_boundary_generator_evidence,
    extract_intentional_boundary_compiler_and_ast_evidence,
    inventory_intentional_boundary_repository, parse_intentional_boundary_gradle_tooling_model,
};
use std::fs;
use std::path::Path;
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn semantic_census(source: &IntentionalBoundarySourceCensus) -> IntentionalBoundarySemanticCensus {
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
                                "kotlin evidence fixture {} {}",
                                file.repository_path, method.symbol_name
                            ),
                            provider_identity: format!(
                                "kotlin evidence fixture {} {}",
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
                            visibility: IntentionalBoundarySemanticVisibility::Public,
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
        schema_version:
            crate::benchmark::release::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract:
            super::super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT.to_string(),
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
        source_references: Vec::new(),
        resolved_method_count: methods.len(),
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        methods,
        semantic_census_sha256: String::new(),
    };
    semantic.semantic_census_sha256 =
        super::super::super::intentional_boundary_semantic::compute_semantic_census_sha256(
            &semantic,
        )
        .unwrap();
    semantic
}

fn fake_replay(
    command: &super::super::GeneratorCommand,
    outputs: &[ExpectedOutput],
) -> ReplaySuccess {
    let execution = |run_number| IntentionalBoundaryGeneratorExecution {
        run_number,
        command: command.execution.clone(),
        environment: command.execution_environment.clone(),
        runtime_identity_sha256: "1".repeat(64),
        status_code: 0,
        timed_out: false,
        network_enabled: false,
        stdout_sha256: "2".repeat(64),
        stderr_sha256: "3".repeat(64),
    };
    let preparations = command
        .preparation
        .as_ref()
        .map_or_else(Vec::new, |preparation| {
            (1..=2)
                .map(|run_number| IntentionalBoundaryGeneratorExecution {
                    run_number,
                    command: preparation.clone(),
                    environment: command.preparation_environment.clone(),
                    runtime_identity_sha256: "4".repeat(64),
                    status_code: 0,
                    timed_out: false,
                    network_enabled: true,
                    stdout_sha256: "5".repeat(64),
                    stderr_sha256: "6".repeat(64),
                })
                .collect()
        });
    ReplaySuccess {
        outputs: outputs
            .iter()
            .map(|output| IntentionalBoundaryGeneratorOutput {
                repository_path: output.repository_path.clone(),
                object_id: output.object_id.clone(),
                byte_length: output.byte_length,
                committed_sha256: output.committed_sha256.clone(),
                first_run_sha256: output.committed_sha256.clone(),
                second_run_sha256: output.committed_sha256.clone(),
            })
            .collect(),
        preparations,
        executions: vec![execution(1), execution(2)],
    }
}

#[test]
fn gradle_configuration_reaches_evidence_as_a_project_model_contract() {
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
            "https://github.com/example/gradle-evidence.git",
        ],
    );
    for (path, content) in [
        ("settings.gradle.kts", "rootProject.name = \"evidence\"\n"),
        ("build.gradle.kts", "plugins { application }\n"),
        ("gradle.lockfile", "empty=empty\n"),
        (
            "gradle/verification-metadata.xml",
            "<verification-metadata/>\n",
        ),
        (
            "src/main/kotlin/Generated.kt",
            "// @generated\npackage evidence\nfun generated() = 7\n",
        ),
    ] {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = inventory_intentional_boundary_repository(
        "github.com/example/gradle-evidence",
        &revision,
        root.path(),
    )
    .unwrap();
    let source = census_intentional_boundary_repository(
        &inventory.repository,
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();
    let semantic = semantic_census(&source);
    let canonical = |path: &str| {
        fs::canonicalize(root.path().join(path))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    let model = serde_json::to_vec(&serde_json::json!({
        "contract": "sniff-gradle-tooling-project-model-v4",
        "tooling_api_version": "8.8",
        "gradle_version": "8.8",
        "settings_directory": canonical(""),
        "projects": [{
            "project_path": ":",
            "project_name": "evidence",
            "group_name": "example",
            "project_version": "1.0.0",
            "project_directory": canonical(""),
            "build_file": canonical("build.gradle.kts"),
            "build_file_exists": true,
            "provider_kinds": ["application"],
            "production_source_files": [canonical("src/main/kotlin/Generated.kt")],
            "producer_tasks": [{
                "task_path": ":writeGenerated",
                "task_type": "org.gradle.api.DefaultTask",
                "output_files": [canonical("src/main/kotlin/Generated.kt")],
                "production_source_files": [canonical("src/main/kotlin/Generated.kt")]
            }]
        }]
    }))
    .unwrap();
    let project_models = parse_intentional_boundary_gradle_tooling_model(
        root.path(),
        &inventory,
        "settings.gradle.kts",
        &"a".repeat(64),
        &model,
    )
    .unwrap();
    let manifests = census_intentional_boundary_manifests(
        &inventory.repository,
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();
    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifests).unwrap();
    let ast = census_intentional_boundary_kotlin_ast(
        &inventory.repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
    )
    .unwrap();
    let base_evidence = extract_intentional_boundary_compiler_and_ast_evidence(
        &inventory.repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
        &[ast],
    )
    .unwrap();
    let generators = super::super::census_generators_with_executor(
        &inventory.repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
        &project_models,
        &manifests,
        &bindings,
        &base_evidence,
        |command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();
    let evidence = compose_intentional_boundary_generator_evidence(
        IntentionalBoundaryGeneratorEvidenceInputs {
            inventory: &inventory,
            source_census: &source,
            semantic_census: &semantic,
            project_model_census: &project_models,
            manifest_census: &manifests,
            binding_census: &bindings,
            base_evidence: &base_evidence,
            generator_census: &generators,
        },
    )
    .unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.proof
            == IntentionalBoundaryEvidenceProof::ProjectModelContract(
                IntentionalBoundaryProjectModelProofKind::GeneratorConfiguration,
            )
    }));
    assert!(!evidence.atoms.iter().any(|atom| {
        matches!(
            atom.proof,
            IntentionalBoundaryEvidenceProof::ManifestContract(
                crate::benchmark::release::IntentionalBoundaryManifestProofKind::GeneratorConfiguration
            )
        )
    }));
}
