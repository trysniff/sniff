use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, bind_intentional_boundary_manifests,
    census_intentional_boundary_javascript_ast, census_intentional_boundary_manifests,
    census_intentional_boundary_python_ast, census_intentional_boundary_repository,
    census_intentional_boundary_rust_ast, extract_intentional_boundary_compiler_and_ast_evidence,
    inventory_intentional_boundary_repository,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

fn location(path: &str) -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: path.to_string(),
        start_line_zero_based: 0,
        start_character_zero_based: 0,
        end_line_zero_based: 0,
        end_character_zero_based: 10,
    }
}

fn declaration(id: &str, manifest: &str) -> IntentionalBoundaryManifestDeclaration {
    IntentionalBoundaryManifestDeclaration {
        declaration_id: id.to_string(),
        provider: IntentionalBoundaryManifestProvider::CargoManifest,
        manifest_repository_path: manifest.to_string(),
        manifest_object_id: "a".repeat(40),
        declaration_kind: IntentionalBoundaryManifestDeclarationKind::BuildScript,
        declaration_location: location(manifest),
        target: IntentionalBoundaryManifestTarget::RepositoryPath {
            repository_path: manifest
                .rsplit_once('/')
                .map_or("build.rs".to_string(), |(root, _)| {
                    format!("{root}/build.rs")
                }),
        },
    }
}

fn expected() -> ExpectedOutput {
    ExpectedOutput {
        repository_path: "src/generated.rs".to_string(),
        object_id: "b".repeat(40),
        byte_length: 12,
        committed_sha256: "c".repeat(64),
    }
}

fn success(command: &GeneratorCommand, expected: &ExpectedOutput) -> ReplaySuccess {
    let execution = |run_number| IntentionalBoundaryGeneratorExecution {
        run_number,
        command: command.execution.clone(),
        environment: command.execution_environment.clone(),
        runtime_identity_sha256: "d".repeat(64),
        status_code: 0,
        timed_out: false,
        network_enabled: false,
        stdout_sha256: "e".repeat(64),
        stderr_sha256: "f".repeat(64),
    };
    ReplaySuccess {
        outputs: vec![IntentionalBoundaryGeneratorOutput {
            repository_path: expected.repository_path.clone(),
            object_id: expected.object_id.clone(),
            byte_length: expected.byte_length,
            committed_sha256: expected.committed_sha256.clone(),
            first_run_sha256: expected.committed_sha256.clone(),
            second_run_sha256: expected.committed_sha256.clone(),
        }],
        preparations: Vec::new(),
        executions: vec![execution(1), execution(2)],
    }
}

#[test]
fn cargo_configuration_is_an_exact_offline_locked_command() {
    let declaration = declaration("root", "Cargo.toml");

    assert_eq!(
        cargo_generator_command(&declaration).unwrap(),
        [
            "cargo",
            "check",
            "--offline",
            "--locked",
            "--manifest-path",
            "Cargo.toml",
        ]
    );
}

#[test]
fn nearest_manifest_owns_only_its_descendant_generated_surface() {
    let root = declaration("root", "Cargo.toml");
    let nested = declaration("nested", "crates/child/Cargo.toml");

    assert_eq!(
        nearest_declarations("crates/child/src/generated.rs", &[&root, &nested]),
        vec!["nested".to_string()]
    );
    assert_eq!(
        nearest_declarations("src/generated.rs", &[&root, &nested]),
        vec!["root".to_string()]
    );
}

#[test]
fn replay_receipt_requires_two_exact_non_networked_reproductions() {
    let declaration = declaration("root", "Cargo.toml");
    let command = GeneratorCommand {
        preparation: None,
        preparation_environment: BTreeMap::new(),
        execution: cargo_generator_command(&declaration).unwrap(),
        execution_environment: BTreeMap::new(),
        cleanup_paths: Vec::new(),
    };
    let expected_output = expected();
    let valid = success(&command, &expected_output);

    validate_replay_success(&valid, &command, std::slice::from_ref(&expected_output)).unwrap();

    let mut networked = valid;
    networked.executions[1].network_enabled = true;
    assert!(
        validate_replay_success(&networked, &command, std::slice::from_ref(&expected_output))
            .unwrap_err()
            .contains("receipt contract")
    );

    let mut changed_environment = success(&command, &expected_output);
    changed_environment.executions[0]
        .environment
        .insert("GOENV".to_string(), "off".to_string());
    assert!(
        validate_replay_success(&changed_environment, &command, &[expected_output])
            .unwrap_err()
            .contains("receipt contract")
    );
}

struct Fixture {
    root: tempfile::TempDir,
    repository: String,
    revision: String,
    inventory: IntentionalBoundaryRepositoryInventory,
    source: IntentionalBoundarySourceCensus,
    semantic: IntentionalBoundarySemanticCensus,
    project_models: IntentionalBoundaryProjectModelCensus,
    manifests: IntentionalBoundaryManifestCensus,
    bindings: IntentionalBoundaryManifestBindingCensus,
    evidence: IntentionalBoundaryEvidenceCensus,
}

fn empty_project_models(
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> IntentionalBoundaryProjectModelCensus {
    super::super::intentional_boundary_project_model::finish_project_model_census(
        inventory,
        Vec::new(),
        Vec::new(),
    )
    .unwrap()
}

fn fixture() -> Fixture {
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
            "https://github.com/example/generator-fixture.git",
        ],
    );
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"generator-fixture\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2024\"\n",
            "build = \"build.rs\"\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("Cargo.lock"),
        concat!(
            "# This file is automatically @generated by Cargo.\n",
            "# It is not intended for manual editing.\n",
            "version = 4\n\n",
            "[[package]]\n",
            "name = \"generator-fixture\"\n",
            "version = \"0.1.0\"\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("build.rs"),
        concat!(
            "fn main() {\n",
            "    std::fs::write(\"src/generated.rs\", ",
            "\"// @generated\\npub fn generated_value() -> u8 { 7 }\\n\").unwrap();\n",
            "}\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "mod generated;\npub use generated::generated_value;\n",
    )
    .unwrap();
    fs::write(
        root.path().join("src/generated.rs"),
        "// @generated\npub fn generated_value() -> u8 { 7 }\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/generator-fixture".to_string();
    let inventory =
        inventory_intentional_boundary_repository(&repository, &revision, root.path()).unwrap();
    let source =
        census_intentional_boundary_repository(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let semantic = semantic_fixture(
        &source,
        IntentionalBoundaryIndexerKind::Rust,
        "rust-analyzer",
    );
    let ast = census_intentional_boundary_rust_ast(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
    )
    .unwrap();
    let evidence = extract_intentional_boundary_compiler_and_ast_evidence(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
        &[ast],
    )
    .unwrap();
    let manifests =
        census_intentional_boundary_manifests(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifests).unwrap();
    let project_models = empty_project_models(&inventory);
    Fixture {
        root,
        repository,
        revision,
        inventory,
        source,
        semantic,
        project_models,
        manifests,
        bindings,
        evidence,
    }
}

fn node_fixture() -> Fixture {
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
            "https://github.com/example/node-generator-fixture.git",
        ],
    );
    fs::create_dir(root.path().join("src")).unwrap();
    fs::create_dir(root.path().join("tools")).unwrap();
    fs::write(
        root.path().join("package.json"),
        concat!(
            "{\n",
            "  \"name\": \"node-generator-fixture\",\n",
            "  \"version\": \"1.0.0\",\n",
            "  \"scripts\": {\n",
            "    \"test\": \"node --test\",\n",
            "    \"generate\": \"node tools/generate.js\"\n",
            "  }\n",
            "}\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        concat!(
            "{\n",
            "  \"name\": \"node-generator-fixture\",\n",
            "  \"version\": \"1.0.0\",\n",
            "  \"lockfileVersion\": 3,\n",
            "  \"requires\": true,\n",
            "  \"packages\": {\"\": {\"name\": \"node-generator-fixture\", ",
            "\"version\": \"1.0.0\"}}\n",
            "}\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("tools/generate.js"),
        concat!(
            "const fs = require('node:fs');\n",
            "fs.writeFileSync('src/generated.js', ",
            "'// @generated\\nexport function generatedValue() { return 7; }\\n');\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("src/generated.js"),
        "// @generated\nexport function generatedValue() { return 7; }\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/node-generator-fixture".to_string();
    let inventory =
        inventory_intentional_boundary_repository(&repository, &revision, root.path()).unwrap();
    let source =
        census_intentional_boundary_repository(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let semantic = semantic_fixture(
        &source,
        IntentionalBoundaryIndexerKind::TypeScriptJavaScript,
        "scip-typescript",
    );
    let ast = census_intentional_boundary_javascript_ast(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
    )
    .unwrap();
    let evidence = extract_intentional_boundary_compiler_and_ast_evidence(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
        &[ast],
    )
    .unwrap();
    let manifests =
        census_intentional_boundary_manifests(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifests).unwrap();
    let project_models = empty_project_models(&inventory);
    Fixture {
        root,
        repository,
        revision,
        inventory,
        source,
        semantic,
        project_models,
        manifests,
        bindings,
        evidence,
    }
}

fn python_fixture() -> Fixture {
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
            "https://github.com/example/python-generator-fixture.git",
        ],
    );
    fs::write(
        root.path().join("pyproject.toml"),
        concat!(
            "[project]\n",
            "name = \"python-generator-fixture\"\n",
            "version = \"0.1.0\"\n",
            "requires-python = \">=3.9\"\n",
            "dependencies = []\n\n",
            "[project.scripts]\n",
            "generate = \"generator:generate\"\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("uv.lock"),
        concat!(
            "version = 1\n",
            "revision = 3\n",
            "requires-python = \">=3.9\"\n\n",
            "[[package]]\n",
            "name = \"python-generator-fixture\"\n",
            "version = \"0.1.0\"\n",
            "source = { virtual = \".\" }\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("generator.py"),
        concat!(
            "from pathlib import Path\n\n",
            "def generate():\n",
            "    Path(\"generated.py\").write_bytes(",
            "b\"# @generated\\ndef generated_value():\\n    return 7\\n\")\n",
        ),
    )
    .unwrap();
    fs::write(
        root.path().join("generated.py"),
        "# @generated\ndef generated_value():\n    return 7\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/python-generator-fixture".to_string();
    let inventory =
        inventory_intentional_boundary_repository(&repository, &revision, root.path()).unwrap();
    let source =
        census_intentional_boundary_repository(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let semantic = semantic_fixture(
        &source,
        IntentionalBoundaryIndexerKind::Python,
        "scip-python",
    );
    let ast = census_intentional_boundary_python_ast(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
    )
    .unwrap();
    let evidence = extract_intentional_boundary_compiler_and_ast_evidence(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
        &[ast],
    )
    .unwrap();
    let manifests =
        census_intentional_boundary_manifests(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifests).unwrap();
    let project_models = empty_project_models(&inventory);
    Fixture {
        root,
        repository,
        revision,
        inventory,
        source,
        semantic,
        project_models,
        manifests,
        bindings,
        evidence,
    }
}

fn semantic_fixture(
    source: &IntentionalBoundarySourceCensus,
    indexer: IntentionalBoundaryIndexerKind,
    tool_name: &str,
) -> IntentionalBoundarySemanticCensus {
    let mut methods = Vec::new();
    for (path, entry) in source.source_files.iter().flat_map(|file| {
        file.methods
            .iter()
            .map(move |method| (file.repository_path.as_str(), method))
    }) {
        let symbol_id = format!(
            "{tool_name} generator-fixture {path}/{}().",
            entry.symbol_name
        );
        let definition = IntentionalBoundarySemanticRange {
            repository_path: path.to_string(),
            start_line_zero_based: entry.start_line.saturating_sub(1) as u32,
            start_character_zero_based: 0,
            end_line_zero_based: entry.end_line.saturating_sub(1) as u32,
            end_character_zero_based: 1,
        };
        methods.push(IntentionalBoundarySemanticMethod {
            parser_unit_id: entry.parser_unit_id.clone(),
            repository_path: path.to_string(),
            symbol_name: entry.symbol_name.clone(),
            start_line: entry.start_line,
            end_line: entry.end_line,
            indexer,
            status: IntentionalBoundarySemanticMethodStatus::Resolved {
                symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                    symbol_id: symbol_id.clone(),
                    provider_identity: symbol_id,
                    display_name: Some(entry.symbol_name.clone()),
                    category: IntentionalBoundarySemanticSymbolCategory::Callable,
                    provider_kind: "function".to_string(),
                    documentation: Vec::new(),
                    signature: None,
                    signature_referenced_symbols: Vec::new(),
                    owner: None,
                    definitions: vec![definition.clone()],
                    visibility: IntentionalBoundarySemanticVisibility::Public,
                    surfaces: Vec::new(),
                    origin: IntentionalBoundarySemanticOrigin::Repository,
                    ambiguity_notes: Vec::new(),
                }),
                joined_definition: Some(definition),
            },
            occurrences: Vec::new(),
            calls: Vec::new(),
            relationships: Vec::new(),
            imports: Vec::new(),
            test_relationships: Vec::new(),
        });
    }
    let mut semantic = IntentionalBoundarySemanticCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
            .to_string(),
        repository: source.repository.clone(),
        revision: source.revision.clone(),
        source_census_sha256: source.census_sha256.clone(),
        indexers: vec![IntentionalBoundarySemanticIndexerCensus {
            indexer,
            tool_name: tool_name.to_string(),
            tool_version: Some("fixture".to_string()),
            semantic_facts_sha256: "a".repeat(64),
            diagnostic_count: 0,
            diagnostics_sha256: "b".repeat(64),
            document_count: source.source_files.len(),
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
    semantic
}

fn fake_replay(command: &GeneratorCommand, outputs: &[ExpectedOutput]) -> ReplaySuccess {
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
fn reproduced_generator_qualifies_only_after_all_three_evidence_groups() {
    let fixture = fixture();
    let census = census_generators_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        |_declaration, command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();

    super::super::validate_intentional_boundary_generator_census_commitment(
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        &census,
    )
    .unwrap();
    let evidence = super::super::compose_intentional_boundary_generator_evidence(
        super::super::IntentionalBoundaryGeneratorEvidenceInputs {
            inventory: &fixture.inventory,
            source_census: &fixture.source,
            semantic_census: &fixture.semantic,
            project_model_census: &fixture.project_models,
            manifest_census: &fixture.manifests,
            binding_census: &fixture.bindings,
            base_evidence: &fixture.evidence,
            generator_census: &census,
        },
    )
    .unwrap();
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol,
        &fixture.source,
        &fixture.semantic,
        &evidence,
    )
    .unwrap();

    assert!(candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::GeneratedSurface
    }));
}

#[test]
fn recommitted_tampered_replay_output_is_rejected() {
    let fixture = fixture();
    let mut census = census_generators_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        |_declaration, command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();
    let IntentionalBoundaryGeneratorReplayOutcome::Reproduced { outputs, .. } =
        &mut census.replays[0].outcome
    else {
        panic!("expected reproduced fixture");
    };
    outputs[0].first_run_sha256 = "9".repeat(64);
    census.generator_census_sha256 = generator_census_sha256(&census).unwrap();

    assert!(
        super::super::validate_intentional_boundary_generator_census_commitment(
            &fixture.inventory,
            &fixture.source,
            &fixture.semantic,
            &fixture.project_models,
            &fixture.manifests,
            &fixture.bindings,
            &fixture.evidence,
            &census,
        )
        .unwrap_err()
        .contains("output bytes")
    );
}

#[test]
fn recommitted_tampered_replay_environment_is_rejected() {
    let fixture = fixture();
    let mut census = census_generators_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        |_declaration, command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();
    let IntentionalBoundaryGeneratorReplayOutcome::Reproduced { executions, .. } =
        &mut census.replays[0].outcome
    else {
        panic!("expected reproduced fixture");
    };
    executions[0]
        .environment
        .insert("GOENV".to_string(), "changed".to_string());
    census.generator_census_sha256 = generator_census_sha256(&census).unwrap();

    assert!(
        super::super::validate_intentional_boundary_generator_census_commitment(
            &fixture.inventory,
            &fixture.source,
            &fixture.semantic,
            &fixture.project_models,
            &fixture.manifests,
            &fixture.bindings,
            &fixture.evidence,
            &census,
        )
        .unwrap_err()
        .contains("receipt")
    );
}

#[test]
fn real_cargo_generator_reproduces_committed_output_twice_offline() {
    let fixture = fixture();

    let census = census_intentional_boundary_generators(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
    )
    .unwrap();

    let outcome = &census.replays[0].outcome;
    match outcome {
        IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
            outputs,
            executions,
            ..
        } => {
            assert_eq!(outputs.len(), 1);
            assert_eq!(executions.len(), 2);
            assert!(
                executions
                    .iter()
                    .all(|execution| !execution.network_enabled)
            );
        }
        IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
            ..
        } if cfg!(windows) => {}
        _ => panic!("real Cargo generator did not reproduce its committed output: {outcome:#?}"),
    }
}

#[test]
fn python_entrypoint_command_is_bound_locked_and_project_install_free() {
    let fixture = python_fixture();
    let declaration = fixture
        .manifests
        .declarations
        .iter()
        .find(|declaration| {
            declaration.provider == IntentionalBoundaryManifestProvider::PythonProjectManifest
        })
        .unwrap();

    let command = generator_command_with_context(
        &fixture.inventory,
        &fixture.manifests.declarations,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.bindings,
        declaration,
    )
    .unwrap();

    assert_eq!(
        command.preparation.unwrap(),
        [
            "uv",
            "sync",
            "--project",
            ".",
            "--locked",
            "--no-install-project",
            "--no-install-workspace",
            "--no-dev",
            "--no-default-groups",
            "--no-progress",
            "--no-python-downloads",
        ]
    );
    assert_eq!(command.execution.first().map(String::as_str), Some("uv"));
    assert!(
        command
            .execution
            .iter()
            .any(|argument| argument == "--no-sync")
    );
    assert!(
        command
            .execution
            .windows(3)
            .any(|arguments| arguments == ["-I", "-B", "-c"])
    );
    assert_eq!(
        &command.execution[command.execution.len() - 3..],
        [".", "generator", "generate"]
    );
}

#[test]
fn python_entrypoint_rejects_ambiguous_lock_families() {
    let fixture = python_fixture();
    let declaration = fixture.manifests.declarations.first().unwrap();
    let mut inventory = fixture.inventory.clone();
    let mut second_lock = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == "uv.lock")
        .unwrap()
        .clone();
    second_lock.repository_path = "poetry.lock".to_string();
    inventory.tracked_entries.push(second_lock);

    assert!(
        generator_command_with_context(
            &inventory,
            &fixture.manifests.declarations,
            &fixture.semantic,
            &fixture.project_models,
            &fixture.bindings,
            declaration,
        )
        .is_none()
    );
}

#[test]
fn real_uv_entrypoint_reproduces_committed_output_twice_offline() {
    let fixture = python_fixture();

    let census = census_intentional_boundary_generators(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
    )
    .unwrap();

    let outcome = &census.replays[0].outcome;
    match outcome {
        IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
            preparations,
            outputs,
            executions,
            ..
        } => {
            assert_eq!(preparations.len(), 2);
            assert!(
                preparations
                    .iter()
                    .all(|preparation| preparation.network_enabled)
            );
            assert_eq!(outputs.len(), 1);
            assert_eq!(executions.len(), 2);
            assert!(
                executions
                    .iter()
                    .all(|execution| !execution.network_enabled)
            );
        }
        IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
            ..
        } if cfg!(windows) => {}
        _ => panic!("real uv generator did not reproduce its committed output: {outcome:#?}"),
    }
}

#[test]
fn dependency_preparation_cannot_take_credit_for_generated_output() {
    let fixture = fixture();
    let declaration = fixture
        .manifests
        .declarations
        .iter()
        .find(|declaration| {
            declaration.declaration_kind == IntentionalBoundaryManifestDeclarationKind::BuildScript
        })
        .unwrap();
    let python = if cfg!(windows) { "python" } else { "python3" };
    let command = GeneratorCommand {
        preparation: Some(vec![
            python.to_string(),
            "-I".to_string(),
            "-c".to_string(),
            concat!(
                "from pathlib import Path;",
                "Path('src/generated.rs').write_text(",
                "'// @generated\\npub fn generated_value() -> u8 { 7 }\\n')"
            )
            .to_string(),
        ]),
        preparation_environment: BTreeMap::new(),
        execution: vec![
            python.to_string(),
            "-I".to_string(),
            "-c".to_string(),
            "pass".to_string(),
        ],
        execution_environment: BTreeMap::new(),
        cleanup_paths: Vec::new(),
    };
    let outputs =
        vec![expected_output(&fixture.inventory, &fixture.source, "src/generated.rs").unwrap()];

    let failure = match runtime::execute_generator_replay(
        fixture.root.path(),
        &fixture.revision,
        declaration,
        &command,
        &outputs,
    ) {
        Ok(_) => panic!("preparation output was misattributed to the generator command"),
        Err(failure) => failure,
    };

    assert_eq!(
        failure.reason,
        IntentionalBoundaryGeneratorUnresolvedReason::OutputMissing
    );
    assert!(
        failure.detail.contains("generator did not recreate"),
        "{}",
        failure.detail
    );
}

#[test]
fn real_npm_generator_prepares_locked_dependencies_then_reproduces_twice_offline() {
    let fixture = node_fixture();

    let census = census_intentional_boundary_generators(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
    )
    .unwrap();

    let outcome = &census.replays[0].outcome;
    match outcome {
        IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
            declaration_id,
            preparations,
            command,
            outputs,
            executions,
            ..
        } => {
            assert_eq!(census.replays[0].candidate_declaration_ids.len(), 2);
            let selected = fixture
                .manifests
                .declarations
                .iter()
                .find(|declaration| declaration.declaration_id == *declaration_id)
                .unwrap();
            assert!(matches!(
                &selected.target,
                IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                    if script_name == "generate"
            ));
            assert_eq!(preparations.len(), 2);
            assert!(
                preparations
                    .iter()
                    .all(|preparation| preparation.network_enabled)
            );
            assert_eq!(command.first().map(String::as_str), Some("npm"));
            assert_eq!(outputs.len(), 1);
            assert_eq!(executions.len(), 2);
            assert!(
                executions
                    .iter()
                    .all(|execution| !execution.network_enabled)
            );
        }
        IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
            ..
        } if cfg!(windows) => {}
        _ => panic!("real npm generator did not reproduce its committed output: {outcome:#?}"),
    }
}

#[test]
fn npm_generator_command_is_exact_locked_and_lifecycle_disabled() {
    let fixture = node_fixture();
    let declaration = fixture
        .manifests
        .declarations
        .iter()
        .find(|declaration| {
            matches!(
                &declaration.target,
                IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                    if script_name == "generate"
            )
        })
        .unwrap();

    let command = generator_command(
        &fixture.inventory,
        &fixture.manifests.declarations,
        declaration,
    )
    .unwrap();

    assert_eq!(
        command.preparation.unwrap(),
        [
            "npm",
            "--prefix",
            ".",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]
    );
    assert_eq!(
        command.execution,
        [
            "npm",
            "--prefix",
            ".",
            "run-script",
            "--ignore-scripts",
            "generate",
        ]
    );
    assert_eq!(command.cleanup_paths, ["node_modules"]);

    let mut unlocked = fixture.inventory.clone();
    unlocked
        .tracked_entries
        .retain(|entry| entry.repository_path != "package-lock.json");
    assert!(generator_command(&unlocked, &fixture.manifests.declarations, declaration).is_none());
}

fn node_manager_command(
    fixture: &Fixture,
    lockfile: &str,
    package_manager: Option<&str>,
) -> Option<GeneratorCommand> {
    let mut inventory = fixture.inventory.clone();
    let mut lock_entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == "package-lock.json")
        .unwrap()
        .clone();
    inventory.tracked_entries.retain(|entry| {
        ![
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        ]
        .contains(&entry.repository_path.as_str())
    });
    lock_entry.repository_path = lockfile.to_string();
    inventory.tracked_entries.push(lock_entry);
    inventory
        .tracked_entries
        .sort_by(|left, right| left.repository_path.cmp(&right.repository_path));

    let mut declarations = fixture.manifests.declarations.clone();
    for declaration in &mut declarations {
        if let IntentionalBoundaryManifestTarget::PackageScript {
            package_manager: value,
            ..
        } = &mut declaration.target
        {
            *value = package_manager.map(str::to_string);
        }
    }
    let declaration = declarations.iter().find(|declaration| {
        matches!(
            &declaration.target,
            IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                if script_name == "generate"
        )
    })?;
    generator_command(&inventory, &declarations, declaration)
}

#[test]
fn pnpm_generator_command_is_exact_frozen_and_lifecycle_disabled() {
    let fixture = node_fixture();
    let command = node_manager_command(&fixture, "pnpm-lock.yaml", Some("pnpm@10.15.0"))
        .expect("pinned pnpm lock should be supported");

    assert_eq!(
        command.preparation.unwrap(),
        [
            "pnpm",
            "--dir",
            ".",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--reporter=silent",
        ]
    );
    assert_eq!(command.execution, ["pnpm", "--dir", ".", "run", "generate"]);
    assert_eq!(command.cleanup_paths, ["node_modules"]);
}

#[test]
fn yarn_generator_commands_require_a_pinned_major_and_disable_install_builds() {
    let fixture = node_fixture();
    assert!(node_manager_command(&fixture, "yarn.lock", None).is_none());

    let classic = node_manager_command(&fixture, "yarn.lock", Some("yarn@1.22.22")).unwrap();
    assert_eq!(
        classic.preparation.unwrap(),
        [
            "yarn",
            "--cwd",
            ".",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--non-interactive",
        ]
    );
    assert_eq!(classic.execution, ["yarn", "--cwd", ".", "run", "generate"]);

    let modern =
        node_manager_command(&fixture, "yarn.lock", Some("yarn@4.9.2+sha512.deadbeef")).unwrap();
    assert_eq!(
        modern.preparation.unwrap(),
        [
            "yarn",
            "--cwd",
            ".",
            "install",
            "--immutable",
            "--mode=skip-build",
        ]
    );
    assert_eq!(
        modern.cleanup_paths,
        [
            "node_modules",
            ".pnp.cjs",
            ".pnp.loader.mjs",
            ".yarn/install-state.gz",
            ".yarn/unplugged",
        ]
    );
}

#[test]
fn bun_generator_command_is_frozen_and_install_scripts_are_disabled() {
    let fixture = node_fixture();
    let command = node_manager_command(&fixture, "bun.lock", Some("bun@1.2.20")).unwrap();

    assert_eq!(
        command.preparation.unwrap(),
        [
            "bun",
            "install",
            "--cwd",
            ".",
            "--frozen-lockfile",
            "--ignore-scripts",
        ]
    );
    assert_eq!(command.execution, ["bun", "--cwd", ".", "run", "generate"]);
}

#[test]
fn node_manager_selection_rejects_ambiguity_mismatch_and_unpinned_versions() {
    let fixture = node_fixture();
    assert!(node_manager_command(&fixture, "pnpm-lock.yaml", Some("npm@10.8.0")).is_none());
    assert!(node_manager_command(&fixture, "pnpm-lock.yaml", Some("pnpm@latest")).is_none());

    let declaration = fixture
        .manifests
        .declarations
        .iter()
        .find(|declaration| {
            matches!(
                &declaration.target,
                IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                    if script_name == "generate"
            )
        })
        .unwrap();
    let mut ambiguous = fixture.inventory.clone();
    let mut second_lock = ambiguous
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == "package-lock.json")
        .unwrap()
        .clone();
    second_lock.repository_path = "pnpm-lock.yaml".to_string();
    ambiguous.tracked_entries.push(second_lock);
    assert!(generator_command(&ambiguous, &fixture.manifests.declarations, declaration).is_none());
}

#[test]
fn managers_with_implicit_hooks_do_not_misattribute_generated_output() {
    let fixture = node_fixture();
    let mut inventory = fixture.inventory.clone();
    let lock = inventory
        .tracked_entries
        .iter_mut()
        .find(|entry| entry.repository_path == "package-lock.json")
        .unwrap();
    lock.repository_path = "bun.lock".to_string();
    let mut declarations = fixture.manifests.declarations.clone();
    for declaration in &mut declarations {
        if let IntentionalBoundaryManifestTarget::PackageScript {
            package_manager, ..
        } = &mut declaration.target
        {
            *package_manager = Some("bun@1.2.20".to_string());
        }
    }
    let selected = declarations
        .iter()
        .find(|declaration| {
            matches!(
                &declaration.target,
                IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                    if script_name == "generate"
            )
        })
        .unwrap()
        .clone();
    let mut hook = selected.clone();
    let IntentionalBoundaryManifestTarget::PackageScript { script_name, .. } = &mut hook.target
    else {
        unreachable!()
    };
    *script_name = "pregenerate".to_string();
    declarations.push(hook);

    assert!(generator_command(&inventory, &declarations, &selected).is_none());
}

#[test]
fn recommitted_network_disabled_npm_preparation_is_rejected() {
    let fixture = node_fixture();
    let mut census = census_generators_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        |_declaration, command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();
    let IntentionalBoundaryGeneratorReplayOutcome::Reproduced { preparations, .. } =
        &mut census.replays[0].outcome
    else {
        panic!("expected reproduced npm fixture");
    };
    preparations[0].network_enabled = false;
    census.generator_census_sha256 = generator_census_sha256(&census).unwrap();

    assert!(
        super::super::validate_intentional_boundary_generator_census_commitment(
            &fixture.inventory,
            &fixture.source,
            &fixture.semantic,
            &fixture.project_models,
            &fixture.manifests,
            &fixture.bindings,
            &fixture.evidence,
            &census,
        )
        .unwrap_err()
        .contains("receipt")
    );
}

#[test]
fn recommitted_omitted_package_script_candidate_is_rejected() {
    let fixture = node_fixture();
    let mut census = census_generators_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        |_declaration, command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();
    assert_eq!(census.replays[0].candidate_declaration_ids.len(), 2);
    let IntentionalBoundaryGeneratorReplayOutcome::Reproduced { declaration_id, .. } =
        &census.replays[0].outcome
    else {
        panic!("expected reproduced npm fixture");
    };
    let selected = fixture
        .manifests
        .declarations
        .iter()
        .find(|declaration| declaration.declaration_id == *declaration_id)
        .unwrap();
    assert!(matches!(
        &selected.target,
        IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
            if script_name == "generate"
    ));
    census.replays[0].candidate_declaration_ids.pop();
    census.replays[0].replay_id = replay_id(
        &census.repository,
        &census.revision,
        &census.replays[0].candidate_declaration_ids,
        &census.replays[0].subjects,
    )
    .unwrap();
    census.generator_census_sha256 = generator_census_sha256(&census).unwrap();

    assert!(
        super::super::validate_intentional_boundary_generator_census_commitment(
            &fixture.inventory,
            &fixture.source,
            &fixture.semantic,
            &fixture.project_models,
            &fixture.manifests,
            &fixture.bindings,
            &fixture.evidence,
            &census,
        )
        .unwrap_err()
        .contains("configuration assignment")
    );
}

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
