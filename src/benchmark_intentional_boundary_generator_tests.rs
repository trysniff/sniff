use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticIndexerCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticSymbolFacts, IntentionalBoundarySemanticVisibility,
    bind_intentional_boundary_manifests, census_intentional_boundary_manifests,
    census_intentional_boundary_repository, census_intentional_boundary_rust_ast,
    extract_intentional_boundary_compiler_and_ast_evidence,
    inventory_intentional_boundary_repository,
};
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

fn success(command: &[String], expected: &ExpectedOutput) -> ReplaySuccess {
    let execution = |run_number| IntentionalBoundaryGeneratorExecution {
        run_number,
        command: command.to_vec(),
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
        nearest_declaration("crates/child/src/generated.rs", &[&root, &nested]),
        Some("nested".to_string())
    );
    assert_eq!(
        nearest_declaration("src/generated.rs", &[&root, &nested]),
        Some("root".to_string())
    );
}

#[test]
fn replay_receipt_requires_two_exact_non_networked_reproductions() {
    let declaration = declaration("root", "Cargo.toml");
    let command = cargo_generator_command(&declaration).unwrap();
    let expected = expected();
    let valid = success(&command, &expected);

    validate_replay_success(&valid, &command, std::slice::from_ref(&expected)).unwrap();

    let mut networked = valid;
    networked.executions[1].network_enabled = true;
    assert!(
        validate_replay_success(&networked, &command, &[expected])
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
    manifests: IntentionalBoundaryManifestCensus,
    bindings: IntentionalBoundaryManifestBindingCensus,
    evidence: IntentionalBoundaryEvidenceCensus,
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
    let semantic = semantic_fixture(&source);
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
    Fixture {
        root,
        repository,
        revision,
        inventory,
        source,
        semantic,
        manifests,
        bindings,
        evidence,
    }
}

fn semantic_fixture(source: &IntentionalBoundarySourceCensus) -> IntentionalBoundarySemanticCensus {
    let mut methods = Vec::new();
    for (path, entry) in source.source_files.iter().flat_map(|file| {
        file.methods
            .iter()
            .map(move |method| (file.repository_path.as_str(), method))
    }) {
        let symbol_id = format!(
            "rust-analyzer cargo generator-fixture 0.1.0 {path}/{}().",
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
            indexer: IntentionalBoundaryIndexerKind::Rust,
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
            indexer: IntentionalBoundaryIndexerKind::Rust,
            tool_name: "rust-analyzer".to_string(),
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

fn fake_replay(command: &[String], outputs: &[ExpectedOutput]) -> ReplaySuccess {
    let execution = |run_number| IntentionalBoundaryGeneratorExecution {
        run_number,
        command: command.to_vec(),
        runtime_identity_sha256: "1".repeat(64),
        status_code: 0,
        timed_out: false,
        network_enabled: false,
        stdout_sha256: "2".repeat(64),
        stderr_sha256: "3".repeat(64),
    };
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
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
        |_declaration, command, outputs| Ok(fake_replay(command, outputs)),
    )
    .unwrap();

    super::super::validate_intentional_boundary_generator_census_commitment(
        &fixture.source,
        &fixture.semantic,
        &fixture.manifests,
        &fixture.evidence,
        &census,
    )
    .unwrap();
    let evidence = super::super::compose_intentional_boundary_generator_evidence(
        &fixture.source,
        &fixture.semantic,
        &fixture.manifests,
        &fixture.evidence,
        &census,
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
            &fixture.source,
            &fixture.semantic,
            &fixture.manifests,
            &fixture.evidence,
            &census,
        )
        .unwrap_err()
        .contains("output bytes")
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
