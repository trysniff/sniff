use super::*;
use crate::benchmark::release::{
    HistoricalTestRecipeDiscovery, HistoricalTestRecipeStatus, IntentionalBoundaryAstProofKind,
    IntentionalBoundaryEvidenceProof, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticRelationshipFacts, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticSymbolFacts, IntentionalBoundarySemanticVisibility,
    census_intentional_boundary_repository, extract_intentional_boundary_compiler_evidence,
    inventory_intentional_boundary_repository,
};
use std::fs;
use std::process::Command;

#[test]
fn repository_selectors_reject_paths_outside_the_checkout() {
    assert!(is_safe_repository_path("tests/behavior.rs"));
    assert!(!is_safe_repository_path("../tests/behavior.rs"));
    assert!(!is_safe_repository_path("tests\\behavior.rs"));
}

#[test]
fn go_package_selector_is_repository_relative() {
    assert_eq!(
        parent_repository_path("internal/retry/retry_test.go"),
        "internal/retry"
    );
    assert_eq!(parent_repository_path("retry_test.go"), ".");
}

#[test]
fn rust_selector_comes_from_the_complete_compiler_identity() {
    assert_eq!(
        rust_harness_name(
            "rust-analyzer cargo demo 1.0.0 tests/adapter_works().",
            "adapter_works"
        ),
        Some("tests::adapter_works".to_string())
    );
    assert_eq!(
        rust_harness_name(
            "rust-analyzer cargo demo 1.0.0 other/adapter_works().",
            "different"
        ),
        None
    );
    assert_eq!(
        rust_harness_name(
            "rust-analyzer cargo demo 1.0.0 Adapter#adapter_works().",
            "adapter_works"
        ),
        None
    );
}

#[test]
fn exact_behavior_proof_survives_full_commitment_replay() {
    let fixture = fixture();
    let mut executions = 0;
    let census = census_behavior_tests_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        |selector| {
            executions += 1;
            Ok(passing_attempt(selector.clone(), &fixture.revision))
        },
    )
    .unwrap();

    assert_eq!(executions, 1);
    assert_eq!(census.candidates.len(), 1);
    assert_eq!(census.witnesses.len(), 1);
    assert_eq!(census.executions.len(), 1);
    assert!(matches!(
        census.candidates[0].status,
        IntentionalBoundaryBehaviorCandidateStatus::Passed { .. }
    ));
    validate_intentional_boundary_behavior_census_commitment(
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        &census,
    )
    .unwrap();
    let evidence = compose_intentional_boundary_behavior_evidence(
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        &census,
    )
    .unwrap();
    assert_eq!(
        evidence
            .atom_count_by_kind
            .get(&BoundaryEvidenceKind::PassingBehaviorTest),
        Some(&1)
    );
    assert_eq!(
        evidence.input_census_sha256.get("targeted_behavior_tests"),
        Some(&census.behavior_census_sha256)
    );
    validate_intentional_boundary_behavior_evidence(
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        &census,
        &evidence,
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
        candidate.category == super::super::IntentionalBoundaryCategory::RetryBoundary
    }));

    let mut tampered = census;
    tampered.executions[0].network_enabled = true;
    assert!(
        validate_intentional_boundary_behavior_census_commitment(
            &fixture.source,
            &fixture.semantic,
            &fixture.evidence,
            &tampered,
        )
        .unwrap_err()
        .contains("execution")
    );
}

#[test]
fn baseline_pass_is_not_qualifying_behavior_evidence() {
    let fixture = fixture();
    let error = census_behavior_tests_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        |selector| {
            let mut attempt = passing_attempt(selector.clone(), &fixture.revision);
            let IntentionalBoundaryBehaviorWitnessOutcome::Passed { proof, .. } =
                &mut attempt.outcome
            else {
                unreachable!();
            };
            *proof = IntentionalBoundaryBehaviorTestProofKind::BaselinePass;
            Ok(attempt)
        },
    )
    .unwrap_err();

    assert!(error.contains("non-targeted proof"));
}

#[test]
fn available_compiler_test_cannot_be_hidden_as_missing() {
    let fixture = fixture();
    let census = census_behavior_tests_with_executor(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        |selector| Ok(passing_attempt(selector.clone(), &fixture.revision)),
    )
    .unwrap();
    let mut witness = census.witnesses[0].clone();
    witness.test_parser_unit_id = None;
    witness.selector = None;
    witness.outcome = IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
        reason: IntentionalBoundaryBehaviorUnresolvedReason::TestMethodUnavailable,
        detail: "forged missing test".to_string(),
        execution_id: None,
    };
    witness.witness_id = witness_id(
        &witness.candidate_id,
        &witness.test_symbol_id,
        witness.relationship_kind,
        None,
    )
    .unwrap();
    let mut candidate = census.candidates[0].clone();
    candidate.status = IntentionalBoundaryBehaviorCandidateStatus::Unresolved;
    let forged = finish_behavior_census(
        &fixture.source,
        &fixture.semantic,
        &fixture.evidence,
        vec![candidate],
        vec![witness],
        Vec::new(),
    )
    .unwrap();

    assert!(
        validate_intentional_boundary_behavior_census_commitment(
            &fixture.source,
            &fixture.semantic,
            &fixture.evidence,
            &forged,
        )
        .unwrap_err()
        .contains("test compiler identity")
    );
}

#[test]
fn real_cargo_test_is_exact_and_network_is_disabled() {
    let fixture = fixture();
    let selector = IntentionalBoundaryBehaviorSelector::CargoTest {
        test_name: "tests::adapter_works".to_string(),
    };

    let attempt =
        runtime::execute_behavior_selector(fixture.root.path(), &fixture.revision, &selector)
            .unwrap();
    match attempt.outcome {
        IntentionalBoundaryBehaviorWitnessOutcome::Passed {
            proof: IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            execution_id,
        } => {
            let execution = attempt.execution.expect("passing proof has a receipt");
            assert_eq!(execution.execution_id, execution_id);
            assert!(!execution.network_enabled);
            assert!(execution.test_executed);
            assert_eq!(execution.executed_test_count, 1);
            assert_eq!(execution.matched_test_count, 1);
        }
        IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
            reason: IntentionalBoundaryBehaviorUnresolvedReason::SandboxUnavailable,
            execution_id: None,
            ..
        } if cfg!(windows) => {}
        outcome => panic!("real Cargo behavior proof did not pass safely: {outcome:?}"),
    }
}

struct Fixture {
    root: tempfile::TempDir,
    repository: String,
    revision: String,
    inventory: IntentionalBoundaryRepositoryInventory,
    source: IntentionalBoundarySourceCensus,
    semantic: IntentionalBoundarySemanticCensus,
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
            "https://github.com/example/behavior-fixture.git",
        ],
    );
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname = \"behavior-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        concat!(
            "pub fn adapter(value: i32) -> i32 { target(value) }\n",
            "fn target(value: i32) -> i32 { value + 1 }\n",
            "#[cfg(test)] mod tests {\n",
            "    use super::*;\n",
            "    #[test] fn adapter_works() { assert_eq!(adapter(1), 2); }\n",
            "}\n",
        ),
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/behavior-fixture".to_string();
    let inventory =
        inventory_intentional_boundary_repository(&repository, &revision, root.path()).unwrap();
    let source =
        census_intentional_boundary_repository(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let semantic = semantic_fixture(&source);
    let compiler_evidence =
        extract_intentional_boundary_compiler_evidence(&source, &semantic).unwrap();
    let production = semantic
        .methods
        .iter()
        .find(|method| method.symbol_name == "adapter")
        .unwrap();
    let production_symbol_id = resolved_symbol_id(production).unwrap();
    let mut atoms = compiler_evidence.atoms;
    super::super::intentional_boundary_compiler_evidence::push_typed_atom(
        &mut atoms,
        production,
        production_symbol_id,
        BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes,
        IntentionalBoundaryEvidenceProof::SourceAst(
            IntentionalBoundaryAstProofKind::DistinctOutcomeBranches,
        ),
        definition_locations(production).into_iter().collect(),
        Vec::new(),
    )
    .unwrap();
    let evidence = super::super::intentional_boundary_compiler_evidence::finish_evidence_census(
        &source,
        &semantic,
        compiler_evidence.input_census_sha256,
        atoms,
    )
    .unwrap();
    Fixture {
        root,
        repository,
        revision,
        inventory,
        source,
        semantic,
        evidence,
    }
}

fn semantic_fixture(source: &IntentionalBoundarySourceCensus) -> IntentionalBoundarySemanticCensus {
    const PRODUCTION: &str = "rust-analyzer cargo behavior-fixture 0.1.0 adapter().";
    const TEST: &str = "rust-analyzer cargo behavior-fixture 0.1.0 tests/adapter_works().";
    let entries = source
        .source_files
        .iter()
        .flat_map(|file| {
            file.methods
                .iter()
                .map(move |method| (file.repository_path.as_str(), method))
        })
        .collect::<Vec<_>>();
    let mut methods = Vec::new();
    for (path, entry) in entries {
        let mut method = IntentionalBoundarySemanticMethod {
            parser_unit_id: entry.parser_unit_id.clone(),
            repository_path: path.to_string(),
            symbol_name: entry.symbol_name.clone(),
            start_line: entry.start_line,
            end_line: entry.end_line,
            indexer: IntentionalBoundaryIndexerKind::Rust,
            status: IntentionalBoundarySemanticMethodStatus::CompilerExcluded {
                reason: "fixture helper".to_string(),
            },
            occurrences: Vec::new(),
            calls: Vec::new(),
            relationships: Vec::new(),
            imports: Vec::new(),
            test_relationships: Vec::new(),
        };
        let location = IntentionalBoundarySemanticRange {
            repository_path: path.to_string(),
            start_line_zero_based: entry.start_line.saturating_sub(1) as u32,
            start_character_zero_based: 0,
            end_line_zero_based: entry.end_line.saturating_sub(1) as u32,
            end_character_zero_based: 1,
        };
        let symbol_id = match entry.symbol_name.as_str() {
            "adapter" => Some(PRODUCTION),
            "adapter_works" => Some(TEST),
            _ => None,
        };
        if let Some(symbol_id) = symbol_id {
            method.status = IntentionalBoundarySemanticMethodStatus::Resolved {
                symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                    symbol_id: symbol_id.to_string(),
                    provider_identity: symbol_id.to_string(),
                    display_name: Some(entry.symbol_name.clone()),
                    category: IntentionalBoundarySemanticSymbolCategory::Callable,
                    provider_kind: "function".to_string(),
                    documentation: Vec::new(),
                    signature: None,
                    signature_referenced_symbols: Vec::new(),
                    owner: None,
                    definitions: vec![location.clone()],
                    visibility: IntentionalBoundarySemanticVisibility::Private,
                    surfaces: Vec::new(),
                    origin: IntentionalBoundarySemanticOrigin::Repository,
                    ambiguity_notes: Vec::new(),
                }),
                joined_definition: Some(location),
            };
            method.test_relationships = vec![IntentionalBoundarySemanticTestFacts {
                test_symbol: TEST.to_string(),
                production: IntentionalBoundarySemanticResolution::Resolved {
                    value: PRODUCTION.to_string(),
                },
                kind: IntentionalBoundarySemanticTestKind::Exercises,
            }];
            if entry.symbol_name == "adapter" {
                method.relationships = vec![IntentionalBoundarySemanticRelationshipFacts {
                    source: PRODUCTION.to_string(),
                    target: "rust-analyzer cargo behavior-fixture 0.1.0 Adapter#".to_string(),
                    kind: IntentionalBoundarySemanticRelationshipKind::Implementation,
                }];
            }
        }
        methods.push(method);
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
            document_count: 1,
            symbol_count: 3,
            relationship_count: 1,
            import_count: 0,
            call_count: 0,
            test_relationship_count: 1,
            unresolved_edge_count: 0,
        }],
        source_references: Vec::new(),
        resolved_method_count: 2,
        compiler_excluded_method_count: methods.len() - 2,
        unresolved_method_count: 0,
        methods,
        semantic_census_sha256: String::new(),
    };
    semantic.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(&semantic)
            .unwrap();
    semantic
}

fn passing_attempt(
    selector: IntentionalBoundaryBehaviorSelector,
    revision: &str,
) -> BehaviorExecutionAttempt {
    let recipe = HistoricalTestRecipeDiscovery {
        status: HistoricalTestRecipeStatus::Selected,
        preparation_commands: Vec::new(),
        command: Some(vec![
            "cargo".to_string(),
            "test".to_string(),
            "--workspace".to_string(),
            "--all-targets".to_string(),
        ]),
        runtime_program: Some("cargo".to_string()),
        inputs: Vec::new(),
        reason: "fixture".to_string(),
    };
    let (_, command) = runtime::targeted_command(&selector, &recipe).unwrap();
    let recipe_json = serde_json::to_string(&recipe).unwrap();
    let runtime_identity = "fixture-runtime";
    let stdout = match &selector {
        IntentionalBoundaryBehaviorSelector::CargoTest { test_name } => {
            format!("running 1 test\ntest {test_name} ... ok\n")
        }
        _ => unreachable!("fixture uses the Cargo selector"),
    };
    let stdout_sha256 = "e".repeat(64);
    let stderr_sha256 = "f".repeat(64);
    let raw = serde_json::json!({
        "schema_version": 1,
        "revision": revision,
        "runtime_identity": runtime_identity,
        "network_enabled": false,
        "preparation": [],
        "test": {
            "stage": "test",
            "logical_command": command,
            "launcher_kind": "fixture",
            "status_code": 0,
            "timed_out": false,
            "network_enabled": false,
            "stdout_complete_sha256": stdout_sha256,
            "stderr_complete_sha256": stderr_sha256,
            "stdout_bounded_sanitized": stdout,
            "stderr_bounded_sanitized": ""
        }
    });
    let raw_result_json = format!("{}\n", serde_json::to_string_pretty(&raw).unwrap());
    let mut execution = IntentionalBoundaryBehaviorExecution {
        execution_id: String::new(),
        revision: revision.to_string(),
        provider: selector.provider(),
        selector,
        recipe_sha256: hash_json(&recipe).unwrap(),
        recipe_json,
        command,
        runtime_identity_sha256: format!("{:x}", Sha256::digest(runtime_identity.as_bytes())),
        status_code: Some(0),
        timed_out: false,
        network_enabled: false,
        test_executed: true,
        executed_test_count: 1,
        matched_test_count: 1,
        stdout_sha256,
        stderr_sha256,
        raw_result_sha256: format!("{:x}", Sha256::digest(raw_result_json.as_bytes())),
        raw_result_json,
    };
    execution.execution_id = runtime::compute_execution_id(&execution).unwrap();
    BehaviorExecutionAttempt {
        outcome: IntentionalBoundaryBehaviorWitnessOutcome::Passed {
            proof: IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            execution_id: execution.execution_id.clone(),
        },
        execution: Some(execution),
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
