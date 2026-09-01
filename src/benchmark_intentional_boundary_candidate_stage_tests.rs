use super::super::intentional_boundary_ast_stage::finish_ast_stage;
use super::super::intentional_boundary_behavior::commitment::finish_behavior_census;
use super::super::intentional_boundary_behavior_stage::finish_behavior_stage;
use super::super::intentional_boundary_candidate_outcome::candidate_invalid;
use super::super::intentional_boundary_evidence_stage::finish_evidence_stage;
use super::super::intentional_boundary_evidence_stage::tests::{evidence, fixture};
use super::super::intentional_boundary_generator::finish_census;
use super::super::intentional_boundary_generator_stage::finish_generator_stage;
use super::super::intentional_boundary_manifest_stage::finish_manifest_stage;
use super::super::intentional_boundary_project_model_stage::finish_project_model_stage;
use super::super::intentional_boundary_semantic_stage::finish_semantic_stage;
use super::*;
use crate::benchmark::{
    IntentionalBoundaryAstCensusStageOutcome, IntentionalBoundaryLicenseCensusStageOutcome,
    IntentionalBoundaryManifestStageOutcome, IntentionalBoundaryMaterializationOutcome,
    IntentionalBoundaryProjectModelStageOutcome, IntentionalBoundarySemanticCensusStageOutcome,
    IntentionalBoundarySourceCensusStageOutcome,
};
use crate::semantic_index::{SemanticIndex, SemanticIndexProvenance, SemanticTextEncoding};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_indexer_runner::SemanticIndexerBatchOutcome;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn completion_binds_behavior_lineage_and_uses_its_evidence() {
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let (task, materialization, inventory, source, license, mut semantic, ast, mut manifest) =
        fixture();
    semantic.semantic_census = super::super::intentional_boundary_semantic::build_semantic_census(
        Path::new("."),
        &source.source_census,
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    manifest.manifest_census.manifest_contract =
        super::super::intentional_boundary_manifest::MANIFEST_CONTRACT.to_string();
    manifest.manifest_census.manifest_census_sha256 =
        super::super::intentional_boundary_manifest::compute_manifest_census_sha256(
            &manifest.manifest_census,
        )
        .unwrap();
    manifest.binding_census = super::super::bind_intentional_boundary_manifests(
        &source.source_census,
        &semantic.semantic_census,
        &manifest.manifest_census,
    )
    .unwrap();
    let base = finish_evidence_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        evidence(&source, &semantic, &ast, &manifest, false),
    )
    .unwrap();
    let project_model = finish_project_model_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let IntentionalBoundaryProjectModelStageOutcome::Completed(project_model) = project_model
    else {
        panic!("empty provider set must complete");
    };
    let generator_census = finish_census(
        &inventory,
        &source.source_census,
        &semantic.semantic_census,
        &project_model.project_model_census,
        &manifest.manifest_census,
        &manifest.binding_census,
        &project_model.evidence_census,
        Vec::new(),
    )
    .unwrap();
    let generator = finish_generator_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        generator_census,
    )
    .unwrap();
    let behavior_census = finish_behavior_census(
        &source.source_census,
        &semantic.semantic_census,
        &generator.evidence_census,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let behavior = finish_behavior_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        behavior_census,
    )
    .unwrap();
    let candidate_census = super::super::intentional_boundary_candidate::qualify_intentional_boundary_candidates_typed(
        &protocol,
        &source.source_census,
        &semantic.semantic_census,
        &behavior.evidence_census,
    )
    .unwrap();
    let stage = finish_candidate_stage(
        &protocol,
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        &behavior,
        candidate_census,
    )
    .unwrap();

    assert_eq!(stage.behavior_stage_sha256, behavior.stage_sha256);
    assert_eq!(stage.protocol_sha256, protocol.protocol_sha256);
    assert_eq!(
        stage.candidate_census.evidence_census_sha256,
        behavior.evidence_census.evidence_census_sha256
    );
    assert_eq!(stage.stage_sha256.len(), 64);

    let mut changed = stage.clone();
    changed.behavior_stage_sha256 = "0".repeat(64);
    assert_ne!(
        candidate_stage_sha256(&changed).unwrap(),
        stage.stage_sha256
    );

    let mut tampered_behavior = behavior.clone();
    tampered_behavior.stage_sha256 = "0".repeat(64);
    let error = finish_candidate_stage(
        &protocol,
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        &tampered_behavior,
        stage.candidate_census.clone(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryCandidateStageErrorKind::InvalidInput
    );

    let mut mismatched_task = task.clone();
    mismatched_task.protocol_sha256 = "0".repeat(64);
    let error = finish_candidate_stage(
        &protocol,
        &mismatched_task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        &behavior,
        stage.candidate_census,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryCandidateStageErrorKind::InvalidInput
    );
    assert_eq!(
        error.detail,
        "intentional-boundary candidate protocol does not match the frame task"
    );
}

#[test]
fn candidate_errors_map_without_reason_text() {
    let error = map_derivation_error(candidate_invalid("same arbitrary detail"));

    assert_eq!(
        error.kind,
        IntentionalBoundaryCandidateStageErrorKind::InvalidInput
    );
    assert_eq!(error.detail, "same arbitrary detail");
}

#[test]
fn committed_candidate_replay_validates_the_complete_chain_without_reexecuting_upstream_stages() {
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let task: IntentionalBoundaryFrameTask = serde_json::from_slice(include_bytes!(
        "../sniffbench/non-blind-v1-intentional-boundary-frame-task.json"
    ))
    .unwrap();
    let source_repository = committed_repository();
    let state = tempfile::tempdir().unwrap();
    let destination = state.path().join("rank-0001");
    let materialization = super::super::intentional_boundary_materialization::
        materialize_intentional_boundary_repository_fixture(
            &task,
            1,
            &destination,
            source_repository.path(),
        )
        .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Completed(materialization) = materialization
    else {
        panic!("fixture repository must materialize");
    };
    let inventory = super::super::inventory_intentional_boundary_repository_typed(
        &materialization.artifact.repository,
        &materialization.artifact.revision,
        &materialization.checkout_root,
    )
    .unwrap();
    let source = super::super::census_intentional_boundary_repository_stage(
        &task,
        &materialization.artifact,
        &materialization.checkout_root,
        &inventory,
    )
    .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Completed(source) = source else {
        panic!("fixture source census must complete");
    };
    let license = super::super::census_intentional_boundary_repository_licenses(
        &task,
        &materialization.artifact,
        &materialization.checkout_root,
        &inventory,
        &source,
    )
    .unwrap();
    let IntentionalBoundaryLicenseCensusStageOutcome::Completed(license) = license else {
        panic!("fixture license census must complete");
    };
    let files =
        super::super::intentional_boundary_source_census::intentional_boundary_file_records_typed(
            &materialization.checkout_root,
            &inventory,
            &source.source_census,
        )
        .unwrap();
    let semantic = finish_semantic_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &materialization.checkout_root,
        &files,
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::from([(
                SemanticIndexerKind::Rust,
                empty_rust_index(&materialization.checkout_root),
            )]),
            failures: Vec::new(),
        }),
    )
    .unwrap();
    let IntentionalBoundarySemanticCensusStageOutcome::Completed(semantic) = semantic else {
        panic!("fixture semantic census must complete");
    };
    let ast_census = super::super::census_intentional_boundary_rust_ast(
        &materialization.artifact.repository,
        &materialization.artifact.revision,
        &materialization.checkout_root,
        &inventory,
        &source.source_census,
        &semantic.semantic_census,
    )
    .unwrap();
    let ast = finish_ast_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        vec![Ok(ast_census)],
    )
    .unwrap();
    let IntentionalBoundaryAstCensusStageOutcome::Completed(ast) = ast else {
        panic!("fixture AST census must complete");
    };
    let manifests = super::super::census_intentional_boundary_manifests(
        &materialization.artifact.repository,
        &materialization.artifact.revision,
        &materialization.checkout_root,
        &inventory,
    )
    .unwrap();
    let bindings = super::super::bind_intentional_boundary_manifests(
        &source.source_census,
        &semantic.semantic_census,
        &manifests,
    )
    .unwrap();
    let manifest = finish_manifest_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        Ok((manifests, bindings)),
    )
    .unwrap();
    let IntentionalBoundaryManifestStageOutcome::Completed(manifest) = manifest else {
        panic!("fixture manifest census must complete");
    };
    let base = finish_evidence_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        evidence(&source, &semantic, &ast, &manifest, false),
    )
    .unwrap();
    let project_model = finish_project_model_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let IntentionalBoundaryProjectModelStageOutcome::Completed(project_model) = project_model
    else {
        panic!("empty project-model provider set must complete");
    };
    let generator_census = finish_census(
        &inventory,
        &source.source_census,
        &semantic.semantic_census,
        &project_model.project_model_census,
        &manifest.manifest_census,
        &manifest.binding_census,
        &project_model.evidence_census,
        Vec::new(),
    )
    .unwrap();
    let generator = finish_generator_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        generator_census,
    )
    .unwrap();
    let behavior_census = finish_behavior_census(
        &source.source_census,
        &semantic.semantic_census,
        &generator.evidence_census,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let behavior = finish_behavior_stage(
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        behavior_census,
    )
    .unwrap();
    let candidate_census = super::super::qualify_intentional_boundary_candidates_typed(
        &protocol,
        &source.source_census,
        &semantic.semantic_census,
        &behavior.evidence_census,
    )
    .unwrap();
    let candidate = finish_candidate_stage(
        &protocol,
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        &behavior,
        candidate_census,
    )
    .unwrap();

    validate_committed_intentional_boundary_candidate_stage(
        &protocol,
        &task,
        &materialization.artifact,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &project_model,
        &generator,
        &behavior,
        &candidate,
    )
    .unwrap();

    let mut tampered_materialization = materialization.artifact.clone();
    tampered_materialization.tree_oid = "0".repeat(40);
    assert!(
        validate_committed_intentional_boundary_candidate_stage(
            &protocol,
            &task,
            &tampered_materialization,
            &inventory,
            &source,
            &license,
            &semantic,
            &ast,
            &manifest,
            &base,
            &project_model,
            &generator,
            &behavior,
            &candidate,
        )
        .is_err()
    );

    let mut tampered_inventory = inventory.clone();
    tampered_inventory.tracked_entries[0].mode = "100755".to_string();
    assert!(
        validate_committed_intentional_boundary_candidate_stage(
            &protocol,
            &task,
            &materialization.artifact,
            &tampered_inventory,
            &source,
            &license,
            &semantic,
            &ast,
            &manifest,
            &base,
            &project_model,
            &generator,
            &behavior,
            &candidate,
        )
        .is_err()
    );

    let mut tampered_source = source.clone();
    tampered_source.source_census.census_sha256 = "0".repeat(64);
    assert!(
        validate_committed_intentional_boundary_candidate_stage(
            &protocol,
            &task,
            &materialization.artifact,
            &inventory,
            &tampered_source,
            &license,
            &semantic,
            &ast,
            &manifest,
            &base,
            &project_model,
            &generator,
            &behavior,
            &candidate,
        )
        .is_err()
    );
}

fn committed_repository() -> tempfile::TempDir {
    let repository = tempfile::tempdir().unwrap();
    git(repository.path(), &["init", "--quiet"]);
    git(repository.path(), &["config", "user.name", "SniffBench"]);
    git(
        repository.path(),
        &["config", "user.email", "sniffbench@example.invalid"],
    );
    fs::create_dir(repository.path().join("src")).unwrap();
    fs::write(repository.path().join("src/lib.rs"), "// fixture\n").unwrap();
    fs::write(repository.path().join("LICENSE"), "fixture license\n").unwrap();
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
    repository
}

fn empty_rust_index(root: &Path) -> SemanticIndex {
    SemanticIndex {
        format_version: crate::semantic_index::SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: root.to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            arguments: Vec::new(),
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            invocations: vec![crate::semantic_index::SemanticIndexerInvocation {
                arguments: Vec::new(),
                context: Default::default(),
                contribution: crate::semantic_index::SemanticIndexerContribution::CompleteIndex,
                output_sha256: "0".repeat(64),
            }],
            diagnostics: Vec::new(),
        },
        documents: BTreeMap::new(),
        symbols: BTreeMap::new(),
        relationships: Default::default(),
        imports: Default::default(),
        calls: Default::default(),
        test_relationships: Default::default(),
        unresolved_edges: Default::default(),
    }
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
