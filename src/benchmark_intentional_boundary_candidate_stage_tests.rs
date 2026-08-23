use super::super::intentional_boundary_behavior::commitment::finish_behavior_census;
use super::super::intentional_boundary_behavior_stage::finish_behavior_stage;
use super::super::intentional_boundary_candidate_outcome::candidate_invalid;
use super::super::intentional_boundary_evidence_stage::finish_evidence_stage;
use super::super::intentional_boundary_evidence_stage::tests::{evidence, fixture};
use super::super::intentional_boundary_generator::finish_census;
use super::super::intentional_boundary_generator_stage::finish_generator_stage;
use super::super::intentional_boundary_project_model_stage::finish_project_model_stage;
use super::*;
use crate::benchmark::IntentionalBoundaryProjectModelStageOutcome;
use std::collections::BTreeMap;
use std::path::Path;

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
