use super::super::intentional_boundary_behavior::commitment::finish_behavior_census;
use super::super::intentional_boundary_behavior_outcome::{
    behavior_failed, behavior_invalid, behavior_unavailable,
};
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
fn completion_binds_generator_lineage_and_extends_its_evidence() {
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
    let stage = finish_behavior_stage(
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

    assert_eq!(stage.generator_stage_sha256, generator.stage_sha256);
    assert_eq!(
        stage.behavior_census.base_evidence_census_sha256,
        generator.evidence_census.evidence_census_sha256
    );
    assert_eq!(stage.stage_sha256.len(), 64);
    assert_eq!(
        stage
            .evidence_census
            .input_census_sha256
            .get("targeted_behavior_tests"),
        Some(&stage.behavior_census.behavior_census_sha256)
    );

    let mut changed = stage.clone();
    changed.generator_stage_sha256 = "0".repeat(64);
    assert_ne!(behavior_stage_sha256(&changed).unwrap(), stage.stage_sha256);

    let mut tampered_generator = generator.clone();
    tampered_generator.stage_sha256 = "0".repeat(64);
    let error = finish_behavior_stage(
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
        &tampered_generator,
        stage.behavior_census,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryBehaviorStageErrorKind::InvalidInput
    );
}

#[test]
fn operational_behavior_errors_keep_their_stage_kind() {
    for (source, expected) in [
        (
            behavior_invalid("same detail"),
            IntentionalBoundaryBehaviorStageErrorKind::InvalidInput,
        ),
        (
            behavior_unavailable("same detail"),
            IntentionalBoundaryBehaviorStageErrorKind::InfrastructureUnavailable,
        ),
        (
            behavior_failed("same detail"),
            IntentionalBoundaryBehaviorStageErrorKind::InfrastructureFailed,
        ),
    ] {
        assert_eq!(map_derivation_error(source).kind, expected);
    }
}
