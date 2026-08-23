use super::super::intentional_boundary_evidence_stage::finish_evidence_stage;
use super::super::intentional_boundary_evidence_stage::tests::{evidence, fixture};
use super::super::intentional_boundary_generator::finish_census;
use super::super::intentional_boundary_generator_outcome::{
    generator_failed, generator_invalid, generator_unavailable,
};
use super::super::intentional_boundary_project_model_stage::finish_project_model_stage;
use super::*;
use crate::benchmark::IntentionalBoundaryProjectModelStageOutcome;
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn completion_binds_project_model_lineage_and_extends_its_evidence() {
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
    let generator = finish_census(
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
    let stage = finish_generator_stage(
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
        generator.clone(),
    )
    .unwrap();

    assert_eq!(stage.project_model_stage_sha256, project_model.stage_sha256);
    assert_eq!(
        stage.generator_census.base_evidence_census_sha256,
        project_model.evidence_census.evidence_census_sha256
    );
    assert_eq!(stage.stage_sha256.len(), 64);
    assert_eq!(
        stage.evidence_census.atoms,
        project_model.evidence_census.atoms
    );
    assert_eq!(
        stage
            .evidence_census
            .input_census_sha256
            .get("generator_replay"),
        Some(&stage.generator_census.generator_census_sha256)
    );

    let mut changed = stage.clone();
    changed.project_model_stage_sha256 = "0".repeat(64);
    assert_ne!(
        generator_stage_sha256(&changed).unwrap(),
        stage.stage_sha256
    );

    let mut tampered_project_model = (*project_model).clone();
    tampered_project_model.stage_sha256 = "0".repeat(64);
    let error = finish_generator_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        &tampered_project_model,
        generator,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryGeneratorStageErrorKind::InvalidInput
    );
}

#[test]
fn operational_generator_errors_keep_their_stage_kind() {
    for (source, expected) in [
        (
            generator_invalid("same detail"),
            IntentionalBoundaryGeneratorStageErrorKind::InvalidInput,
        ),
        (
            generator_unavailable("same detail"),
            IntentionalBoundaryGeneratorStageErrorKind::InfrastructureUnavailable,
        ),
        (
            generator_failed("same detail"),
            IntentionalBoundaryGeneratorStageErrorKind::InfrastructureFailed,
        ),
    ] {
        assert_eq!(map_derivation_error(source).kind, expected);
    }
}
