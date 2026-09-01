use super::super::intentional_boundary_evidence_stage::finish_evidence_stage;
use super::super::intentional_boundary_evidence_stage::tests::{evidence, fixture};
use super::super::intentional_boundary_project_model::finish_project_model_census;
use super::super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationErrorKind, project_model_error, project_model_process_error,
};
use super::super::intentional_boundary_project_model_stage_support::{
    ResolvedProjectModelRun, resolve_project_model_runs,
};
use super::*;
use crate::benchmark::{
    IntentionalBoundaryEvidenceStageError, IntentionalBoundaryEvidenceStageErrorKind,
    IntentionalBoundaryManifestDocument, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryProjectModelExclusionReason, IntentionalBoundaryProjectModelFailurePhase,
};
use crate::sandbox::SandboxOutput;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
fn base_stage(
    source: &IntentionalBoundarySourceCensusStage,
    license: &IntentionalBoundaryLicenseCensusStage,
    semantic: &IntentionalBoundarySemanticCensusStage,
    ast: &IntentionalBoundaryAstCensusStage,
    manifest: &IntentionalBoundaryManifestStage,
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> IntentionalBoundaryEvidenceStage {
    finish_evidence_stage(
        task,
        materialization,
        inventory,
        source,
        license,
        semantic,
        ast,
        manifest,
        evidence(source, semantic, ast, manifest, false),
    )
    .unwrap()
}

#[test]
fn completion_binds_every_upstream_identity_and_extends_base_evidence() {
    let (task, materialization, inventory, source, license, mut semantic, ast, mut manifest) =
        fixture();
    semantic.semantic_census = super::super::intentional_boundary_semantic::build_semantic_census(
        Path::new("."),
        &source.source_census,
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    manifest.binding_census.semantic_census_sha256 =
        semantic.semantic_census.semantic_census_sha256.clone();
    let base = base_stage(
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &task,
        &materialization,
        &inventory,
    );
    let outcome = finish_project_model_stage(
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
    let IntentionalBoundaryProjectModelStageOutcome::Completed(stage) = outcome else {
        panic!("empty provider set must complete");
    };

    assert!(stage.required_providers.is_empty());
    assert!(stage.project_model_census.executions.is_empty());
    assert!(stage.binding_census.bindings.is_empty());
    assert_eq!(stage.base_evidence_stage_sha256, base.stage_sha256);
    assert_eq!(stage.manifest_stage_sha256, manifest.stage_sha256);
    assert_eq!(stage.ast_census_stage_sha256, ast.stage_sha256);
    assert_eq!(stage.stage_sha256.len(), 64);
    assert_eq!(
        stage
            .evidence_census
            .input_census_sha256
            .get(PROJECT_MODEL_INPUT),
        Some(&stage.project_model_census.project_model_census_sha256)
    );
    assert_eq!(
        stage
            .evidence_census
            .input_census_sha256
            .get(PROJECT_MODEL_BINDING_INPUT),
        Some(&stage.binding_census.binding_census_sha256)
    );
}

#[test]
fn terminal_provider_failures_become_hash_bound_exclusion_evidence() {
    let (_, _, inventory, _, _, _, _, _) = fixture();
    let process = SandboxOutput {
        status_code: Some(2),
        stdout: "partial model".to_string(),
        stderr: "repository rejected".to_string(),
        stdout_sha256: sha256(b"partial model"),
        stderr_sha256: sha256(b"repository rejected"),
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    };
    let error = project_model_process_error(
        ProjectModelDerivationErrorKind::ProviderRejectedRepository,
        IntentionalBoundaryProjectModelProvider::CargoMetadata,
        IntentionalBoundaryProjectModelFailurePhase::Execution,
        "Cargo.toml",
        "arbitrary terminal detail",
        process,
    );
    let resolved = resolve_project_model_runs(
        &inventory,
        vec![(
            IntentionalBoundaryProjectModelProvider::CargoMetadata,
            Err(error),
        )],
    )
    .unwrap();
    let ResolvedProjectModelRun::Excluded(failures) = resolved else {
        panic!("terminal provider rejection must exclude");
    };

    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0].reason,
        IntentionalBoundaryProjectModelExclusionReason::ProviderRejectedRepository
    );
    assert_eq!(
        failures[0].invocation_anchor_repository_path.as_deref(),
        Some("Cargo.toml")
    );
    assert_eq!(failures[0].detail_sha256.len(), 64);
    assert_eq!(failures[0].process.as_ref().unwrap().status_code, Some(2));
}

#[test]
fn exclusion_commits_manifest_derived_provider_requirements() {
    let (task, materialization, inventory, source, license, semantic, ast, mut manifest) =
        fixture();
    manifest
        .manifest_census
        .documents
        .push(IntentionalBoundaryManifestDocument {
            provider: IntentionalBoundaryManifestProvider::CargoManifest,
            repository_path: "Cargo.toml".to_string(),
            object_id: "a".repeat(40),
            source_sha256: "b".repeat(64),
            declaration_count: 0,
        });
    manifest
        .manifest_census
        .document_count_by_provider
        .insert(IntentionalBoundaryManifestProvider::CargoManifest, 1);
    let base = base_stage(
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &task,
        &materialization,
        &inventory,
    );
    let provider = IntentionalBoundaryProjectModelProvider::CargoMetadata;
    let outcome = finish_project_model_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        vec![provider],
        vec![(
            provider,
            Err(project_model_error(
                ProjectModelDerivationErrorKind::ProviderRejectedRepository,
                provider,
                IntentionalBoundaryProjectModelFailurePhase::Execution,
                Some("Cargo.toml"),
                "typed rejection",
            )),
        )],
    )
    .unwrap();
    let IntentionalBoundaryProjectModelStageOutcome::Excluded(exclusion) = outcome else {
        panic!("terminal provider rejection must exclude");
    };

    assert_eq!(exclusion.required_providers, [provider]);
    assert_eq!(exclusion.failures.len(), 1);
    assert_eq!(exclusion.exclusion_sha256.len(), 64);
    let mut changed = (*exclusion).clone();
    changed.required_providers.clear();
    assert_ne!(
        exclusion_sha256(&changed).unwrap(),
        exclusion.exclusion_sha256
    );
}

#[test]
fn operational_kinds_never_become_checkpointable_exclusions() {
    let (_, _, inventory, _, _, _, _, _) = fixture();
    for (source_kind, expected_kind) in [
        (
            ProjectModelDerivationErrorKind::InvalidInput,
            IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
        ),
        (
            ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            IntentionalBoundaryProjectModelStageErrorKind::InfrastructureUnavailable,
        ),
        (
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed,
        ),
    ] {
        let error = project_model_error(
            source_kind,
            IntentionalBoundaryProjectModelProvider::GoList,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some("go.mod"),
            "identical arbitrary detail",
        );
        let mapped = resolve_project_model_runs(
            &inventory,
            vec![(IntentionalBoundaryProjectModelProvider::GoList, Err(error))],
        )
        .unwrap_err();
        assert_eq!(mapped.kind, expected_kind);
        assert_eq!(mapped.detail, "identical arbitrary detail");
    }
}

#[test]
fn malformed_provider_coverage_is_terminal_without_reason_text_matching() {
    let (_, _, inventory, _, _, _, _, _) = fixture();
    let empty = finish_project_model_census(&inventory, Vec::new(), Vec::new()).unwrap();
    let resolved = resolve_project_model_runs(
        &inventory,
        vec![(
            IntentionalBoundaryProjectModelProvider::GradleToolingApi,
            Ok(empty),
        )],
    )
    .unwrap();
    let ResolvedProjectModelRun::Excluded(failures) = resolved else {
        panic!("incomplete provider coverage must exclude");
    };
    assert_eq!(
        failures[0].reason,
        IntentionalBoundaryProjectModelExclusionReason::ProviderOutputIncomplete
    );
}

#[test]
fn required_providers_are_derived_from_manifests_not_caller_preference() {
    let (task, materialization, inventory, source, license, semantic, ast, manifest) = fixture();
    let base = base_stage(
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &task,
        &materialization,
        &inventory,
    );
    let error = finish_project_model_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        &base,
        vec![IntentionalBoundaryProjectModelProvider::CargoMetadata],
        vec![(
            IntentionalBoundaryProjectModelProvider::CargoMetadata,
            Err(project_model_error(
                ProjectModelDerivationErrorKind::ProviderRejectedRepository,
                IntentionalBoundaryProjectModelProvider::CargoMetadata,
                IntentionalBoundaryProjectModelFailurePhase::Execution,
                Some("Cargo.toml"),
                "caller invented provider",
            )),
        )],
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryProjectModelStageErrorKind::InvalidInput
    );
}

#[test]
fn upstream_error_kinds_map_without_detail_classification() {
    for (source_kind, expected_kind) in [
        (
            IntentionalBoundaryEvidenceStageErrorKind::InvalidInput,
            IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
        ),
        (
            IntentionalBoundaryEvidenceStageErrorKind::InfrastructureUnavailable,
            IntentionalBoundaryProjectModelStageErrorKind::InfrastructureUnavailable,
        ),
        (
            IntentionalBoundaryEvidenceStageErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed,
        ),
    ] {
        let mapped = map_evidence_error(IntentionalBoundaryEvidenceStageError {
            kind: source_kind,
            detail: "same detail".to_string(),
        });
        assert_eq!(mapped.kind, expected_kind);
        assert_eq!(mapped.detail, "same detail");
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
