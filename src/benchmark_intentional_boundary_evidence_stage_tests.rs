use super::super::intentional_boundary_compiler_evidence::finish_evidence_census;
use super::super::intentional_boundary_evidence_stage_support::expected_base_evidence_inputs;
use super::*;
use crate::benchmark::{
    BoundaryGitObjectFormat, IntentionalBoundaryAstCensus, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestCensus, IntentionalBoundaryManifestStage,
    IntentionalBoundaryMaterialization, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticCensusStage,
    IntentionalBoundarySourceCensus, IntentionalBoundarySourceCensusStage,
};
use std::collections::BTreeMap;

const TASK: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-frame-task.json");

#[allow(clippy::type_complexity)]
pub(in crate::benchmark::release) fn fixture() -> (
    IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySourceCensusStage,
    IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundarySemanticCensusStage,
    IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryManifestStage,
) {
    let task: IntentionalBoundaryFrameTask = serde_json::from_slice(TASK).unwrap();
    let repository = task.repositories[0].repository.clone();
    let revision = "a".repeat(40);
    let inventory = IntentionalBoundaryRepositoryInventory {
        schema_version: 1,
        inventory_contract: "fixture-inventory".to_string(),
        repository: repository.clone(),
        revision: revision.clone(),
        git_object_format: BoundaryGitObjectFormat::Sha1,
        tracked_entries: Vec::new(),
        inventory_sha256: "b".repeat(64),
    };
    let materialization = IntentionalBoundaryMaterialization {
        schema_version: 1,
        materialization_contract: "fixture-materialization".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        population_rank_sha256: task.repositories[0].population_rank_sha256.clone(),
        repository: repository.clone(),
        clone_url: format!("https://{repository}.git"),
        revision: revision.clone(),
        git_object_format: "sha1".to_string(),
        tree_oid: "c".repeat(40),
        materialization_sha256: "d".repeat(64),
    };
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture-source".to_string(),
        repository: repository.clone(),
        revision: revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        tracked_entry_count: 0,
        source_files: Vec::new(),
        source_file_count: 0,
        method_count: 0,
        census_sha256: "e".repeat(64),
    };
    let source = IntentionalBoundarySourceCensusStage {
        schema_version: 1,
        stage_contract: "fixture-source-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_extension_contract: "fixture-extensions".to_string(),
        source_census,
        stage_sha256: "f".repeat(64),
    };
    let license = IntentionalBoundaryLicenseCensusStage {
        schema_version: 1,
        stage_contract: "fixture-license-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source.stage_sha256.clone(),
        filename_contract: "fixture-license-policy".to_string(),
        tracked_entry_count: 0,
        matched_candidate_count: 0,
        license_artifacts: Vec::new(),
        rejected_candidates: Vec::new(),
        stage_sha256: "1".repeat(64),
    };
    let semantic_census = IntentionalBoundarySemanticCensus {
        schema_version: 1,
        semantic_contract: "fixture-semantic".to_string(),
        repository: repository.clone(),
        revision: revision.clone(),
        source_census_sha256: source.source_census.census_sha256.clone(),
        indexers: Vec::new(),
        source_references: Vec::new(),
        methods: Vec::new(),
        resolved_method_count: 0,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_census_sha256: "2".repeat(64),
    };
    let semantic = IntentionalBoundarySemanticCensusStage {
        schema_version: 1,
        stage_contract: "fixture-semantic-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source.stage_sha256.clone(),
        license_census_stage_sha256: license.stage_sha256.clone(),
        semantic_census,
        stage_sha256: "3".repeat(64),
    };
    let ast = IntentionalBoundaryAstCensusStage {
        schema_version: 1,
        stage_contract: "fixture-ast-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source.stage_sha256.clone(),
        license_census_stage_sha256: license.stage_sha256.clone(),
        semantic_census_stage_sha256: semantic.stage_sha256.clone(),
        languages: Vec::new(),
        ast_censuses: Vec::new(),
        stage_sha256: "4".repeat(64),
    };
    let manifests = IntentionalBoundaryManifestCensus {
        schema_version: 5,
        manifest_contract: "fixture-manifests".to_string(),
        repository: repository.clone(),
        revision: revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        documents: Vec::new(),
        document_count_by_provider: BTreeMap::new(),
        declarations: Vec::new(),
        declaration_count_by_kind: BTreeMap::new(),
        manifest_census_sha256: "5".repeat(64),
    };
    let bindings = IntentionalBoundaryManifestBindingCensus {
        schema_version: 3,
        binding_contract: "fixture-bindings".to_string(),
        repository,
        revision,
        source_census_sha256: source.source_census.census_sha256.clone(),
        semantic_census_sha256: semantic.semantic_census.semantic_census_sha256.clone(),
        manifest_census_sha256: manifests.manifest_census_sha256.clone(),
        bindings: Vec::new(),
        bound_declaration_count: 0,
        non_method_declaration_count: 0,
        awaiting_generator_replay_count: 0,
        unresolved_declaration_count: 0,
        binding_census_sha256: "6".repeat(64),
    };
    let manifest = IntentionalBoundaryManifestStage {
        schema_version: 1,
        stage_contract: "fixture-manifest-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source.stage_sha256.clone(),
        license_census_stage_sha256: license.stage_sha256.clone(),
        semantic_census_stage_sha256: semantic.stage_sha256.clone(),
        ast_census_stage_sha256: ast.stage_sha256.clone(),
        manifest_census: manifests,
        binding_census: bindings,
        stage_sha256: "7".repeat(64),
    };
    (
        task,
        materialization,
        inventory,
        source,
        license,
        semantic,
        ast,
        manifest,
    )
}

pub(in crate::benchmark::release) fn evidence(
    source: &IntentionalBoundarySourceCensusStage,
    semantic: &IntentionalBoundarySemanticCensusStage,
    ast: &IntentionalBoundaryAstCensusStage,
    manifest: &IntentionalBoundaryManifestStage,
    extra_input: bool,
) -> IntentionalBoundaryEvidenceCensus {
    let mut inputs = expected_base_evidence_inputs(
        &semantic.semantic_census,
        &ast.ast_censuses,
        &manifest.manifest_census,
        &manifest.binding_census,
    )
    .unwrap();
    if extra_input {
        inputs.insert("unexpected".to_string(), "8".repeat(64));
    }
    finish_evidence_census(
        &source.source_census,
        &semantic.semantic_census,
        inputs,
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn completion_binds_every_upstream_identity() {
    let (task, materialization, inventory, source, license, semantic, ast, manifest) = fixture();
    let evidence = evidence(&source, &semantic, &ast, &manifest, false);
    let stage = finish_evidence_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        evidence,
    )
    .unwrap();

    assert_eq!(stage.frame_task_sha256, task.task_sha256);
    assert_eq!(
        stage.materialization_sha256,
        materialization.materialization_sha256
    );
    assert_eq!(stage.inventory_sha256, inventory.inventory_sha256);
    assert_eq!(stage.source_census_stage_sha256, source.stage_sha256);
    assert_eq!(stage.license_census_stage_sha256, license.stage_sha256);
    assert_eq!(stage.semantic_census_stage_sha256, semantic.stage_sha256);
    assert_eq!(stage.ast_census_stage_sha256, ast.stage_sha256);
    assert_eq!(stage.manifest_stage_sha256, manifest.stage_sha256);
    assert_eq!(stage.stage_sha256.len(), 64);
}

#[test]
fn completion_rejects_extra_inputs_and_manifest_lineage_drift() {
    let (task, materialization, inventory, source, license, semantic, ast, manifest) = fixture();
    let extra = evidence(&source, &semantic, &ast, &manifest, true);
    let error = finish_evidence_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &manifest,
        extra,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryEvidenceStageErrorKind::InvalidInput
    );

    let clean = evidence(&source, &semantic, &ast, &manifest, false);
    let mut changed_manifest = manifest;
    changed_manifest.ast_census_stage_sha256 = "9".repeat(64);
    let error = finish_evidence_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        &changed_manifest,
        clean,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryEvidenceStageErrorKind::InvalidInput
    );
}

#[test]
fn maps_manifest_errors_without_reason_text() {
    for (source_kind, expected_kind) in [
        (
            IntentionalBoundaryManifestStageErrorKind::InvalidInput,
            IntentionalBoundaryEvidenceStageErrorKind::InvalidInput,
        ),
        (
            IntentionalBoundaryManifestStageErrorKind::InfrastructureUnavailable,
            IntentionalBoundaryEvidenceStageErrorKind::InfrastructureUnavailable,
        ),
        (
            IntentionalBoundaryManifestStageErrorKind::InfrastructureFailed,
            IntentionalBoundaryEvidenceStageErrorKind::InfrastructureFailed,
        ),
    ] {
        let mapped = map_manifest_error(IntentionalBoundaryManifestStageError {
            kind: source_kind,
            detail: "same arbitrary detail".to_string(),
        });
        assert_eq!(mapped.kind, expected_kind);
        assert_eq!(mapped.detail, "same arbitrary detail");
    }
}

#[test]
fn repeated_ast_language_is_a_typed_invalid_input() {
    let (_, _, _, _, _, semantic, _, manifest) = fixture();
    let ast = IntentionalBoundaryAstCensus {
        schema_version: 7,
        ast_contract: "fixture-ast".to_string(),
        repository: manifest.manifest_census.repository.clone(),
        revision: manifest.manifest_census.revision.clone(),
        source_census_sha256: manifest.binding_census.source_census_sha256.clone(),
        semantic_census_sha256: semantic.semantic_census.semantic_census_sha256.clone(),
        languages: vec!["rust".to_string()],
        methods: Vec::new(),
        method_count: 0,
        fact_count: 0,
        ast_census_sha256: "a".repeat(64),
    };
    let error = expected_base_evidence_inputs(
        &semantic.semantic_census,
        &[ast.clone(), ast],
        &manifest.manifest_census,
        &manifest.binding_census,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        super::super::intentional_boundary_evidence_outcome::EvidenceDerivationErrorKind::InvalidInput
    );
}
