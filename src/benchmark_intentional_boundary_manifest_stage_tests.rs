use super::*;
use crate::benchmark::{
    BoundaryGitObjectFormat, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestCensus, IntentionalBoundaryManifestExclusionReason,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryMaterialization,
    IntentionalBoundaryMaterializationOutcome, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticCensusStage,
    IntentionalBoundarySourceCensus, IntentionalBoundarySourceCensusStage,
    inventory_intentional_boundary_repository_typed,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

const TASK: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-frame-task.json");

#[allow(clippy::type_complexity)]
fn fixture() -> (
    IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySourceCensusStage,
    IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundarySemanticCensusStage,
    IntentionalBoundaryAstCensusStage,
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
        repository,
        revision,
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
    (
        task,
        materialization,
        inventory,
        source,
        license,
        semantic,
        ast,
    )
}

fn completed_censuses(
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source: &IntentionalBoundarySourceCensusStage,
    semantic: &IntentionalBoundarySemanticCensusStage,
) -> (
    IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestBindingCensus,
) {
    let manifests = IntentionalBoundaryManifestCensus {
        schema_version: 5,
        manifest_contract: "fixture-manifests".to_string(),
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
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
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
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
    (manifests, bindings)
}

fn derivation_error(
    kind: super::super::intentional_boundary_manifest_outcome::ManifestDerivationErrorKind,
    provider: Option<IntentionalBoundaryManifestProvider>,
    repository_path: Option<&str>,
    detail: &str,
) -> super::super::intentional_boundary_manifest_outcome::ManifestDerivationError {
    super::super::intentional_boundary_manifest_outcome::ManifestDerivationError {
        kind,
        provider,
        repository_path: repository_path.map(str::to_string),
        detail: detail.to_string(),
    }
}

#[test]
fn preserves_all_terminal_failures_with_canonical_bounded_evidence() {
    use super::super::intentional_boundary_manifest_outcome::ManifestDerivationErrorKind;

    let resolved = resolve_manifest_errors(vec![
        derivation_error(
            ManifestDerivationErrorKind::ManifestParserRejected,
            Some(IntentionalBoundaryManifestProvider::NodePackageManifest),
            Some("z/package.json"),
            &"x".repeat(5_000),
        ),
        derivation_error(
            ManifestDerivationErrorKind::ManifestEncodingRejected,
            Some(IntentionalBoundaryManifestProvider::PythonProjectManifest),
            Some("a/pyproject.toml"),
            "not UTF-8",
        ),
    ])
    .unwrap();
    let ManifestPreflight::Excluded(failures) = resolved else {
        panic!("terminal manifest failures must exclude");
    };

    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].repository_path, "a/pyproject.toml");
    assert_eq!(failures[1].repository_path, "z/package.json");
    assert_eq!(failures[1].detail_sha256.len(), 64);
    assert_eq!(failures[1].retained_detail.len(), 4 * 1024);
    assert!(failures[1].detail_truncated);
}

#[test]
fn operational_failure_prevents_terminal_exclusion_without_reason_text() {
    use super::super::intentional_boundary_manifest_outcome::ManifestDerivationErrorKind;

    let error = resolve_manifest_errors(vec![
        derivation_error(
            ManifestDerivationErrorKind::ManifestParserRejected,
            Some(IntentionalBoundaryManifestProvider::CargoManifest),
            Some("Cargo.toml"),
            "terminal parser rejection",
        ),
        derivation_error(
            ManifestDerivationErrorKind::InfrastructureFailed,
            None,
            None,
            "git object read failed",
        ),
    ])
    .err()
    .unwrap();

    assert_eq!(
        error.kind,
        IntentionalBoundaryManifestStageErrorKind::InfrastructureFailed
    );
    assert_eq!(error.detail, "git object read failed");
    assert!(!error.detail.contains("terminal parser rejection"));
}

#[test]
fn completion_and_exclusion_seal_every_upstream_identity() {
    use super::super::intentional_boundary_manifest_outcome::ManifestDerivationErrorKind;

    let (task, materialization, inventory, source, license, semantic, ast) = fixture();
    let censuses = completed_censuses(&materialization, &inventory, &source, &semantic);
    let completed = finish_manifest_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        Ok(censuses),
    )
    .unwrap();
    let IntentionalBoundaryManifestStageOutcome::Completed(mut completed) = completed else {
        panic!("valid manifest censuses must complete");
    };
    assert_eq!(completed.ast_census_stage_sha256, ast.stage_sha256);
    assert_eq!(completed.stage_sha256.len(), 64);
    completed.binding_census.unresolved_declaration_count += 1;
    assert_ne!(completed.stage_sha256, stage_sha256(&completed).unwrap());

    let excluded = finish_manifest_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        &ast,
        Err(vec![derivation_error(
            ManifestDerivationErrorKind::ManifestShapeRejected,
            Some(IntentionalBoundaryManifestProvider::CargoManifest),
            Some("Cargo.toml"),
            "not a regular blob",
        )]),
    )
    .unwrap();
    let IntentionalBoundaryManifestStageOutcome::Excluded(excluded) = excluded else {
        panic!("terminal manifest shape must exclude");
    };
    assert_eq!(excluded.ast_census_stage_sha256, ast.stage_sha256);
    assert_eq!(excluded.exclusion_sha256.len(), 64);
}

#[test]
fn completion_rejects_manifest_and_binding_lineage_drift() {
    let (task, materialization, inventory, source, license, semantic, ast) = fixture();
    let (manifests, bindings) =
        completed_censuses(&materialization, &inventory, &source, &semantic);
    let mut changed_hash = bindings.clone();
    changed_hash.manifest_census_sha256 = "9".repeat(64);
    let mut changed_repository = bindings.clone();
    changed_repository.repository = "example/other".to_string();
    let mut changed_revision = bindings;
    changed_revision.revision = "8".repeat(40);

    for changed in [changed_hash, changed_repository, changed_revision] {
        let error = finish_manifest_stage(
            &task,
            &materialization,
            &inventory,
            &source,
            &license,
            &semantic,
            &ast,
            Ok((manifests.clone(), changed)),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.kind,
            IntentionalBoundaryManifestStageErrorKind::InvalidInput
        );
    }
}

#[test]
fn maps_ast_stage_failures_without_message_classification() {
    let error = map_ast_error(IntentionalBoundaryAstCensusStageError {
        kind: IntentionalBoundaryAstCensusStageErrorKind::InfrastructureUnavailable,
        detail: "AST runtime unavailable".to_string(),
    });
    assert_eq!(
        error.kind,
        IntentionalBoundaryManifestStageErrorKind::InfrastructureUnavailable
    );
    assert_eq!(error.detail, "AST runtime unavailable");
}

#[test]
fn real_preflight_preserves_every_malformed_manifest() {
    let source = tempfile::tempdir().unwrap();
    git(source.path(), &["init"]);
    git(
        source.path(),
        &["config", "user.email", "sniff@example.test"],
    );
    git(source.path(), &["config", "user.name", "Sniff Test"]);
    write(source.path(), "a/package.json", "{not-json\n");
    write(source.path(), "b/pyproject.toml", "[project\n");
    git(source.path(), &["add", "."]);
    git(source.path(), &["commit", "-m", "fixture"]);
    let task: IntentionalBoundaryFrameTask = serde_json::from_slice(TASK).unwrap();
    let state = tempfile::tempdir().unwrap();
    let destination = state.path().join("rank-0001");
    let outcome = super::super::intentional_boundary_materialization::
        materialize_intentional_boundary_repository_fixture(
            &task,
            1,
            &destination,
            source.path(),
        )
        .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Completed(completed) = outcome else {
        panic!("committed fixture must materialize");
    };
    let inventory = inventory_intentional_boundary_repository_typed(
        &completed.artifact.repository,
        &completed.artifact.revision,
        &completed.checkout_root,
    )
    .unwrap();

    let errors = preflight_manifest_entries(&completed.checkout_root, &inventory);
    let resolved = resolve_manifest_errors(errors).unwrap();
    let ManifestPreflight::Excluded(failures) = resolved else {
        panic!("malformed manifests must exclude");
    };

    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].repository_path, "a/package.json");
    assert_eq!(failures[1].repository_path, "b/pyproject.toml");
    assert!(failures.iter().all(|failure| {
        failure.reason == IntentionalBoundaryManifestExclusionReason::ManifestParserRejected
    }));
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?} failed");
}
