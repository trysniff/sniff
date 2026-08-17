use crate::product_contract::SlopPattern;
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[path = "benchmark_release.rs"]
mod release;

#[cfg(test)]
pub(crate) use release::write_test_non_blind_source_seal;
#[cfg(test)]
pub(crate) use release::write_test_source_seal;
pub use release::{
    ActualCostReceipt, AffectedHistoricalMethod, BenchmarkAdjudication, BenchmarkBaseline,
    BenchmarkBaselineFinding, BenchmarkCorpus, BenchmarkEvidence, BenchmarkPartition, BenchmarkRun,
    BenchmarkRunPrediction, BenchmarkScope, BenchmarkSourceSeal, BenchmarkSubmission,
    BenchmarkUsage, BlindCaseBundle, BlindReviewer, BoundaryEvidenceKind, BoundaryGitEntryKind,
    BoundaryGitObjectFormat, DockerHistoricalV2TestExecutor, FrameEligibilityAudit,
    FrameIneligibilityReason, FrameIneligibleRecord,
    HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION,
    HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION,
    HISTORICAL_V2_EXECUTION_CHECKPOINT_SCHEMA_VERSION,
    HISTORICAL_V2_EXECUTION_HARNESS_SCHEMA_VERSION, HISTORICAL_V2_FRAME_SCHEMA_VERSION,
    HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION,
    HISTORICAL_V2_IDENTICAL_TEST_PLAN_SCHEMA_VERSION,
    HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION, HISTORICAL_V2_PROTOCOL_SCHEMA_VERSION,
    HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION, HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
    HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION,
    HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION,
    HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION, HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION,
    HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_TEST_MATERIALIZATION_SCHEMA_VERSION, HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION,
    HistoricalAssessmentDisposition, HistoricalAssessmentEvidence, HistoricalCapturedDiff,
    HistoricalChangedPath, HistoricalCloneOutcome, HistoricalCommitMetadata, HistoricalDiffHunk,
    HistoricalEvidenceKind, HistoricalExclusionReason, HistoricalGitDiscovery,
    HistoricalProductionPathDelta, HistoricalRepositoryAssessment, HistoricalRepositoryCandidate,
    HistoricalRepositoryFacts, HistoricalRevisionSide, HistoricalSelectedProvenance,
    HistoricalSnapshotRoots, HistoricalSourceDeltaCensus, HistoricalTestExecution,
    HistoricalTestExecutionOutcome, HistoricalTestOutcome, HistoricalTestRecipeDiscovery,
    HistoricalTestRecipeInput, HistoricalTestRecipeStatus, HistoricalTestResult,
    HistoricalTestStepResult, HistoricalV2AssessmentContract, HistoricalV2AssessmentIdentity,
    HistoricalV2AssessmentIdentityInputs, HistoricalV2CandidateDecision,
    HistoricalV2CandidateOutcome, HistoricalV2ChangedMethod,
    HistoricalV2ChangedMethodResolutionFailure, HistoricalV2CheckpointedExecution,
    HistoricalV2DatasetContract, HistoricalV2DatasetShard, HistoricalV2ExclusionArtifact,
    HistoricalV2ExclusionManifest, HistoricalV2ExecutionBaseImage, HistoricalV2ExecutionCheckpoint,
    HistoricalV2ExecutionCheckpointDisposition, HistoricalV2ExecutionCheckpointInputs,
    HistoricalV2ExecutionCommandEvidence, HistoricalV2ExecutionError,
    HistoricalV2ExecutionErrorKind, HistoricalV2ExecutionHarness, HistoricalV2ExecutionPhase,
    HistoricalV2ExecutionPolicy, HistoricalV2ExecutionSide, HistoricalV2Frame,
    HistoricalV2FrameDisposition, HistoricalV2FrameExclusionReason, HistoricalV2FrameRecord,
    HistoricalV2FrameShard, HistoricalV2GitCommandRejectionEvidence,
    HistoricalV2IdenticalTestExclusionReason, HistoricalV2IdenticalTestExecution,
    HistoricalV2IdenticalTestExecutionRequest, HistoricalV2IdenticalTestExecutor,
    HistoricalV2IdenticalTestOutcome, HistoricalV2IdenticalTestPlan, HistoricalV2Materialization,
    HistoricalV2MaterializationExclusion, HistoricalV2MaterializationExclusionEvidence,
    HistoricalV2MaterializationExclusionReason, HistoricalV2MaterializedRoots,
    HistoricalV2MethodBounds, HistoricalV2NoTestPatchArtifact, HistoricalV2PartitionExclusions,
    HistoricalV2PatchFacts, HistoricalV2PayloadStageInputs, HistoricalV2PreparedStage,
    HistoricalV2ProjectedRow, HistoricalV2Protocol, HistoricalV2PublicSurfaceChange,
    HistoricalV2PublicSurfaceDelta, HistoricalV2PublicSurfaceEntry, HistoricalV2PublicSymbol,
    HistoricalV2Qualification, HistoricalV2QualificationExclusionReason,
    HistoricalV2QualificationOutcome, HistoricalV2QualifiedPath,
    HistoricalV2RawIdenticalTestExecution, HistoricalV2RecoverableTestExecutor,
    HistoricalV2ReviewContract, HistoricalV2SelectedPayload, HistoricalV2SelectedPayloads,
    HistoricalV2SelectedSlotPayloadArtifact, HistoricalV2SelectionContract,
    HistoricalV2SemanticCensus, HistoricalV2SemanticCensusExclusion,
    HistoricalV2SemanticCensusExclusionReason, HistoricalV2SemanticCensusFailureEvidence,
    HistoricalV2SemanticCensusFailurePhase, HistoricalV2SemanticProcessEvidence,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SemanticSnapshotSide, HistoricalV2Slot,
    HistoricalV2SlotOutcome, HistoricalV2SlotRunDisposition, HistoricalV2SlotRunIdentity,
    HistoricalV2SlotRunSummary, HistoricalV2SlotSelection, HistoricalV2SlotStage,
    HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageCheckpointInput,
    HistoricalV2SlotStageContext, HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind,
    HistoricalV2SlotStageExecutor, HistoricalV2SlotStageFuture, HistoricalV2SlotStageJournal,
    HistoricalV2SlotStageOutcome, HistoricalV2SourceCensus, HistoricalV2SourceCensusExclusion,
    HistoricalV2SourceCensusExclusionReason, HistoricalV2SourceCensusFailureEvidence,
    HistoricalV2SourceFile, HistoricalV2SourceMethod, HistoricalV2SourceRole,
    HistoricalV2SourceRoleBasis, HistoricalV2SourceRoleDecision, HistoricalV2SourceSnapshotCensus,
    HistoricalV2SourceSnapshotSide, HistoricalV2StageArtifactKind, HistoricalV2StageResult,
    HistoricalV2StoredSlotStage, HistoricalV2TerminalExclusionReason,
    HistoricalV2TestMaterialization, HistoricalV2TestMaterializationBinding,
    HistoricalV2TestMaterializationExclusion, HistoricalV2TestMaterializationExclusionEvidence,
    HistoricalV2TestMaterializationExclusionReason, HistoricalV2TestMaterializationSide,
    HistoricalV2TestMaterializedRoots, HistoricalV2TestPatchRejectionEvidence,
    HistoricalV2TestRecipe, HistoricalV2TestRecipeExclusionReason, HistoricalV2TestRecipeOutcome,
    HistoricalV2UnresolvedChangedMethod, INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_CANDIDATE_FRAME_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_EVIDENCE_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_FRAME_RANK_SCHEMA_VERSION, INTENTIONAL_BOUNDARY_FRAME_TASK_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_INVENTORY_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_LABEL_RESOLUTION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_LABEL_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_MANIFEST_BINDING_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_MANIFEST_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_BINDING_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_PROTOCOL_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SLOT_SELECTION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SOURCE_BUNDLE_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION, IntentionalBoundaryAstCensus,
    IntentionalBoundaryAstFact, IntentionalBoundaryAstMethod, IntentionalBoundaryAstMethodStatus,
    IntentionalBoundaryAstProofKind, IntentionalBoundaryBehaviorCandidate,
    IntentionalBoundaryBehaviorCandidateStatus, IntentionalBoundaryBehaviorCensus,
    IntentionalBoundaryBehaviorExecution, IntentionalBoundaryBehaviorProvider,
    IntentionalBoundaryBehaviorSelector, IntentionalBoundaryBehaviorTestProofKind,
    IntentionalBoundaryBehaviorUnresolvedReason, IntentionalBoundaryBehaviorWitness,
    IntentionalBoundaryBehaviorWitnessOutcome, IntentionalBoundaryCandidate,
    IntentionalBoundaryCandidateCensus, IntentionalBoundaryCandidateFrame,
    IntentionalBoundaryCompilerProofKind, IntentionalBoundaryEvidenceAtom,
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceProof,
    IntentionalBoundaryFinalBasis, IntentionalBoundaryFinalLabel,
    IntentionalBoundaryFinalLabelBundle, IntentionalBoundaryFinalOutcome,
    IntentionalBoundaryFrameExclusionReason, IntentionalBoundaryFrameRankOutcome,
    IntentionalBoundaryFrameRankRecord, IntentionalBoundaryFrameTask,
    IntentionalBoundaryGeneratorProofKind, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryLabelAudit, IntentionalBoundaryLabelAuditItem,
    IntentionalBoundaryLabelDecision, IntentionalBoundaryLabelResolver,
    IntentionalBoundaryLabelReviewer, IntentionalBoundaryLabelStatus, IntentionalBoundaryLabelTask,
    IntentionalBoundaryLabelWorksheet, IntentionalBoundaryManifestBinding,
    IntentionalBoundaryManifestBindingCensus, IntentionalBoundaryManifestBindingOutcome,
    IntentionalBoundaryManifestBindingUnresolvedReason, IntentionalBoundaryManifestBoundSubject,
    IntentionalBoundaryManifestCensus, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestDocument,
    IntentionalBoundaryManifestNonMethodReason, IntentionalBoundaryManifestProofKind,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundaryProjectModelBinding,
    IntentionalBoundaryProjectModelBindingCensus, IntentionalBoundaryProjectModelBindingOutcome,
    IntentionalBoundaryProjectModelBindingUnresolvedReason,
    IntentionalBoundaryProjectModelBoundSubject, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelNonBoundaryReason,
    IntentionalBoundaryProjectModelNonMethodReason, IntentionalBoundaryProjectModelProvider,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundaryProjectModelTargetStatus,
    IntentionalBoundaryProjectModelUnresolvedReason, IntentionalBoundaryProtocol,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundaryRepositoryTask,
    IntentionalBoundaryResolutionItem, IntentionalBoundaryResolutionWorksheet,
    IntentionalBoundaryReviewerLabel, IntentionalBoundarySemanticCallFacts,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticDispatch,
    IntentionalBoundarySemanticImportFacts, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOccurrenceFacts, IntentionalBoundarySemanticOccurrenceRole,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticRelationshipFacts, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSurface,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticTestFacts, IntentionalBoundarySemanticTestKind,
    IntentionalBoundarySemanticUnresolvedReason, IntentionalBoundarySemanticVisibility,
    IntentionalBoundarySlot, IntentionalBoundarySlotOutcome, IntentionalBoundarySlotSelection,
    IntentionalBoundarySourceArtifact, IntentionalBoundarySourceBundle,
    IntentionalBoundarySourceCensus, IntentionalBoundarySourceCitation,
    IntentionalBoundarySourceFile, IntentionalBoundarySourceMaterial,
    IntentionalBoundarySourceRepository, IntentionalBoundarySourceReviewItem,
    IntentionalBoundaryTrackedEntry, LABEL_RESOLUTION_SCHEMA_VERSION, LABEL_REVIEW_SCHEMA_VERSION,
    LabelAgreementStatus, LabelResolutionManifest, LabelResolver, LabelReviewAudit,
    LabelReviewProgress, LabelReviewWorksheet, LabelReviewer, MethodLabelAudit,
    MethodLabelDecision, MethodLabelReview, NON_BLIND_HISTORY_ASSESSMENT_PROTOCOL_SCHEMA_VERSION,
    NON_BLIND_HISTORY_ASSESSMENT_SCHEMA_VERSION, NON_BLIND_HISTORY_WORKSHEET_SCHEMA_VERSION,
    NON_BLIND_SOURCE_SEAL_SCHEMA_VERSION, NonBlindHistoryAssessment, NonBlindHistoryWorksheet,
    NonBlindSelectionPolicy, NonBlindSourceEntry, NonBlindSourceKind, NonBlindSourceSeal,
    ProvenanceArtifact, RankedHistoricalCommit, ReleaseBenchmarkCase, ReleaseBenchmarkMetrics,
    ResolvedLabelCase, ReviewerDisposition, ReviewerLabel, SOURCE_ASSESSMENT_CENSUS_CONTRACT,
    SOURCE_CENSUS_CONTRACT_VERSION, SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION,
    SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION,
    SOURCE_SAMPLING_CONTINUATION_POLICY_SCHEMA_VERSION, SOURCE_SAMPLING_POLICY_SCHEMA_VERSION,
    SOURCE_SEAL_SCHEMA_VERSION, SOURCE_SELECTION_AUDIT_SCHEMA_VERSION,
    SOURCE_SELECTION_COMPONENT_AUDIT_SCHEMA_VERSION,
    SOURCE_SELECTION_COMPOSITE_AUDIT_SCHEMA_VERSION,
    SOURCE_SELECTION_COMPOSITE_POLICY_SCHEMA_VERSION, SealedLicense, SealedMethod,
    SealedSourceSelectionComponent, SourceAssessmentEvidence, SourceAssessmentEvidenceKind,
    SourceAssessmentFacts, SourceAssessmentSupportingEvidence, SourceCandidateAssessment,
    SourceExclusionReason, SourceFrameCollectionManifest, SourceFrameCollectionPolicy,
    SourceFramePageCommitment, SourceFrameRawPage, SourceRepositoryDraft, SourceSamplingPolicy,
    SourceSelectionAudit, SourceSelectionComponentAudit, SourceSelectionComponentCommitment,
    SourceSelectionCompositeAudit, SourceSelectionCompositePolicy, SourceSelectionContinuation,
    SourceSelectionDisposition, SourceSelectionDraft, SourceSelectionWorksheet, SourceSnapshot,
    ValidatedHistoricalV2Protocol, ValidatedIntentionalBoundaryProtocol,
    append_historical_v2_slot_stage_checkpoint, assess_non_blind_history,
    assess_non_blind_history_slice, assess_source_selection,
    audit_intentional_boundary_label_reviews, audit_label_reviews, audit_source_selection,
    audit_source_selection_component, bind_historical_v2_assessment_identity,
    bind_intentional_boundary_manifests, bind_intentional_boundary_project_models,
    build_blind_case_bundle, capture_historical_diffs, census_historical_source_delta,
    census_historical_v2_semantics, census_historical_v2_semantics_typed,
    census_historical_v2_sources, census_historical_v2_sources_typed,
    census_intentional_boundary_behavior_tests, census_intentional_boundary_cargo_project_models,
    census_intentional_boundary_go_ast, census_intentional_boundary_go_project_models,
    census_intentional_boundary_gradle_project_models, census_intentional_boundary_javascript_ast,
    census_intentional_boundary_kotlin_ast, census_intentional_boundary_manifests,
    census_intentional_boundary_python_ast, census_intentional_boundary_repository,
    census_intentional_boundary_rust_ast, census_intentional_boundary_semantics,
    census_intentional_boundary_typescript_ast, checkpoint_historical_v2_assessment_identity,
    checkpoint_historical_v2_identical_test_execution, checkpoint_historical_v2_materialization,
    checkpoint_historical_v2_materialization_exclusion, checkpoint_historical_v2_payload,
    checkpoint_historical_v2_qualification, checkpoint_historical_v2_ready_for_review,
    checkpoint_historical_v2_semantic_census, checkpoint_historical_v2_semantic_census_exclusion,
    checkpoint_historical_v2_source_census, checkpoint_historical_v2_source_census_exclusion,
    checkpoint_historical_v2_test_materialization,
    checkpoint_historical_v2_test_materialization_exclusion, checkpoint_historical_v2_test_recipe,
    classify_historical_v2_patch, clone_complete_historical_repository, collect_source_frame,
    combine_source_selections, commit_intentional_boundary_frame_rank,
    complete_intentional_boundary_candidate_frame, complete_non_blind_history_assessment,
    compose_intentional_boundary_behavior_evidence,
    compose_intentional_boundary_project_model_evidence, create_composite_source_seal,
    create_intentional_boundary_source_bundle, create_source_seal,
    derive_historical_v2_exclusion_manifest, derive_historical_v2_frame_record,
    discover_historical_test_recipe, evaluate_release, execute_historical_v2_identical_tests,
    extend_source_selection, extract_intentional_boundary_compiler_and_ast_evidence,
    extract_intentional_boundary_compiler_ast_and_manifest_evidence,
    extract_intentional_boundary_compiler_evidence, freeze_corpus, freeze_non_blind_source_seal,
    historical_diff_hunks, historical_v2_execution_harness, historical_v2_frame_sha256,
    historical_v2_rank_sha256, inspect_historical_git_repository, inspect_label_review_progress,
    inventory_intentional_boundary_repository, load_historical_v2_execution_checkpoint,
    load_intentional_boundary_frame_ranks, load_non_blind_history_checkpoints,
    materialize_historical_snapshots, materialize_historical_v2_repository,
    materialize_historical_v2_repository_typed, materialize_historical_v2_test_snapshots,
    materialize_historical_v2_test_snapshots_typed, parse_intentional_boundary_cargo_metadata,
    parse_intentional_boundary_go_list, parse_intentional_boundary_gradle_tooling_model,
    prepare_historical_v2_identical_test_plan, prepare_historical_v2_test_recipe,
    prepare_intentional_boundary_analyzed_rank, prepare_intentional_boundary_excluded_rank,
    prepare_intentional_boundary_frame_task, prepare_intentional_boundary_label_resolution,
    prepare_intentional_boundary_label_review, prepare_label_resolution, prepare_label_review,
    prepare_non_blind_history, prepare_non_blind_history_assessment, prepare_source_selection,
    prepare_source_selection_extension, qualify_historical_v2_assessment,
    qualify_intentional_boundary_candidates, rank_historical_commits,
    remove_historical_materialization, resolve_historical_v2_base_image,
    resolve_intentional_boundary_labels, run_historical_test,
    run_historical_v2_identical_tests_checkpointed, run_historical_v2_slot,
    run_historical_v2_slot_slice, select_historical_v2_slots, select_intentional_boundary_slots,
    source_selection_draft, validate_actual_cost_receipt, validate_frozen_corpus,
    validate_historical_v2_assessment_identity,
    validate_historical_v2_assessment_identity_commitment,
    validate_historical_v2_exclusion_manifest, validate_historical_v2_execution_harness,
    validate_historical_v2_execution_harness_repository, validate_historical_v2_frame_commitment,
    validate_historical_v2_identical_test_execution, validate_historical_v2_identical_test_plan,
    validate_historical_v2_materialization, validate_historical_v2_materialization_exclusion,
    validate_historical_v2_protocol, validate_historical_v2_qualification,
    validate_historical_v2_qualification_commitment,
    validate_historical_v2_selected_payloads_commitment, validate_historical_v2_semantic_census,
    validate_historical_v2_semantic_census_commitment,
    validate_historical_v2_semantic_census_exclusion, validate_historical_v2_slot_selection,
    validate_historical_v2_slot_stage_history, validate_historical_v2_source_census,
    validate_historical_v2_source_census_exclusion, validate_historical_v2_test_materialization,
    validate_historical_v2_test_materialization_exclusion, validate_historical_v2_test_recipe,
    validate_intentional_boundary_behavior_census_commitment,
    validate_intentional_boundary_behavior_evidence,
    validate_intentional_boundary_candidate_census, validate_intentional_boundary_candidate_frame,
    validate_intentional_boundary_cargo_metadata,
    validate_intentional_boundary_compiler_and_ast_evidence,
    validate_intentional_boundary_compiler_ast_and_manifest_evidence,
    validate_intentional_boundary_compiler_evidence, validate_intentional_boundary_final_labels,
    validate_intentional_boundary_frame_task, validate_intentional_boundary_go_ast_census,
    validate_intentional_boundary_go_list, validate_intentional_boundary_gradle_tooling_model,
    validate_intentional_boundary_javascript_ast_census,
    validate_intentional_boundary_kotlin_ast_census, validate_intentional_boundary_label_audit,
    validate_intentional_boundary_label_resolution, validate_intentional_boundary_label_review,
    validate_intentional_boundary_manifest_bindings, validate_intentional_boundary_manifest_census,
    validate_intentional_boundary_project_model_bindings,
    validate_intentional_boundary_project_model_census_commitment,
    validate_intentional_boundary_project_model_evidence, validate_intentional_boundary_protocol,
    validate_intentional_boundary_python_ast_census,
    validate_intentional_boundary_repository_inventory,
    validate_intentional_boundary_rust_ast_census, validate_intentional_boundary_semantic_census,
    validate_intentional_boundary_slot_selection, validate_intentional_boundary_source_bundle,
    validate_intentional_boundary_source_bundle_artifacts,
    validate_intentional_boundary_source_census,
    validate_intentional_boundary_typescript_ast_census, validate_label_review,
    validate_label_review_audit, validate_non_blind_history_assessment,
    validate_non_blind_history_worksheet, validate_non_blind_source_seal,
    validate_source_frame_manifest, validate_source_seal, validate_source_selection_audit,
    validate_source_selection_component_against_frame, validate_source_selection_component_audit,
    validate_source_selection_composite_audit, validate_source_selection_worksheet,
    write_derived_historical_v2_exclusion_manifest, write_historical_v2_slot_selection,
    write_non_blind_history_checkpoint,
};

#[cfg(feature = "sniffbench-frame")]
pub use release::{
    build_historical_v2_frame, extract_historical_v2_selected_payloads,
    validate_historical_v2_frame_sources, validate_historical_v2_selected_payloads,
    visit_historical_v2_projected_shard, write_historical_v2_frame,
    write_historical_v2_selected_payloads,
};

/// One labeled unit in a SniffBench corpus. The label is hidden from the
/// analyzer during a run and is used only after predictions are collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub case_id: String,
    pub language: String,
    pub expected_tier: FindingTier,
    pub expected_pattern: String,
    #[serde(default)]
    pub intentional_boundary: bool,
}

/// The normalized prediction recorded for one benchmark unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkPrediction {
    pub case_id: String,
    pub tier: FindingTier,
    pub pattern: String,
    pub evidence_valid: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LanguageMetrics {
    pub case_count: usize,
    pub expected_slop: usize,
    pub predicted_slop: usize,
    pub slop_true_positives: usize,
    pub expected_findings: usize,
    pub predicted_findings: usize,
    pub combined_true_positives: usize,
    pub false_positives: usize,
    pub evidence_valid_findings: usize,
    pub pattern_opportunities: usize,
    pub pattern_true_positives: usize,
    pub slop_precision: f64,
    pub slop_recall: f64,
    pub combined_precision: f64,
    pub combined_recall: f64,
    pub false_positive_rate: f64,
    pub intentional_boundary_cases: usize,
    pub intentional_boundary_false_positives: usize,
    pub intentional_boundary_false_positive_rate: f64,
    pub evidence_validity: f64,
    pub pattern_accuracy: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    pub case_count: usize,
    pub expected_slop: usize,
    pub predicted_slop: usize,
    pub slop_true_positives: usize,
    pub expected_findings: usize,
    pub predicted_findings: usize,
    pub combined_true_positives: usize,
    pub false_positives: usize,
    pub evidence_valid_findings: usize,
    pub pattern_opportunities: usize,
    pub pattern_true_positives: usize,
    pub slop_precision: f64,
    pub slop_recall: f64,
    pub combined_precision: f64,
    pub combined_recall: f64,
    pub false_positive_rate: f64,
    pub intentional_boundary_cases: usize,
    pub intentional_boundary_false_positives: usize,
    pub intentional_boundary_false_positive_rate: f64,
    pub evidence_validity: f64,
    pub pattern_accuracy: f64,
    pub by_language: BTreeMap<String, LanguageMetrics>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepeatabilityMetrics {
    pub run_count: usize,
    pub case_count: usize,
    pub stable_cases: usize,
    pub verdict_repeatability: f64,
}

impl BenchmarkMetrics {
    /// Return every failed release threshold instead of hiding the first one.
    pub fn release_gate_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        require_at_least(&mut errors, "Slop precision", self.slop_precision, 0.95);
        require_at_least(
            &mut errors,
            "combined Slop plus Kinda Slop precision",
            self.combined_precision,
            0.85,
        );
        require_at_least(
            &mut errors,
            "combined Slop plus Kinda Slop recall",
            self.combined_recall,
            0.80,
        );
        require_at_least(
            &mut errors,
            "evidence validity",
            self.evidence_validity,
            1.0,
        );
        if self.intentional_boundary_false_positive_rate > 0.02 {
            errors.push(format!(
                "intentional-boundary false-positive rate {:.2}% exceeds 2.00%",
                self.intentional_boundary_false_positive_rate * 100.0
            ));
        }
        for (language, metrics) in &self.by_language {
            if metrics.expected_slop == 0 && metrics.predicted_slop == 0 {
                continue;
            }
            require_at_least(
                &mut errors,
                &format!("{language} Slop precision"),
                metrics.slop_precision,
                0.90,
            );
            require_at_least(
                &mut errors,
                &format!("{language} Slop recall"),
                metrics.slop_recall,
                0.70,
            );
        }
        errors
    }

    pub fn assert_release_gate(&self) -> Result<(), String> {
        let errors = self.release_gate_errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

/// Evaluate a complete prediction ledger. Missing, duplicate, and invented
/// IDs are errors because partial coverage must never look like a benchmark.
pub fn evaluate(
    cases: &[BenchmarkCase],
    predictions: &[BenchmarkPrediction],
) -> Result<BenchmarkMetrics, String> {
    let expected = unique_case_map(cases)?;
    let actual = unique_prediction_map(predictions, &expected)?;
    if actual.len() != expected.len() {
        let missing = expected
            .keys()
            .filter(|case_id| !actual.contains_key(*case_id))
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "benchmark prediction ledger omitted case IDs: {}",
            missing.join(", ")
        ));
    }

    let mut metrics = BenchmarkMetrics {
        case_count: cases.len(),
        ..BenchmarkMetrics::default()
    };
    let mut by_language = BTreeMap::<String, LanguageAccumulator>::new();
    for case in cases {
        let prediction = actual
            .get(&case.case_id)
            .expect("complete prediction map was validated above");
        let language = by_language.entry(case.language.clone()).or_default();
        language.observe(
            case.expected_tier,
            &case.expected_pattern,
            case.intentional_boundary,
            prediction,
        );
        observe_global(
            &mut metrics,
            case.expected_tier,
            &case.expected_pattern,
            case.intentional_boundary,
            prediction,
        );
    }
    metrics.by_language = by_language
        .into_iter()
        .map(|(language, accumulator)| (language, accumulator.finish()))
        .collect();
    finalize_metrics(&mut metrics);
    Ok(metrics)
}

/// Compare the verdict and typed mechanism across complete repeated runs.
pub fn measure_repeatability(
    runs: &[Vec<BenchmarkPrediction>],
) -> Result<RepeatabilityMetrics, String> {
    if runs.len() < 2 {
        return Err("repeatability requires at least two complete runs".to_string());
    }
    let run_maps = runs
        .iter()
        .map(|run| prediction_identity_map(run))
        .collect::<Result<Vec<_>, _>>()?;
    let baseline = &run_maps[0];
    let case_count = baseline.len();
    for (index, predictions) in run_maps.iter().enumerate().skip(1) {
        if predictions.keys().collect::<HashSet<_>>() != baseline.keys().collect::<HashSet<_>>() {
            return Err(format!(
                "repeatability run {} does not contain the same complete case ledger",
                index + 1
            ));
        }
    }
    let mut stable_cases = 0;
    for case_id in baseline.keys() {
        let stable = run_maps
            .iter()
            .skip(1)
            .all(|predictions| predictions.get(case_id) == baseline.get(case_id));
        if stable {
            stable_cases += 1;
        }
    }
    Ok(RepeatabilityMetrics {
        run_count: runs.len(),
        case_count,
        stable_cases,
        verdict_repeatability: ratio(stable_cases, case_count),
    })
}

#[derive(Debug, Clone, Default)]
struct LanguageAccumulator {
    case_count: usize,
    expected_slop: usize,
    predicted_slop: usize,
    slop_true_positives: usize,
    expected_findings: usize,
    predicted_findings: usize,
    combined_true_positives: usize,
    false_positives: usize,
    intentional_boundary_cases: usize,
    intentional_boundary_false_positives: usize,
    evidence_valid_findings: usize,
    pattern_opportunities: usize,
    pattern_true_positives: usize,
}

impl LanguageAccumulator {
    fn observe(
        &mut self,
        expected: FindingTier,
        expected_pattern: &str,
        intentional_boundary: bool,
        prediction: &BenchmarkPrediction,
    ) {
        self.case_count += 1;
        observe_counts(
            self,
            expected,
            intentional_boundary,
            prediction.tier,
            prediction.evidence_valid,
        );
        observe_pattern(self, expected, expected_pattern, prediction);
    }

    fn finish(self) -> LanguageMetrics {
        LanguageMetrics {
            case_count: self.case_count,
            expected_slop: self.expected_slop,
            predicted_slop: self.predicted_slop,
            slop_true_positives: self.slop_true_positives,
            expected_findings: self.expected_findings,
            predicted_findings: self.predicted_findings,
            combined_true_positives: self.combined_true_positives,
            false_positives: self.false_positives,
            intentional_boundary_cases: self.intentional_boundary_cases,
            intentional_boundary_false_positives: self.intentional_boundary_false_positives,
            intentional_boundary_false_positive_rate: ratio_or_zero(
                self.intentional_boundary_false_positives,
                self.intentional_boundary_cases,
            ),
            evidence_valid_findings: self.evidence_valid_findings,
            pattern_opportunities: self.pattern_opportunities,
            pattern_true_positives: self.pattern_true_positives,
            slop_precision: ratio(self.slop_true_positives, self.predicted_slop),
            slop_recall: ratio(self.slop_true_positives, self.expected_slop),
            combined_precision: ratio(self.combined_true_positives, self.predicted_findings),
            combined_recall: ratio(self.combined_true_positives, self.expected_findings),
            false_positive_rate: ratio_or_zero(
                self.false_positives,
                self.case_count.saturating_sub(self.expected_findings),
            ),
            evidence_validity: ratio(self.evidence_valid_findings, self.predicted_findings),
            pattern_accuracy: ratio(self.pattern_true_positives, self.pattern_opportunities),
        }
    }
}

fn observe_global(
    metrics: &mut BenchmarkMetrics,
    expected: FindingTier,
    expected_pattern: &str,
    intentional_boundary: bool,
    prediction: &BenchmarkPrediction,
) {
    observe_counts(
        metrics,
        expected,
        intentional_boundary,
        prediction.tier,
        prediction.evidence_valid,
    );
    observe_pattern(metrics, expected, expected_pattern, prediction);
}

fn observe_pattern<T: PatternFields>(
    sink: &mut T,
    expected: FindingTier,
    expected_pattern: &str,
    prediction: &BenchmarkPrediction,
) {
    if is_finding(expected) && is_finding(prediction.tier) {
        *sink.pattern_opportunities_mut() += 1;
        if expected_pattern == prediction.pattern {
            *sink.pattern_true_positives_mut() += 1;
        }
    }
}

fn observe_counts<T: CountFields>(
    sink: &mut T,
    expected: FindingTier,
    intentional_boundary: bool,
    predicted: FindingTier,
    evidence_valid: bool,
) {
    if intentional_boundary {
        *sink.intentional_boundary_cases_mut() += 1;
        if !is_finding(expected) && is_finding(predicted) {
            *sink.intentional_boundary_false_positives_mut() += 1;
        }
    }
    if expected == FindingTier::Slop {
        *sink.expected_slop_mut() += 1;
    }
    if predicted == FindingTier::Slop {
        *sink.predicted_slop_mut() += 1;
    }
    if expected == FindingTier::Slop && predicted == FindingTier::Slop {
        *sink.slop_true_positives_mut() += 1;
    }
    if is_finding(expected) {
        *sink.expected_findings_mut() += 1;
    }
    if is_finding(predicted) {
        *sink.predicted_findings_mut() += 1;
        if evidence_valid {
            *sink.evidence_valid_findings_mut() += 1;
        }
    }
    if is_finding(expected) && is_finding(predicted) {
        *sink.combined_true_positives_mut() += 1;
    }
    if !is_finding(expected) && is_finding(predicted) {
        *sink.false_positives_mut() += 1;
    }
}

trait CountFields {
    fn expected_slop_mut(&mut self) -> &mut usize;
    fn predicted_slop_mut(&mut self) -> &mut usize;
    fn slop_true_positives_mut(&mut self) -> &mut usize;
    fn expected_findings_mut(&mut self) -> &mut usize;
    fn predicted_findings_mut(&mut self) -> &mut usize;
    fn combined_true_positives_mut(&mut self) -> &mut usize;
    fn false_positives_mut(&mut self) -> &mut usize;
    fn intentional_boundary_cases_mut(&mut self) -> &mut usize;
    fn intentional_boundary_false_positives_mut(&mut self) -> &mut usize;
    fn evidence_valid_findings_mut(&mut self) -> &mut usize;
}

trait PatternFields {
    fn pattern_opportunities_mut(&mut self) -> &mut usize;
    fn pattern_true_positives_mut(&mut self) -> &mut usize;
}

macro_rules! impl_count_fields {
    ($type:ty) => {
        impl CountFields for $type {
            fn expected_slop_mut(&mut self) -> &mut usize {
                &mut self.expected_slop
            }
            fn predicted_slop_mut(&mut self) -> &mut usize {
                &mut self.predicted_slop
            }
            fn slop_true_positives_mut(&mut self) -> &mut usize {
                &mut self.slop_true_positives
            }
            fn expected_findings_mut(&mut self) -> &mut usize {
                &mut self.expected_findings
            }
            fn predicted_findings_mut(&mut self) -> &mut usize {
                &mut self.predicted_findings
            }
            fn combined_true_positives_mut(&mut self) -> &mut usize {
                &mut self.combined_true_positives
            }
            fn false_positives_mut(&mut self) -> &mut usize {
                &mut self.false_positives
            }
            fn intentional_boundary_cases_mut(&mut self) -> &mut usize {
                &mut self.intentional_boundary_cases
            }
            fn intentional_boundary_false_positives_mut(&mut self) -> &mut usize {
                &mut self.intentional_boundary_false_positives
            }
            fn evidence_valid_findings_mut(&mut self) -> &mut usize {
                &mut self.evidence_valid_findings
            }
        }

        impl PatternFields for $type {
            fn pattern_opportunities_mut(&mut self) -> &mut usize {
                &mut self.pattern_opportunities
            }
            fn pattern_true_positives_mut(&mut self) -> &mut usize {
                &mut self.pattern_true_positives
            }
        }
    };
}

impl_count_fields!(BenchmarkMetrics);
impl_count_fields!(LanguageAccumulator);

fn finalize_metrics(metrics: &mut BenchmarkMetrics) {
    metrics.slop_precision = ratio(metrics.slop_true_positives, metrics.predicted_slop);
    metrics.slop_recall = ratio(metrics.slop_true_positives, metrics.expected_slop);
    metrics.combined_precision = ratio(metrics.combined_true_positives, metrics.predicted_findings);
    metrics.combined_recall = ratio(metrics.combined_true_positives, metrics.expected_findings);
    metrics.false_positive_rate = ratio_or_zero(
        metrics.false_positives,
        metrics.case_count.saturating_sub(metrics.expected_findings),
    );
    metrics.intentional_boundary_false_positive_rate = ratio_or_zero(
        metrics.intentional_boundary_false_positives,
        metrics.intentional_boundary_cases,
    );
    metrics.evidence_validity = ratio(metrics.evidence_valid_findings, metrics.predicted_findings);
    metrics.pattern_accuracy = ratio(
        metrics.pattern_true_positives,
        metrics.pattern_opportunities,
    );
}

fn require_at_least(errors: &mut Vec<String>, label: &str, value: f64, minimum: f64) {
    if value < minimum {
        errors.push(format!(
            "{label} {:.2}% is below {:.2}%",
            value * 100.0,
            minimum * 100.0
        ));
    }
}

fn is_finding(tier: FindingTier) -> bool {
    matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn ratio_or_zero(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn unique_case_map(cases: &[BenchmarkCase]) -> Result<HashMap<String, BenchmarkCase>, String> {
    let mut map = HashMap::with_capacity(cases.len());
    for case in cases {
        if case.case_id.trim().is_empty() || case.language.trim().is_empty() {
            return Err("benchmark cases require non-empty case_id and language".to_string());
        }
        let pattern = SlopPattern::parse(&case.expected_pattern).ok_or_else(|| {
            format!(
                "benchmark case {} has an unknown typed pattern {}",
                case.case_id, case.expected_pattern
            )
        })?;
        if !pattern.is_valid_for(case.expected_tier) {
            return Err(format!(
                "benchmark case {} uses pattern {} with tier {}",
                case.case_id,
                pattern,
                case.expected_tier.label()
            ));
        }
        if map.insert(case.case_id.clone(), case.clone()).is_some() {
            return Err(format!("benchmark corpus repeats case {}", case.case_id));
        }
    }
    Ok(map)
}

fn unique_prediction_map(
    predictions: &[BenchmarkPrediction],
    expected: &HashMap<String, BenchmarkCase>,
) -> Result<HashMap<String, BenchmarkPrediction>, String> {
    let mut map = HashMap::with_capacity(predictions.len());
    for prediction in predictions {
        if !expected.contains_key(&prediction.case_id) {
            return Err(format!(
                "benchmark prediction references unknown case {}",
                prediction.case_id
            ));
        }
        let pattern = SlopPattern::parse(&prediction.pattern).ok_or_else(|| {
            format!(
                "benchmark prediction {} has an unknown typed pattern {}",
                prediction.case_id, prediction.pattern
            )
        })?;
        if !pattern.is_valid_for(prediction.tier) {
            return Err(format!(
                "benchmark prediction {} uses pattern {} with tier {}",
                prediction.case_id,
                pattern,
                prediction.tier.label()
            ));
        }
        if map
            .insert(prediction.case_id.clone(), prediction.clone())
            .is_some()
        {
            return Err(format!(
                "benchmark predictions repeat case {}",
                prediction.case_id
            ));
        }
    }
    Ok(map)
}

fn prediction_identity_map(
    predictions: &[BenchmarkPrediction],
) -> Result<HashMap<String, (FindingTier, String)>, String> {
    let mut map = HashMap::with_capacity(predictions.len());
    for prediction in predictions {
        if map
            .insert(
                prediction.case_id.clone(),
                (prediction.tier, prediction.pattern.clone()),
            )
            .is_some()
        {
            return Err(format!(
                "repeatability run repeats case {}",
                prediction.case_id
            ));
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::{BenchmarkCase, BenchmarkPrediction, evaluate, measure_repeatability};
    use crate::types::FindingTier;

    fn case(case_id: &str, language: &str, tier: FindingTier) -> BenchmarkCase {
        BenchmarkCase {
            case_id: case_id.to_string(),
            language: language.to_string(),
            expected_tier: tier,
            expected_pattern: if super::is_finding(tier) {
                "ceremonial_logic".to_string()
            } else {
                "none".to_string()
            },
            intentional_boundary: false,
        }
    }

    fn prediction(case_id: &str, tier: FindingTier) -> BenchmarkPrediction {
        BenchmarkPrediction {
            case_id: case_id.to_string(),
            tier,
            pattern: if super::is_finding(tier) {
                "ceremonial_logic".to_string()
            } else {
                "none".to_string()
            },
            evidence_valid: super::is_finding(tier),
        }
    }

    #[test]
    fn benchmark_metrics_distinguish_slop_and_kinda_slop() {
        let cases = vec![
            case("slop", "python", FindingTier::Slop),
            case("kinda", "python", FindingTier::KindaSlop),
            case("clean", "python", FindingTier::Clean),
        ];
        let predictions = vec![
            prediction("slop", FindingTier::Slop),
            prediction("kinda", FindingTier::Slop),
            prediction("clean", FindingTier::Clean),
        ];

        let metrics = evaluate(&cases, &predictions).unwrap();

        assert_eq!(metrics.slop_true_positives, 1);
        assert_eq!(metrics.combined_true_positives, 2);
        assert_eq!(metrics.false_positives, 0);
        assert_eq!(metrics.by_language["python"].case_count, 3);
        assert_eq!(metrics.combined_recall, 1.0);
        assert_eq!(metrics.pattern_accuracy, 1.0);
        assert!(metrics.slop_precision < 1.0);
    }

    #[test]
    fn intentional_boundary_false_positive_rate_uses_explicit_labels() {
        let mut boundary = case("boundary", "python", FindingTier::Clean);
        boundary.intentional_boundary = true;
        let cases = vec![boundary, case("ordinary", "python", FindingTier::Clean)];
        let predictions = vec![
            prediction("boundary", FindingTier::Slop),
            prediction("ordinary", FindingTier::Slop),
        ];

        let metrics = evaluate(&cases, &predictions).unwrap();

        assert_eq!(metrics.intentional_boundary_cases, 1);
        assert_eq!(metrics.intentional_boundary_false_positives, 1);
        assert_eq!(metrics.intentional_boundary_false_positive_rate, 1.0);
        assert!(
            metrics
                .release_gate_errors()
                .iter()
                .any(|error| error.contains("intentional-boundary"))
        );
    }

    #[test]
    fn benchmark_ledger_rejects_missing_unknown_and_duplicate_units() {
        let cases = vec![case("a", "python", FindingTier::Clean)];
        assert!(evaluate(&cases, &[]).unwrap_err().contains("omitted"));
        assert!(
            evaluate(&cases, &[prediction("unknown", FindingTier::Clean)])
                .unwrap_err()
                .contains("unknown case")
        );
        assert!(
            evaluate(
                &cases,
                &[
                    prediction("a", FindingTier::Clean),
                    prediction("a", FindingTier::Clean)
                ]
            )
            .unwrap_err()
            .contains("repeat")
        );
    }

    #[test]
    fn repeatability_requires_complete_matching_runs() {
        let first = vec![prediction("a", FindingTier::Slop)];
        let second = vec![prediction("a", FindingTier::Slop)];
        let third = vec![prediction("a", FindingTier::Clean)];

        let metrics = measure_repeatability(&[first, second, third]).unwrap();

        assert_eq!(metrics.run_count, 3);
        assert_eq!(metrics.case_count, 1);
        assert_eq!(metrics.stable_cases, 0);
        assert_eq!(metrics.verdict_repeatability, 0.0);

        let error = measure_repeatability(&[vec![prediction("a", FindingTier::Clean)], vec![]])
            .unwrap_err();
        assert!(error.contains("complete case ledger"));
    }

    #[test]
    fn benchmark_predictions_must_use_the_typed_ontology() {
        let cases = vec![case("a", "python", FindingTier::Clean)];
        let mut prediction = prediction("a", FindingTier::Clean);
        prediction.pattern = "ceremonial_logic".to_string();

        let error = evaluate(&cases, &[prediction]).unwrap_err();

        assert!(error.contains("uses pattern"));
    }
}
