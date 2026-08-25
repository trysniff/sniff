use super::history_v2_slot_store_support::validate_slot_path;
use super::{
    HistoricalV2AssessmentIdentity, HistoricalV2AssessmentIdentityInputs,
    HistoricalV2ExecutionError, HistoricalV2ExecutionErrorKind, HistoricalV2IdenticalTestPlan,
    HistoricalV2Materialization, HistoricalV2MaterializationExclusion,
    HistoricalV2MaterializedRoots, HistoricalV2PayloadStageInputs, HistoricalV2PreparedStage,
    HistoricalV2Qualification, HistoricalV2SemanticCensus, HistoricalV2SemanticCensusExclusion,
    HistoricalV2SlotStage, HistoricalV2SlotStageContext, HistoricalV2SlotStageError,
    HistoricalV2SlotStageOutcome, HistoricalV2SourceCensus, HistoricalV2SourceCensusExclusion,
    HistoricalV2StageArtifactKind, HistoricalV2TerminalExclusionReason,
    HistoricalV2TestMaterialization, HistoricalV2TestMaterializationBinding,
    HistoricalV2TestMaterializationExclusion, HistoricalV2TestMaterializedRoots,
    HistoricalV2TestRecipe,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn canonical_work_root(
    work_root: &Path,
    language: &str,
    slot_number: usize,
) -> Result<PathBuf, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Payload;
    validate_slot_path(language, slot_number).map_err(|detail| invalid(stage, detail))?;
    if !work_root.is_absolute() {
        return Err(invalid(stage, "historical-v2 work root must be absolute"));
    }
    fs::create_dir_all(work_root).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to create historical-v2 work root: {error}"),
        )
    })?;
    let work_root = fs::canonicalize(work_root).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to resolve historical-v2 work root: {error}"),
        )
    })?;
    let language_root = work_root.join(language);
    fs::create_dir_all(&language_root).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to create historical-v2 language work root: {error}"),
        )
    })?;
    let language_root = fs::canonicalize(&language_root).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to resolve historical-v2 language work root: {error}"),
        )
    })?;
    if language_root.parent() != Some(work_root.as_path()) {
        return Err(invalid(
            stage,
            "historical-v2 language work root escaped its parent",
        ));
    }
    Ok(work_root)
}

pub(super) fn remove_interrupted_materialization(
    work_root: &Path,
    language: &str,
    slot_number: usize,
) -> Result<(), HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Materialization;
    validate_slot_path(language, slot_number).map_err(|detail| invalid(stage, detail))?;
    let language_root = fs::canonicalize(work_root.join(language)).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to resolve materialization parent: {error}"),
        )
    })?;
    if language_root.parent() != Some(work_root) {
        return Err(invalid(
            stage,
            "historical-v2 materialization parent escaped its work root",
        ));
    }
    let slot_root = language_root.join(format!("slot-{slot_number:04}"));
    if !slot_root.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&slot_root).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to inspect interrupted materialization: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            stage,
            "refusing to remove unsafe interrupted materialization",
        ));
    }
    let resolved = fs::canonicalize(&slot_root).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to resolve interrupted materialization: {error}"),
        )
    })?;
    if resolved.parent() != Some(language_root.as_path())
        || resolved.file_name() != slot_root.file_name()
    {
        return Err(invalid(
            stage,
            "refusing to remove unsafe interrupted materialization",
        ));
    }
    fs::remove_dir_all(&resolved).map_err(|error| {
        infrastructure(
            stage,
            format!("failed to remove interrupted materialization: {error}"),
        )
    })
}

pub(super) fn reconcile_terminal_slot_work(
    work_root: &Path,
    language: &str,
    slot_number: usize,
    disposition: &super::HistoricalV2SlotRunDisposition,
) -> Result<(), HistoricalV2SlotStageError> {
    if matches!(
        disposition,
        super::HistoricalV2SlotRunDisposition::Excluded { .. }
    ) {
        remove_interrupted_materialization(work_root, language, slot_number)?;
    }
    Ok(())
}

pub(super) fn require_operation_identity(
    context: HistoricalV2SlotStageContext<'_>,
    selection_sha256: &str,
    language: &str,
    slot_number: usize,
    canonical_repository: &str,
) -> Result<(), HistoricalV2SlotStageError> {
    if context.identity.selection_sha256 != selection_sha256
        || context.identity.language != language
        || context.identity.slot_number != slot_number
        || context.identity.canonical_repository != canonical_repository
    {
        Err(invalid(
            context.stage,
            "historical-v2 operation inputs crossed the runner identity",
        ))
    } else {
        Ok(())
    }
}

pub(super) struct AssessmentState {
    pub(super) materialization: HistoricalV2Materialization,
    pub(super) materialized_roots: HistoricalV2MaterializedRoots,
    pub(super) test_materialization: Option<HistoricalV2TestMaterialization>,
    pub(super) test_materialized_roots: Option<HistoricalV2TestMaterializedRoots>,
    pub(super) source_census: HistoricalV2SourceCensus,
    pub(super) semantic_census: HistoricalV2SemanticCensus,
}

impl AssessmentState {
    pub(super) fn inputs<'a>(
        &'a self,
        payload: &'a HistoricalV2PayloadStageInputs<'_>,
    ) -> HistoricalV2AssessmentIdentityInputs<'a> {
        HistoricalV2AssessmentIdentityInputs {
            protocol_bytes: payload.protocol_bytes,
            artifact_root: payload.artifact_root,
            frame: payload.frame,
            exclusions: payload.exclusions,
            selection: payload.selection,
            payloads: payload.payloads,
            language: payload.language,
            slot_number: payload.slot_number,
            materialization: &self.materialization,
            materialized_roots: &self.materialized_roots,
            test_materialization: self
                .test_materialization
                .as_ref()
                .zip(self.test_materialized_roots.as_ref())
                .map(|(artifact, roots)| HistoricalV2TestMaterializationBinding {
                    artifact,
                    roots,
                }),
            source_census: &self.source_census,
            semantic_census: &self.semantic_census,
        }
    }
}

pub(super) type ExecutionInputs = (
    AssessmentState,
    HistoricalV2AssessmentIdentity,
    HistoricalV2Qualification,
    HistoricalV2TestRecipe,
    HistoricalV2IdenticalTestPlan,
);

pub(super) fn artifact<T: DeserializeOwned>(
    context: HistoricalV2SlotStageContext<'_>,
    index: usize,
) -> Result<T, HistoricalV2SlotStageError> {
    let value = context
        .history
        .get(index)
        .and_then(|stored| stored.artifact.clone())
        .ok_or_else(|| {
            invalid(
                context.stage,
                "historical-v2 prerequisite artifact is missing",
            )
        })?;
    serde_json::from_value(value).map_err(|error| {
        invalid(
            context.stage,
            format!("invalid historical-v2 prerequisite artifact: {error}"),
        )
    })
}

pub(super) fn completed<T: Serialize>(
    kind: HistoricalV2StageArtifactKind,
    sha256: &str,
    artifact: &T,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    prepared(
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: kind,
            artifact_sha256: sha256.to_string(),
        },
        artifact,
        stage,
    )
}

pub(super) fn excluded<T: Serialize>(
    reason: HistoricalV2TerminalExclusionReason,
    kind: HistoricalV2StageArtifactKind,
    sha256: &str,
    artifact: &T,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    prepared(
        HistoricalV2SlotStageOutcome::Excluded {
            reason,
            artifact_kind: kind,
            artifact_sha256: sha256.to_string(),
        },
        artifact,
        stage,
    )
}

fn prepared<T: Serialize>(
    outcome: HistoricalV2SlotStageOutcome,
    artifact: &T,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    Ok(HistoricalV2PreparedStage {
        outcome,
        artifact: Some(serde_json::to_value(artifact).map_err(|error| {
            invalid(
                stage,
                format!("failed to serialize stage artifact: {error}"),
            )
        })?),
    })
}

pub(super) fn materialization_excluded(
    value: HistoricalV2MaterializationExclusion,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    excluded(
        HistoricalV2TerminalExclusionReason::Materialization(value.reason),
        HistoricalV2StageArtifactKind::MaterializationExclusion,
        &value.exclusion_sha256,
        &value,
        stage,
    )
}

pub(super) fn test_materialization_excluded(
    value: HistoricalV2TestMaterializationExclusion,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    excluded(
        HistoricalV2TerminalExclusionReason::TestMaterialization(value.reason),
        HistoricalV2StageArtifactKind::TestMaterializationExclusion,
        &value.exclusion_sha256,
        &value,
        stage,
    )
}

pub(super) fn source_census_excluded(
    value: HistoricalV2SourceCensusExclusion,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    excluded(
        HistoricalV2TerminalExclusionReason::SourceCensus(value.reasons.clone()),
        HistoricalV2StageArtifactKind::SourceCensusExclusion,
        &value.exclusion_sha256,
        &value,
        stage,
    )
}

pub(super) fn semantic_census_excluded(
    value: HistoricalV2SemanticCensusExclusion,
    stage: HistoricalV2SlotStage,
) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
    excluded(
        HistoricalV2TerminalExclusionReason::SemanticCensus(value.reasons.clone()),
        HistoricalV2StageArtifactKind::SemanticCensusExclusion,
        &value.exclusion_sha256,
        &value,
        stage,
    )
}

pub(super) fn slot_execution_error(
    error: HistoricalV2ExecutionError,
) -> HistoricalV2SlotStageError {
    match error.kind {
        HistoricalV2ExecutionErrorKind::InvalidInput => {
            invalid(HistoricalV2SlotStage::IdenticalTests, error.detail)
        }
        HistoricalV2ExecutionErrorKind::InfrastructureUnavailable => {
            HistoricalV2SlotStageError::unavailable(
                HistoricalV2SlotStage::IdenticalTests,
                error.detail,
            )
        }
        HistoricalV2ExecutionErrorKind::InfrastructureFailed => {
            infrastructure(HistoricalV2SlotStage::IdenticalTests, error.detail)
        }
    }
}

pub(super) fn invalid(
    stage: HistoricalV2SlotStage,
    detail: impl Into<String>,
) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError::invalid(stage, detail)
}

pub(super) fn infrastructure(
    stage: HistoricalV2SlotStage,
    detail: impl Into<String>,
) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError::infrastructure(stage, detail)
}

#[cfg(test)]
#[path = "benchmark_history_v2_slot_operations_support_tests.rs"]
mod tests;
