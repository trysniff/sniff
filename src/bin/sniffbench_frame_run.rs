use super::invalid_data;
use clap::{Args, ValueEnum};
use serde::de::DeserializeOwned;
use sniff::benchmark::{
    DockerHistoricalV2TestExecutor, HistoricalV2ExclusionManifest, HistoricalV2Frame,
    HistoricalV2PublicSurfaceReplayInputs, HistoricalV2SelectedPayloads,
    HistoricalV2SelectedSlotStateInspection, HistoricalV2SelectedSlotStateInspectionInputs,
    HistoricalV2SelectedSlotSweepInputs, HistoricalV2SelectedSlotWorkRecoveryInputs,
    HistoricalV2SemanticCensusExclusion, HistoricalV2SemanticCheckpointKind,
    HistoricalV2SemanticCheckpointProgress, HistoricalV2SemanticSnapshotSide,
    HistoricalV2SemanticWorldProgress, HistoricalV2SlotOutcome, HistoricalV2SlotRunDisposition,
    HistoricalV2SlotSelection, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2SlotStageOutcome, HistoricalV2StageArtifactKind,
    HistoricalV2TerminalExclusionReason, inspect_historical_v2_selected_slot_state,
    recover_historical_v2_selected_slot_work, replay_historical_v2_public_surface_census,
    run_historical_v2_selected_slots_bounded, validate_historical_v2_protocol,
    validate_historical_v2_selected_payloads_commitment,
    validate_historical_v2_semantic_census_exclusion,
};
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

const MAX_PROTOCOL_BYTES: u64 = 1024 * 1024;
const MAX_JSON_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SEMANTIC_EXCLUSION_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Args)]
pub(super) struct RunSlotsArgs {
    #[arg(long)]
    protocol: PathBuf,
    #[arg(long)]
    artifact_root: PathBuf,
    #[arg(long)]
    frame: PathBuf,
    #[arg(long)]
    exclusions: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    payloads: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    work_root: PathBuf,
    #[arg(long)]
    harness_repository_root: PathBuf,
    #[arg(long)]
    docker_executable: PathBuf,
    #[arg(long)]
    max_new_slots: usize,
    #[arg(long)]
    max_new_stages_per_slot: Option<NonZeroUsize>,
    #[arg(long)]
    through_stage: Option<RunThroughStage>,
}

#[derive(Debug, Args)]
pub(super) struct RecoverSlotWorkArgs {
    #[arg(long)]
    protocol: PathBuf,
    #[arg(long)]
    artifact_root: PathBuf,
    #[arg(long)]
    frame: PathBuf,
    #[arg(long)]
    exclusions: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    payloads: PathBuf,
    #[arg(long)]
    work_root: PathBuf,
}

#[derive(Debug, Args)]
pub(super) struct StateStatusArgs {
    #[arg(long)]
    protocol: PathBuf,
    #[arg(long)]
    artifact_root: PathBuf,
    #[arg(long)]
    frame: PathBuf,
    #[arg(long)]
    exclusions: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    payloads: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    /// Include bounded committed semantic failure details in terminal output.
    #[arg(long)]
    show_semantic_failures: bool,
}

#[derive(Debug, Args)]
pub(super) struct ReplayPublicSurfaceCensusArgs {
    #[arg(long)]
    protocol: PathBuf,
    #[arg(long)]
    artifact_root: PathBuf,
    #[arg(long)]
    frame: PathBuf,
    #[arg(long)]
    exclusions: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    payloads: PathBuf,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    work_root: PathBuf,
    #[arg(long)]
    language: String,
    #[arg(long)]
    slot_number: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RunThroughStage {
    Payload,
    Materialization,
    TestMaterialization,
    SourceCensus,
    SemanticCensus,
    AssessmentIdentity,
    Qualification,
    TestRecipe,
    IdenticalTests,
    ReadyForReview,
}

pub(super) async fn run(args: RunSlotsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let protocol = read_plain_file(&args.protocol, "historical-v2 protocol", MAX_PROTOCOL_BYTES)?;
    let frame: HistoricalV2Frame = read_json(&args.frame, "historical-v2 frame")?;
    let exclusions: HistoricalV2ExclusionManifest =
        read_json(&args.exclusions, "historical-v2 exclusions")?;
    let selection: HistoricalV2SlotSelection =
        read_json(&args.selection, "historical-v2 selection")?;
    let payloads: HistoricalV2SelectedPayloads =
        read_json(&args.payloads, "historical-v2 selected payloads")?;
    let client = reqwest::Client::builder().build()?;
    let executor = DockerHistoricalV2TestExecutor::new(args.docker_executable);
    let summary = run_historical_v2_selected_slots_bounded(
        HistoricalV2SelectedSlotSweepInputs {
            client: &client,
            protocol_bytes: &protocol,
            artifact_root: &args.artifact_root,
            frame: &frame,
            exclusions: &exclusions,
            selection: &selection,
            payloads: &payloads,
            state_root: &args.state_root,
            work_root: &args.work_root,
            harness_repository_root: &args.harness_repository_root,
            test_executor: &executor,
            through_stage: args.through_stage.map(Into::into),
        },
        args.max_new_slots,
        args.max_new_stages_per_slot,
    )
    .await
    .map_err(stage_error)?;

    for slot in summary.slots.iter().filter(|slot| should_report_slot(slot)) {
        eprintln!(
            "{} slot {} | {} | {} | resumed at {} | executed {} stage(s)",
            slot.language,
            slot.slot_number,
            slot.canonical_repository,
            disposition(&slot.run.disposition),
            slot.run.resumed_after_sequence,
            slot.run.executed_stages.len()
        );
    }
    eprintln!(
        "Historical-v2 selected-slot sweep {}\nSelected: {}\nNewly admitted: {}\nReady for review: {}\nExcluded: {}\nPaused: {}",
        if summary.paused_count == 0 {
            "complete"
        } else {
            "paused"
        },
        summary.selected_slot_count,
        summary.newly_admitted_slot_count,
        summary.ready_for_review_count,
        summary.excluded_count,
        summary.paused_count
    );
    Ok(())
}

pub(super) fn recover_slot_work(
    args: RecoverSlotWorkArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let protocol = read_plain_file(&args.protocol, "historical-v2 protocol", MAX_PROTOCOL_BYTES)?;
    let frame: HistoricalV2Frame = read_json(&args.frame, "historical-v2 frame")?;
    let exclusions: HistoricalV2ExclusionManifest =
        read_json(&args.exclusions, "historical-v2 exclusions")?;
    let selection: HistoricalV2SlotSelection =
        read_json(&args.selection, "historical-v2 selection")?;
    let payloads: HistoricalV2SelectedPayloads =
        read_json(&args.payloads, "historical-v2 selected payloads")?;
    let summary =
        recover_historical_v2_selected_slot_work(HistoricalV2SelectedSlotWorkRecoveryInputs {
            protocol_bytes: &protocol,
            artifact_root: &args.artifact_root,
            frame: &frame,
            exclusions: &exclusions,
            selection: &selection,
            payloads: &payloads,
            work_root: &args.work_root,
        })
        .map_err(stage_error)?;
    eprintln!(
        "Historical-v2 selected-slot work recovered\nSelected slots: {}\nMaterialized worktrees: {}\nInterrupted indexers recovered: {}\nStarted semantic compiler worlds: {}",
        summary.selected_slot_count,
        summary.materialized_semantic_root_count,
        summary.recovered_semantic_root_count,
        summary.semantic_worlds.len()
    );
    for world in &summary.semantic_worlds {
        eprintln!("{}", semantic_world_progress_line(world));
    }
    eprintln!(
        "Durable semantic checkpoints: {}",
        summary.semantic_checkpoints.len()
    );
    for checkpoint in &summary.semantic_checkpoints {
        eprintln!("{}", semantic_checkpoint_progress_line(checkpoint));
    }
    Ok(())
}

pub(super) fn semantic_world_progress_line(world: &HistoricalV2SemanticWorldProgress) -> String {
    let side = match world.side {
        HistoricalV2SemanticSnapshotSide::Base => "base",
        HistoricalV2SemanticSnapshotSide::Patched => "patched",
    };
    let identity = world.variant_identity.as_deref().unwrap_or("unqualified");
    let dimensions = world
        .dimensions
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let next = world.next_unit_id.as_deref().unwrap_or("complete");
    let next_durable = world.next_durable_unit_id.as_deref().unwrap_or("complete");
    format!(
        "  {}/slot-{:04} side={} family={} world={} variant={} dimensions=[{}] units={}/{} next={} durable_units={}/{} next_durable={}",
        world.language,
        world.slot_number,
        side,
        world.family,
        world.world,
        identity,
        dimensions,
        world.completed_unit_count,
        world.planned_unit_count,
        next,
        world.durable_unit_count,
        world.planned_unit_count,
        next_durable
    )
}

pub(super) fn semantic_checkpoint_progress_line(
    checkpoint: &HistoricalV2SemanticCheckpointProgress,
) -> String {
    let side = match checkpoint.side {
        HistoricalV2SemanticSnapshotSide::Base => "base",
        HistoricalV2SemanticSnapshotSide::Patched => "patched",
    };
    let kind = match checkpoint.kind {
        HistoricalV2SemanticCheckpointKind::Contribution => "contribution",
        HistoricalV2SemanticCheckpointKind::Snapshot => "snapshot",
    };
    format!(
        "  {}/slot-{:04} side={} checkpoint={} identity={} sha256={}",
        checkpoint.language,
        checkpoint.slot_number,
        side,
        kind,
        checkpoint.identity,
        checkpoint.checkpoint_sha256
    )
}

pub(super) fn state_status(args: StateStatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    let protocol = read_plain_file(&args.protocol, "historical-v2 protocol", MAX_PROTOCOL_BYTES)?;
    let frame: HistoricalV2Frame = read_json(&args.frame, "historical-v2 frame")?;
    let exclusions: HistoricalV2ExclusionManifest =
        read_json(&args.exclusions, "historical-v2 exclusions")?;
    let selection: HistoricalV2SlotSelection =
        read_json(&args.selection, "historical-v2 selection")?;
    let payloads: HistoricalV2SelectedPayloads =
        read_json(&args.payloads, "historical-v2 selected payloads")?;
    let summary =
        inspect_historical_v2_selected_slot_state(HistoricalV2SelectedSlotStateInspectionInputs {
            protocol_bytes: &protocol,
            artifact_root: &args.artifact_root,
            frame: &frame,
            exclusions: &exclusions,
            selection: &selection,
            payloads: &payloads,
            state_root: &args.state_root,
        })
        .map_err(stage_error)?;

    for slot in summary.slots.iter().filter(|slot| slot_started(slot)) {
        let latest = slot
            .latest_committed_stage
            .map(stage_name)
            .unwrap_or("none");
        let next = slot.next_stage.map(stage_name).unwrap_or("none");
        let outcome = slot
            .latest_committed_outcome
            .as_ref()
            .map(outcome_name)
            .unwrap_or("none");
        eprintln!(
            "{} slot {} | {} | committed {} stage(s) through {} ({}) | next {} | incomplete initialization={} publish={} rewind={}",
            slot.language,
            slot.slot_number,
            slot.canonical_repository,
            slot.committed_stage_count,
            latest,
            outcome,
            next,
            slot.incomplete_initialization,
            slot.incomplete_stage_transaction,
            slot.incomplete_rewind_transaction,
        );
    }
    eprintln!(
        "Historical-v2 selected-slot state verified\nSelected: {}\nStarted: {}\nTerminal: {}\nIncomplete: {}",
        summary.selected_slot_count,
        summary.started_slot_count,
        summary.terminal_slot_count,
        summary.incomplete_slot_count,
    );
    for quota in &summary.quota_headroom {
        eprintln!(
            "{} release headroom without replay: at most {} accepted / {} required ({} selected, {} terminally excluded, {} fixed){}",
            quota.language,
            quota.maximum_accepted_without_replay,
            quota.minimum_accepted,
            quota.selected_slot_count,
            quota.terminal_excluded_count,
            quota.fixed_slot_count,
            if quota.reachable_without_replay {
                ""
            } else {
                " - unreachable under current sealed state"
            }
        );
    }
    if args.show_semantic_failures {
        for slot in &summary.slots {
            for line in semantic_failure_lines(&args.state_root, slot)? {
                eprintln!("{line}");
            }
        }
    }
    Ok(())
}

fn semantic_failure_lines(
    state_root: &Path,
    slot: &HistoricalV2SelectedSlotStateInspection,
) -> Result<Vec<String>, IoError> {
    let Some(HistoricalV2SlotStageOutcome::Excluded {
        reason: HistoricalV2TerminalExclusionReason::SemanticCensus(reasons),
        artifact_kind,
        artifact_sha256,
    }) = &slot.latest_committed_outcome
    else {
        return Ok(Vec::new());
    };
    if slot.incomplete_rewind_transaction {
        return Ok(Vec::new());
    }
    if slot.latest_committed_stage != Some(HistoricalV2SlotStage::SemanticCensus)
        || *artifact_kind != HistoricalV2StageArtifactKind::SemanticCensusExclusion
    {
        return Err(invalid_data(
            "historical-v2 semantic exclusion stage identity changed".to_string(),
        ));
    }
    let path = state_root
        .join(&slot.language)
        .join(format!("slot-{:04}", slot.slot_number))
        .join("0005-semantic-census")
        .join("artifact.json");
    let bytes = read_plain_file(
        &path,
        "historical-v2 semantic exclusion",
        MAX_SEMANTIC_EXCLUSION_BYTES,
    )?;
    let exclusion: HistoricalV2SemanticCensusExclusion =
        serde_json::from_slice(&bytes).map_err(|error| {
            invalid_data(format!("invalid historical-v2 semantic exclusion: {error}"))
        })?;
    validate_historical_v2_semantic_census_exclusion(&exclusion).map_err(invalid_data)?;
    if exclusion.reasons != *reasons || exclusion.exclusion_sha256 != *artifact_sha256 {
        return Err(invalid_data(
            "historical-v2 semantic exclusion changed from its committed checkpoint".to_string(),
        ));
    }
    Ok(exclusion
        .failures
        .iter()
        .map(|failure| {
            format!(
                "{} slot {} | semantic failure side={:?} revision={} reason={:?} phase={:?} indexer={:?} detail_sha256={} detail={:?}",
                slot.language,
                slot.slot_number,
                failure.side,
                failure.revision,
                failure.reason,
                failure.phase,
                failure.indexer,
                failure.detail_sha256,
                failure.retained_detail,
            )
        })
        .collect())
}

pub(super) fn replay_public_surface_census(
    args: ReplayPublicSurfaceCensusArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let protocol_bytes =
        read_plain_file(&args.protocol, "historical-v2 protocol", MAX_PROTOCOL_BYTES)?;
    let protocol = validate_historical_v2_protocol(&protocol_bytes).map_err(invalid_data)?;
    let frame: HistoricalV2Frame = read_json(&args.frame, "historical-v2 frame")?;
    let exclusions: HistoricalV2ExclusionManifest =
        read_json(&args.exclusions, "historical-v2 exclusions")?;
    let selection: HistoricalV2SlotSelection =
        read_json(&args.selection, "historical-v2 selection")?;
    let payloads: HistoricalV2SelectedPayloads =
        read_json(&args.payloads, "historical-v2 selected payloads")?;
    sniff::benchmark::validate_historical_v2_slot_selection(
        &protocol_bytes,
        &args.artifact_root,
        &frame,
        &exclusions,
        &selection,
    )
    .map_err(invalid_data)?;
    validate_historical_v2_selected_payloads_commitment(
        &protocol,
        &frame,
        &exclusions,
        &selection,
        &payloads,
    )
    .map_err(invalid_data)?;
    let payload = payloads
        .records
        .iter()
        .find(|payload| {
            payload.language == args.language && payload.slot_number == args.slot_number
        })
        .ok_or_else(|| invalid_data("historical-v2 replay target is not selected".to_string()))?;
    let canonical_repository = selection
        .slots
        .iter()
        .find_map(|slot| {
            if slot.language != payload.language || slot.slot_number != payload.slot_number {
                return None;
            }
            match &slot.outcome {
                HistoricalV2SlotOutcome::Selected {
                    global_row_index,
                    instance_id,
                    canonical_repository,
                    ..
                } if *global_row_index == payload.global_row_index
                    && instance_id == &payload.instance_id =>
                {
                    Some(canonical_repository.as_str())
                }
                _ => None,
            }
        })
        .ok_or_else(|| invalid_data("historical-v2 replay identity changed".to_string()))?;
    let summary =
        replay_historical_v2_public_surface_census(HistoricalV2PublicSurfaceReplayInputs {
            state_root: &args.state_root,
            work_root: &args.work_root,
            selection_sha256: &selection.selection_sha256,
            language: &args.language,
            slot_number: args.slot_number,
            canonical_repository,
        })
        .map_err(stage_error)?;
    eprintln!(
        "Historical-v2 public-surface census replay prepared\nTarget: {}/slot-{:04}\nRetained through: {:?}\nRemoved stages: {}\nRemoved semantic progress: {}\nRemoved source progress: {}",
        summary.language,
        summary.slot_number,
        summary.retained_stage,
        summary.removed_stage_count,
        summary.removed_semantic_progress,
        summary.removed_source_progress
    );
    Ok(())
}

pub(super) fn should_report_slot(
    slot: &sniff::benchmark::HistoricalV2SelectedSlotRunSummary,
) -> bool {
    !slot.run.executed_stages.is_empty()
}

fn slot_started(slot: &HistoricalV2SelectedSlotStateInspection) -> bool {
    slot.committed_stage_count > 0
        || slot.incomplete_initialization
        || slot.incomplete_stage_transaction
        || slot.incomplete_rewind_transaction
}

fn outcome_name(outcome: &HistoricalV2SlotStageOutcome) -> &'static str {
    match outcome {
        HistoricalV2SlotStageOutcome::Completed { .. } => "completed",
        HistoricalV2SlotStageOutcome::Excluded { .. } => "excluded",
        HistoricalV2SlotStageOutcome::ReadyForReview => "ready-for-review",
    }
}

fn stage_name(stage: HistoricalV2SlotStage) -> &'static str {
    match stage {
        HistoricalV2SlotStage::Payload => "payload",
        HistoricalV2SlotStage::Materialization => "materialization",
        HistoricalV2SlotStage::TestMaterialization => "test-materialization",
        HistoricalV2SlotStage::SourceCensus => "source-census",
        HistoricalV2SlotStage::SemanticCensus => "semantic-census",
        HistoricalV2SlotStage::AssessmentIdentity => "assessment-identity",
        HistoricalV2SlotStage::Qualification => "qualification",
        HistoricalV2SlotStage::TestRecipe => "test-recipe",
        HistoricalV2SlotStage::IdenticalTests => "identical-tests",
        HistoricalV2SlotStage::ReadyForReview => "ready-for-review",
    }
}

impl From<RunThroughStage> for sniff::benchmark::HistoricalV2SlotStage {
    fn from(value: RunThroughStage) -> Self {
        match value {
            RunThroughStage::Payload => Self::Payload,
            RunThroughStage::Materialization => Self::Materialization,
            RunThroughStage::TestMaterialization => Self::TestMaterialization,
            RunThroughStage::SourceCensus => Self::SourceCensus,
            RunThroughStage::SemanticCensus => Self::SemanticCensus,
            RunThroughStage::AssessmentIdentity => Self::AssessmentIdentity,
            RunThroughStage::Qualification => Self::Qualification,
            RunThroughStage::TestRecipe => Self::TestRecipe,
            RunThroughStage::IdenticalTests => Self::IdenticalTests,
            RunThroughStage::ReadyForReview => Self::ReadyForReview,
        }
    }
}

fn disposition(value: &HistoricalV2SlotRunDisposition) -> String {
    match value {
        HistoricalV2SlotRunDisposition::ReadyForReview => "ready for review".to_string(),
        HistoricalV2SlotRunDisposition::Excluded { stage, reason } => {
            format!("excluded at {stage:?}: {reason:?}")
        }
        HistoricalV2SlotRunDisposition::Paused { next_stage } => {
            format!("paused before {next_stage:?}")
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, IoError> {
    let bytes = read_plain_file(path, label, MAX_JSON_ARTIFACT_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| IoError::new(ErrorKind::InvalidData, format!("invalid {label}: {error}")))
}

fn read_plain_file(path: &Path, label: &str, maximum_bytes: u64) -> Result<Vec<u8>, IoError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to inspect {label} at {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("{label} must be a plain file: {}", path.display()),
        ));
    }
    if metadata.len() > maximum_bytes {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!(
                "{label} exceeds the {maximum_bytes}-byte input limit: {}",
                path.display()
            ),
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read {label} at {}: {error}", path.display()),
        )
    })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!(
                "{label} changed while it was being read: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn stage_error(error: HistoricalV2SlotStageError) -> IoError {
    let kind = match error.kind {
        HistoricalV2SlotStageErrorKind::InvalidInput => ErrorKind::InvalidData,
        HistoricalV2SlotStageErrorKind::InfrastructureUnavailable
        | HistoricalV2SlotStageErrorKind::InfrastructureFailed => ErrorKind::Other,
    };
    IoError::new(
        kind,
        format!(
            "historical-v2 {:?} {:?}: {}",
            error.stage, error.kind, error.detail
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use sniff::benchmark::{
        HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
        HistoricalV2SemanticCensusExclusionReason, HistoricalV2SemanticCensusFailureEvidence,
        HistoricalV2SemanticCensusFailurePhase, HistoricalV2SemanticSnapshotSide,
    };

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn semantic_failure_details_are_escaped_and_commitment_bound() {
        let temp = tempfile::tempdir().unwrap();
        let detail = "compiler output\n\u{1b}[31m";
        let mut exclusion = HistoricalV2SemanticCensusExclusion {
            schema_version: HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
            exclusion_contract: "sniffbench-historical-v2-semantic-census-exclusion-v1".to_string(),
            materialization_sha256: "b".repeat(64),
            source_census_sha256: "c".repeat(64),
            reasons: vec![HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete],
            failures: vec![HistoricalV2SemanticCensusFailureEvidence {
                side: HistoricalV2SemanticSnapshotSide::Base,
                revision: "a".repeat(40),
                reason: HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete,
                indexer: None,
                phase: HistoricalV2SemanticCensusFailurePhase::SnapshotAssembly,
                detail_sha256: sha256(detail.as_bytes()),
                retained_detail: detail.to_string(),
                detail_truncated: false,
                process: None,
            }],
            exclusion_sha256: String::new(),
        };
        exclusion.exclusion_sha256 = sha256(&serde_json::to_vec(&exclusion).unwrap());
        let artifact_path = temp
            .path()
            .join("go/slot-0001/0005-semantic-census/artifact.json");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, serde_json::to_vec(&exclusion).unwrap()).unwrap();
        let mut slot = HistoricalV2SelectedSlotStateInspection {
            language: "go".to_string(),
            slot_number: 1,
            canonical_repository: "example/repository".to_string(),
            committed_stage_count: 5,
            latest_committed_stage: Some(HistoricalV2SlotStage::SemanticCensus),
            latest_committed_outcome: Some(HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::SemanticCensus(
                    exclusion.reasons.clone(),
                ),
                artifact_kind: HistoricalV2StageArtifactKind::SemanticCensusExclusion,
                artifact_sha256: exclusion.exclusion_sha256.clone(),
            }),
            next_stage: None,
            incomplete_initialization: false,
            incomplete_stage_transaction: false,
            incomplete_rewind_transaction: false,
        };

        let lines = semantic_failure_lines(temp.path(), &slot).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("phase=SnapshotAssembly"));
        assert!(lines[0].contains(&sha256(detail.as_bytes())));
        assert!(!lines[0].contains('\n'));
        assert!(!lines[0].contains('\u{1b}'));

        slot.latest_committed_outcome = Some(HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::SemanticCensus(exclusion.reasons.clone()),
            artifact_kind: HistoricalV2StageArtifactKind::SemanticCensusExclusion,
            artifact_sha256: "0".repeat(64),
        });
        assert!(semantic_failure_lines(temp.path(), &slot).is_err());

        slot.latest_committed_outcome = Some(HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::SemanticCensus(exclusion.reasons.clone()),
            artifact_kind: HistoricalV2StageArtifactKind::SemanticCensusExclusion,
            artifact_sha256: exclusion.exclusion_sha256.clone(),
        });
        exclusion.failures[0].retained_detail = "tampered".to_string();
        fs::write(&artifact_path, serde_json::to_vec(&exclusion).unwrap()).unwrap();
        assert!(semantic_failure_lines(temp.path(), &slot).is_err());
    }
}
