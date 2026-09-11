use super::invalid_data;
use clap::{Args, ValueEnum};
use serde::de::DeserializeOwned;
use sniff::benchmark::{
    DockerHistoricalV2TestExecutor, HistoricalV2ExclusionManifest, HistoricalV2Frame,
    HistoricalV2PublicSurfaceReplayInputs, HistoricalV2SelectedPayloads,
    HistoricalV2SelectedSlotStateInspection, HistoricalV2SelectedSlotStateInspectionInputs,
    HistoricalV2SelectedSlotSweepInputs, HistoricalV2SelectedSlotWorkRecoveryInputs,
    HistoricalV2SemanticSnapshotSide, HistoricalV2SlotOutcome, HistoricalV2SlotRunDisposition,
    HistoricalV2SlotSelection, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2SlotStageOutcome,
    inspect_historical_v2_selected_slot_state, recover_historical_v2_selected_slot_work,
    replay_historical_v2_public_surface_census, run_historical_v2_selected_slots_bounded,
    validate_historical_v2_protocol, validate_historical_v2_selected_payloads_commitment,
};
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

const MAX_PROTOCOL_BYTES: u64 = 1024 * 1024;
const MAX_JSON_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

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
    max_new_slots: NonZeroUsize,
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
        eprintln!(
            "  {}/slot-{:04} side={} family={} world={} variant={} dimensions=[{}] units={}/{} next={}",
            world.language,
            world.slot_number,
            side,
            world.family,
            world.world,
            identity,
            dimensions,
            world.completed_unit_count,
            world.planned_unit_count,
            next
        );
    }
    Ok(())
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
    Ok(())
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
