use clap::{Args, ValueEnum};
use serde::de::DeserializeOwned;
use sniff::benchmark::{
    DockerHistoricalV2TestExecutor, HistoricalV2ExclusionManifest, HistoricalV2Frame,
    HistoricalV2SelectedPayloads, HistoricalV2SelectedSlotSweepInputs,
    HistoricalV2SlotRunDisposition, HistoricalV2SlotSelection, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, run_historical_v2_selected_slots_bounded,
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

    for slot in &summary.slots {
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
