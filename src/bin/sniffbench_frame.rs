use clap::{Parser, Subcommand};
use sniff::benchmark::{
    HistoricalV2ExclusionManifest, HistoricalV2Frame, HistoricalV2SlotSelection,
    validate_historical_v2_frame_sources, validate_historical_v2_selected_payloads,
    validate_historical_v2_slot_selection, write_derived_historical_v2_exclusion_manifest,
    write_historical_v2_frame, write_historical_v2_selected_payloads,
    write_historical_v2_slot_selection,
};
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "sniffbench-frame", version)]
#[command(about = "Build and replay SniffBench's pinned historical-v2 Parquet frame")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build a create-new frame from the exact pinned local Parquet shards.
    Collect {
        protocol: PathBuf,
        dataset_root: PathBuf,
        output: PathBuf,
    },
    /// Replay and compare a frame against the exact pinned local Parquet shards.
    Validate {
        protocol: PathBuf,
        dataset_root: PathBuf,
        frame: PathBuf,
    },
    /// Derive and seal the exact six-partition repository exclusions.
    DeriveExclusions {
        protocol: PathBuf,
        artifact_root: PathBuf,
        output: PathBuf,
    },
    /// Freeze the 128 no-backfill slots for every supported language.
    Select {
        protocol: PathBuf,
        dataset_root: PathBuf,
        artifact_root: PathBuf,
        frame: PathBuf,
        exclusions: PathBuf,
        output: PathBuf,
    },
    /// Replay the source frame and reproduce the fixed-slot selection.
    ValidateSelection {
        protocol: PathBuf,
        dataset_root: PathBuf,
        artifact_root: PathBuf,
        frame: PathBuf,
        exclusions: PathBuf,
        selection: PathBuf,
    },
    /// Open the selected patch and two post-selection fields after replaying fixed slots.
    ExtractSelectedPayloads {
        protocol: PathBuf,
        dataset_root: PathBuf,
        artifact_root: PathBuf,
        frame: PathBuf,
        exclusions: PathBuf,
        selection: PathBuf,
        output: PathBuf,
    },
    /// Replay the fixed slots and reproduce their selected payloads.
    ValidateSelectedPayloads {
        protocol: PathBuf,
        dataset_root: PathBuf,
        artifact_root: PathBuf,
        frame: PathBuf,
        exclusions: PathBuf,
        selection: PathBuf,
        payloads: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.command {
        Command::Collect {
            protocol,
            dataset_root,
            output,
        } => {
            let protocol = fs::read(protocol)?;
            let frame = write_historical_v2_frame(&protocol, &dataset_root, &output)
                .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 frame written to {}\nRows: {}\nEligible: {}\nExcluded: {}\nFrame SHA-256: {}",
                output.display(),
                frame.row_count,
                frame.eligible_count,
                frame.excluded_count,
                frame.frame_sha256
            );
        }
        Command::Validate {
            protocol,
            dataset_root,
            frame,
        } => {
            let protocol = fs::read(protocol)?;
            let frame: HistoricalV2Frame = serde_json::from_slice(&fs::read(frame)?)?;
            validate_historical_v2_frame_sources(&protocol, &dataset_root, &frame)
                .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 frame validated\nRows: {}\nFrame SHA-256: {}",
                frame.row_count, frame.frame_sha256
            );
        }
        Command::DeriveExclusions {
            protocol,
            artifact_root,
            output,
        } => {
            let protocol = fs::read(protocol)?;
            let manifest =
                write_derived_historical_v2_exclusion_manifest(&protocol, &artifact_root, &output)
                    .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 exclusions written to {}\nRepositories: {}\nManifest SHA-256: {}",
                output.display(),
                manifest.repository_count,
                manifest.manifest_sha256
            );
        }
        Command::Select {
            protocol,
            dataset_root,
            artifact_root,
            frame,
            exclusions,
            output,
        } => {
            let protocol = fs::read(protocol)?;
            let frame: HistoricalV2Frame = serde_json::from_slice(&fs::read(frame)?)?;
            let exclusions: HistoricalV2ExclusionManifest =
                serde_json::from_slice(&fs::read(exclusions)?)?;
            validate_historical_v2_frame_sources(&protocol, &dataset_root, &frame)
                .map_err(invalid_data)?;
            let selection = write_historical_v2_slot_selection(
                &protocol,
                &artifact_root,
                &frame,
                &exclusions,
                &output,
            )
            .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 slots written to {}\nSelected: {}\nUnfilled: {}\nSelection SHA-256: {}",
                output.display(),
                selection.selected_count,
                selection.unfilled_slot_count,
                selection.selection_sha256
            );
        }
        Command::ValidateSelection {
            protocol,
            dataset_root,
            artifact_root,
            frame,
            exclusions,
            selection,
        } => {
            let protocol = fs::read(protocol)?;
            let frame: HistoricalV2Frame = serde_json::from_slice(&fs::read(frame)?)?;
            let exclusions: HistoricalV2ExclusionManifest =
                serde_json::from_slice(&fs::read(exclusions)?)?;
            let selection: HistoricalV2SlotSelection =
                serde_json::from_slice(&fs::read(selection)?)?;
            validate_historical_v2_frame_sources(&protocol, &dataset_root, &frame)
                .map_err(invalid_data)?;
            validate_historical_v2_slot_selection(
                &protocol,
                &artifact_root,
                &frame,
                &exclusions,
                &selection,
            )
            .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 slot selection validated\nSelected: {}\nSelection SHA-256: {}",
                selection.selected_count, selection.selection_sha256
            );
        }
        Command::ExtractSelectedPayloads {
            protocol,
            dataset_root,
            artifact_root,
            frame,
            exclusions,
            selection,
            output,
        } => {
            let protocol = fs::read(protocol)?;
            let frame: HistoricalV2Frame = serde_json::from_slice(&fs::read(frame)?)?;
            let exclusions: HistoricalV2ExclusionManifest =
                serde_json::from_slice(&fs::read(exclusions)?)?;
            let selection: HistoricalV2SlotSelection =
                serde_json::from_slice(&fs::read(selection)?)?;
            let payloads = write_historical_v2_selected_payloads(
                &protocol,
                &dataset_root,
                &artifact_root,
                &frame,
                &exclusions,
                &selection,
                &output,
            )
            .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 selected payloads written to {}\nSelected: {}\nPayloads SHA-256: {}",
                output.display(),
                payloads.selected_count,
                payloads.payloads_sha256
            );
        }
        Command::ValidateSelectedPayloads {
            protocol,
            dataset_root,
            artifact_root,
            frame,
            exclusions,
            selection,
            payloads,
        } => {
            let protocol = fs::read(protocol)?;
            let frame: HistoricalV2Frame = serde_json::from_slice(&fs::read(frame)?)?;
            let exclusions: HistoricalV2ExclusionManifest =
                serde_json::from_slice(&fs::read(exclusions)?)?;
            let selection: HistoricalV2SlotSelection =
                serde_json::from_slice(&fs::read(selection)?)?;
            validate_historical_v2_selected_payloads(
                &protocol,
                &dataset_root,
                &artifact_root,
                &frame,
                &exclusions,
                &selection,
                &payloads,
            )
            .map_err(invalid_data)?;
            eprintln!(
                "Historical-v2 selected payloads validated\nSelection SHA-256: {}",
                selection.selection_sha256
            );
        }
    }
    Ok(())
}

fn invalid_data(error: String) -> IoError {
    IoError::new(ErrorKind::InvalidData, error)
}
