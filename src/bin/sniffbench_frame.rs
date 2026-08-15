use clap::{Parser, Subcommand};
use sniff::benchmark::{
    HistoricalV2Frame, validate_historical_v2_frame_sources, write_historical_v2_frame,
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
    }
    Ok(())
}

fn invalid_data(error: String) -> IoError {
    IoError::new(ErrorKind::InvalidData, error)
}
