use clap::Parser;
use sniff::benchmark::{
    HistoricalV3PriorNameObservationStatus, audit_historical_v3_prior_names,
    derive_frozen_historical_v3_prior_identity_seal, verify_historical_v3_prior_name_audit,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Replay saved repository-name observations against the frozen prior seal")]
struct Args {
    #[arg(long)]
    artifact_root: PathBuf,
    #[arg(long)]
    frame: PathBuf,
    #[arg(long)]
    exclusions: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long = "observation", required = true)]
    observations: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("prior-name audit failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let seal = derive_frozen_historical_v3_prior_identity_seal(
        &args.artifact_root,
        &args.frame,
        &args.exclusions,
        &args.selection,
    )?;
    let directories = args
        .observations
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    let audit = audit_historical_v3_prior_names(&seal, &directories)?;
    verify_historical_v3_prior_name_audit(&seal, &directories, &audit)?;
    let output_parent = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let output_parent = fs::canonicalize(output_parent)
        .map_err(|error| format!("failed to resolve prior-name audit output directory: {error}"))?;
    for directory in &directories {
        let observation_root = fs::canonicalize(directory).map_err(|error| {
            format!("failed to resolve prior-name observation directory: {error}")
        })?;
        if observation_root == output_parent {
            return Err(
                "prior-name audit output cannot be inside an observation directory".to_string(),
            );
        }
    }
    let mut bytes = serde_json::to_vec_pretty(&audit)
        .map_err(|error| format!("failed to encode prior-name audit: {error}"))?;
    bytes.push(b'\n');
    let mut staged = tempfile::NamedTempFile::new_in(&output_parent)
        .map_err(|error| format!("failed to stage prior-name audit output: {error}"))?;
    staged
        .write_all(&bytes)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| format!("failed to write prior-name audit output: {error}"))?;
    staged
        .persist_noclobber(&args.output)
        .map_err(|error| format!("failed to publish prior-name audit output: {error}"))?;
    let count = |status| {
        audit
            .observations
            .iter()
            .filter(|item| item.status == status)
            .count()
    };
    println!(
        "{} sealed names: {} saved pre-cutoff-ID lookups, {} saved post-cutoff-ID lookups, {} saved 404s; observation time and historical identity remain unproven",
        audit.observations.len(),
        count(HistoricalV3PriorNameObservationStatus::ObservedPreCutoffId),
        count(HistoricalV3PriorNameObservationStatus::ObservedPostCutoffId),
        count(HistoricalV3PriorNameObservationStatus::ObservedNotFound),
    );
    println!("audit SHA-256: {}", audit.audit_sha256);
    Ok(())
}
