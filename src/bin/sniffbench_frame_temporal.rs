use clap::Args;
use sniff::benchmark::{
    HistoricalV3PriorV2TemporalProof, derive_frozen_historical_v3_prior_v2_temporal_proof,
    validate_frozen_historical_v3_prior_v2_temporal_proof,
};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct PriorV2TemporalArgs {
    pub artifact_root: PathBuf,
    pub dataset_root: PathBuf,
    pub frame: PathBuf,
    pub exclusions: PathBuf,
    pub selection: PathBuf,
    pub proof: PathBuf,
}

pub fn issue(args: PriorV2TemporalArgs) -> Result<(), Box<dyn Error>> {
    let proof = derive_frozen_historical_v3_prior_v2_temporal_proof(
        &args.artifact_root,
        &args.dataset_root,
        &args.frame,
        &args.exclusions,
        &args.selection,
    )
    .map_err(super::invalid_data)?;
    let bytes = serde_json::to_vec_pretty(&proof)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.proof)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    eprintln!(
        "Historical-v2 prior temporal proof written to {}\nWitnesses: {}\nProof SHA-256: {}",
        args.proof.display(),
        proof.witnesses.len(),
        proof.proof_sha256
    );
    Ok(())
}

pub fn validate(args: PriorV2TemporalArgs) -> Result<(), Box<dyn Error>> {
    let proof: HistoricalV3PriorV2TemporalProof = serde_json::from_slice(&fs::read(&args.proof)?)?;
    validate_frozen_historical_v3_prior_v2_temporal_proof(
        &args.artifact_root,
        &args.dataset_root,
        &args.frame,
        &args.exclusions,
        &args.selection,
        &proof,
    )
    .map_err(super::invalid_data)?;
    eprintln!(
        "Historical-v2 prior temporal proof validated\nWitnesses: {}\nProof SHA-256: {}",
        proof.witnesses.len(),
        proof.proof_sha256
    );
    Ok(())
}
