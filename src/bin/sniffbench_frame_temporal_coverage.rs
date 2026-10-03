use clap::Args;
use sniff::benchmark::{
    HistoricalV3PriorTemporalCoverage, HistoricalV3PriorTemporalCoverageInputs,
    derive_frozen_historical_v3_prior_temporal_coverage,
    read_historical_v3_prior_temporal_coverage,
    validate_frozen_historical_v3_prior_temporal_coverage,
    write_historical_v3_prior_temporal_coverage_new,
};
use std::error::Error;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct PriorTemporalCoverageArgs {
    pub artifact_root: PathBuf,
    pub dataset_root: PathBuf,
    pub frame: PathBuf,
    pub exclusions: PathBuf,
    pub selection: PathBuf,
    pub blind_source_seal: PathBuf,
    pub source_repository: PathBuf,
    pub coverage: PathBuf,
}

impl PriorTemporalCoverageArgs {
    fn inputs(&self) -> HistoricalV3PriorTemporalCoverageInputs<'_> {
        HistoricalV3PriorTemporalCoverageInputs {
            artifact_root: &self.artifact_root,
            dataset_root: &self.dataset_root,
            frame: &self.frame,
            exclusions: &self.exclusions,
            selection: &self.selection,
            blind_source_seal: &self.blind_source_seal,
            source_repository: &self.source_repository,
        }
    }
}

pub fn issue(args: PriorTemporalCoverageArgs) -> Result<(), Box<dyn Error>> {
    let coverage = derive_frozen_historical_v3_prior_temporal_coverage(&args.inputs())
        .map_err(super::invalid_data)?;
    write_historical_v3_prior_temporal_coverage_new(&args.coverage, &coverage)
        .map_err(super::invalid_data)?;
    print_summary(&coverage);
    eprintln!("Coverage written to {}", args.coverage.display());
    Ok(())
}

pub fn validate(args: PriorTemporalCoverageArgs) -> Result<(), Box<dyn Error>> {
    let coverage =
        read_historical_v3_prior_temporal_coverage(&args.coverage).map_err(super::invalid_data)?;
    validate_frozen_historical_v3_prior_temporal_coverage(&args.inputs(), &coverage)
        .map_err(super::invalid_data)?;
    print_summary(&coverage);
    eprintln!("Coverage replay validated");
    Ok(())
}

fn print_summary(coverage: &HistoricalV3PriorTemporalCoverage) {
    eprintln!(
        "Prior temporal coverage (not admission)\nSource-replayed obligations: {}\nUnresolved obligations: {}\nFully witnessed names: {}\nNames with unresolved obligations: {}\nPublication qualified: {}\nCoverage SHA-256: {}",
        coverage.source_replayed_obligation_count,
        coverage.unresolved_obligation_count,
        coverage.fully_witnessed_repository_count,
        coverage.unresolved_repository_count,
        coverage.publication_qualified,
        coverage.coverage_sha256,
    );
}
