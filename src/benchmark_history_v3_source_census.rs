#[path = "benchmark_history_v3_source_census_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_source_census_failure_commitment.rs"]
mod failure_commitment;

#[path = "benchmark_history_v3_source_census_commitment.rs"]
mod commitment;

pub use commitment::{
    validate_historical_v3_source_census_commitment, validate_historical_v3_source_census_exclusion,
};

#[path = "benchmark_history_v3_source_census_runtime.rs"]
mod runtime;

pub use runtime::run_historical_v3_source_census_stage;

pub(super) const SOURCE_CENSUS_CONTRACT: &str = "sniffbench-historical-v3-source-census-v1";
pub(super) const SOURCE_CENSUS_EXCLUSION_CONTRACT: &str =
    "sniffbench-historical-v3-source-census-exclusion-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_source_census_tests.rs"]
mod tests;
