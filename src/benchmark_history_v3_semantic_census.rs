#[path = "benchmark_history_v3_semantic_census_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_semantic_census_surface.rs"]
mod surface;

#[path = "benchmark_history_v3_semantic_census_failure_commitment.rs"]
mod failure_commitment;

#[path = "benchmark_history_v3_semantic_census_commitment.rs"]
mod commitment;

pub use commitment::{
    validate_historical_v3_semantic_census_commitment,
    validate_historical_v3_semantic_census_exclusion,
};

#[path = "benchmark_history_v3_semantic_census_store.rs"]
mod store;

#[path = "benchmark_history_v3_semantic_census_runtime.rs"]
mod runtime;

pub use runtime::run_historical_v3_semantic_census_stage;

pub(super) const SEMANTIC_CENSUS_CONTRACT: &str =
    "sniffbench-historical-v3-compiler-semantic-census-v1";
pub(super) const SEMANTIC_CENSUS_EXCLUSION_CONTRACT: &str =
    "sniffbench-historical-v3-compiler-semantic-census-exclusion-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_semantic_census_tests.rs"]
mod tests;
