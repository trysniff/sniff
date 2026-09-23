#[path = "benchmark_history_v3_mechanical_qualification_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_mechanical_qualification_roles.rs"]
mod roles;

#[path = "benchmark_history_v3_mechanical_qualification_evidence.rs"]
mod evidence;

#[path = "benchmark_history_v3_mechanical_qualification_paths.rs"]
mod paths;

#[path = "benchmark_history_v3_mechanical_qualification_methods.rs"]
mod methods;

#[path = "benchmark_history_v3_mechanical_qualification_surface.rs"]
mod surface;

#[path = "benchmark_history_v3_mechanical_qualification_commitment.rs"]
mod commitment;

pub use commitment::{
    derive_historical_v3_mechanical_qualification, validate_historical_v3_mechanical_qualification,
    validate_historical_v3_mechanical_qualification_exclusion,
};

#[path = "benchmark_history_v3_mechanical_qualification_store.rs"]
mod store;

#[path = "benchmark_history_v3_mechanical_qualification_runtime.rs"]
mod runtime;

pub use runtime::run_historical_v3_mechanical_qualification_stage;

pub(super) const MECHANICAL_QUALIFICATION_CONTRACT: &str =
    "sniffbench-historical-v3-mechanical-qualification-v1";
pub(super) const MECHANICAL_QUALIFICATION_EXCLUSION_CONTRACT: &str =
    "sniffbench-historical-v3-mechanical-qualification-exclusion-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_mechanical_qualification_tests.rs"]
mod tests;
