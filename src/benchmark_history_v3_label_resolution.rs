#[path = "benchmark_history_v3_label_resolution_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_label_resolution_commitment.rs"]
mod commitment;

pub use commitment::{
    prepare_historical_v3_label_resolution, resolve_historical_v3_label,
    validate_historical_v3_final_label, validate_historical_v3_label_resolution,
};

const RESOLUTION_TASK_CONTRACT: &str = "sniffbench-historical-v3-resolution-task-v1";
const FINAL_LABEL_CONTRACT: &str = "sniffbench-historical-v3-final-label-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_label_resolution_tests.rs"]
mod tests;
