#[path = "benchmark_history_v3_label_review_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_label_review_commitment.rs"]
mod commitment;

#[path = "benchmark_history_v3_label_review_validation.rs"]
mod validation;

pub(super) fn validate_historical_v3_review_decision(
    task: &HistoricalV3LabelTask,
    decision: &HistoricalV3ReviewDecision,
) -> Result<(), String> {
    validation::validate_decision(task, decision)
}

pub use commitment::{
    audit_historical_v3_label_reviews, prepare_historical_v3_label_review,
    validate_historical_v3_label_audit, validate_historical_v3_label_review,
};

#[path = "benchmark_history_v3_label_review_store.rs"]
mod store;

pub use store::{read_historical_v3_label_worksheet, write_historical_v3_label_worksheet_new};

const LABEL_TASK_CONTRACT: &str = "sniffbench-historical-v3-label-task-v1";
const LABEL_AUDIT_CONTRACT: &str = "sniffbench-historical-v3-label-audit-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_label_review_tests.rs"]
pub(crate) mod tests;
