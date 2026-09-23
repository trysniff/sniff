#[path = "benchmark_history_v3_source_review_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_source_review_commitment.rs"]
mod commitment;

pub use commitment::{
    build_historical_v3_source_review_bundle, validate_historical_v3_source_review_bundle,
};

#[path = "benchmark_history_v3_source_review_store.rs"]
mod store;

#[path = "benchmark_history_v3_source_review_runtime.rs"]
mod runtime;

pub use runtime::run_historical_v3_source_review_stage;

#[path = "benchmark_history_v3_source_review_proof.rs"]
mod proof;

pub use proof::{HistoricalV3VerifiedSourceReview, verify_historical_v3_source_review_rank};

const SOURCE_REVIEW_BUNDLE_CONTRACT: &str = "sniffbench-historical-v3-source-review-bundle-v1";
const REVIEW_ITEM_CONTRACT: &str = "sniffbench-historical-v3-review-item-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_source_review_tests.rs"]
mod tests;
