#[path = "benchmark_history_v3_test_recipe_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_test_recipe_selector.rs"]
mod selector;

#[path = "benchmark_history_v3_test_recipe_commitment.rs"]
mod commitment;

pub use commitment::{
    derive_historical_v3_test_recipe, validate_historical_v3_test_recipe,
    validate_historical_v3_test_recipe_exclusion,
};

#[path = "benchmark_history_v3_test_recipe_store.rs"]
mod store;

#[path = "benchmark_history_v3_test_recipe_runtime.rs"]
mod runtime;

pub use runtime::run_historical_v3_test_recipe_stage;

pub(super) const TEST_RECIPE_CONTRACT: &str = "sniffbench-historical-v3-test-recipe-v1";
pub(super) const TEST_RECIPE_EXCLUSION_CONTRACT: &str =
    "sniffbench-historical-v3-test-recipe-exclusion-v1";

#[cfg(test)]
#[path = "benchmark_history_v3_test_recipe_tests.rs"]
mod tests;
