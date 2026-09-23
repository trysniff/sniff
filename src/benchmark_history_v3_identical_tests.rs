#[path = "benchmark_history_v3_identical_tests_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_identical_tests_commitment.rs"]
mod commitment;

pub use commitment::{
    historical_v3_execution_identity_sha256, validate_historical_v3_identical_tests,
};

#[path = "benchmark_history_v3_identical_tests_store.rs"]
mod store;

#[path = "benchmark_history_v3_identical_tests_runtime.rs"]
mod runtime;

pub use runtime::run_historical_v3_identical_tests_stage;

#[path = "benchmark_history_v3_identical_tests_docker_support.rs"]
mod docker_support;

#[path = "benchmark_history_v3_identical_tests_docker.rs"]
mod docker;

pub use docker::DockerHistoricalV3TestExecutor;

const IDENTICAL_TESTS_CONTRACT: &str = "sniffbench-historical-v3-identical-tests-v1";

impl HistoricalV3IdenticalTestExecutionError {
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self {
            kind: HistoricalV3IdenticalTestExecutionErrorKind::InvalidInput,
            detail: detail.into(),
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            kind: HistoricalV3IdenticalTestExecutionErrorKind::InfrastructureUnavailable,
            detail: detail.into(),
        }
    }

    pub fn infrastructure(detail: impl Into<String>) -> Self {
        Self {
            kind: HistoricalV3IdenticalTestExecutionErrorKind::InfrastructureFailed,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for HistoricalV3IdenticalTestExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for HistoricalV3IdenticalTestExecutionError {}

#[cfg(test)]
#[path = "benchmark_history_v3_identical_tests_tests.rs"]
pub(crate) mod tests;
