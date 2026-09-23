use super::super::{HistoricalV3RankIdentity, HistoricalV3TestRecipe};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const HISTORICAL_V3_IDENTICAL_TESTS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3ExecutionSide {
    Base,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3ExecutionPhase {
    Preparation,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ExecutionCommandEvidence {
    pub side: HistoricalV3ExecutionSide,
    pub phase: HistoricalV3ExecutionPhase,
    pub command_index: usize,
    pub command_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_millis: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_byte_count: u64,
    pub stderr_byte_count: u64,
    pub retained_stdout_base64: String,
    pub retained_stderr_base64: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3IdenticalTestExclusionReason {
    PreparationFailed {
        side: HistoricalV3ExecutionSide,
        command_index: usize,
    },
    PreparationTimedOut {
        side: HistoricalV3ExecutionSide,
        command_index: usize,
    },
    TestFailed {
        side: HistoricalV3ExecutionSide,
    },
    TestTimedOut {
        side: HistoricalV3ExecutionSide,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3IdenticalTestOutcome {
    Passed,
    Excluded {
        reason: HistoricalV3IdenticalTestExclusionReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3RawIdenticalTestExecution {
    pub image_digest: String,
    pub toolchain_manifest_sha256: String,
    pub dependency_store_sha256: String,
    pub events: Vec<HistoricalV3ExecutionCommandEvidence>,
    pub outcome: HistoricalV3IdenticalTestOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3IdenticalTests {
    pub schema_version: u32,
    pub execution_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub test_recipe_sha256: String,
    pub execution_policy_sha256: String,
    pub execution_identity_sha256: String,
    pub image_digest: String,
    pub toolchain_manifest_sha256: String,
    pub dependency_store_sha256: String,
    pub events: Vec<HistoricalV3ExecutionCommandEvidence>,
    pub outcome: HistoricalV3IdenticalTestOutcome,
    pub execution_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3IdenticalTestsStageRun {
    Passed {
        artifact: Box<HistoricalV3IdenticalTests>,
        resumed: bool,
    },
    Excluded {
        artifact: Box<HistoricalV3IdenticalTests>,
        resumed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalV3IdenticalTestExecutionErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3IdenticalTestExecutionError {
    pub kind: HistoricalV3IdenticalTestExecutionErrorKind,
    pub detail: String,
}

pub struct HistoricalV3IdenticalTestExecutionRequest<'a> {
    pub execution_identity_sha256: &'a str,
    pub recipe: &'a HistoricalV3TestRecipe,
    pub base_root: &'a Path,
    pub merge_root: &'a Path,
    pub retained_output_bytes: usize,
    pub preparation_command_timeout_seconds: u64,
    pub test_command_timeout_seconds: u64,
}

pub trait HistoricalV3IdenticalTestExecutor {
    fn recover(
        &self,
        execution_identity_sha256: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError>;

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>;
}
