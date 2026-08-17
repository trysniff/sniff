use serde::{Deserialize, Serialize};
use std::path::Path;

pub const HISTORICAL_V2_IDENTICAL_TEST_PLAN_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExecutionPolicy {
    pub platform: String,
    pub cpu_limit_millis: u64,
    pub memory_limit_bytes: u64,
    pub process_limit: u64,
    pub temporary_filesystem_bytes: u64,
    pub install_command_timeout_seconds: u64,
    pub test_timeout_seconds: u64,
    pub retained_output_bytes: usize,
    pub install_network_enabled: bool,
    pub test_network_enabled: bool,
    pub ephemeral_root_filesystem: bool,
    pub host_source_mounts_forbidden: bool,
    pub all_capabilities_dropped: bool,
    pub no_new_privileges: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2IdenticalTestPlan {
    pub schema_version: u32,
    pub plan_contract: String,
    pub assessment_identity_sha256: String,
    pub qualification_sha256: String,
    pub test_recipe_sha256: String,
    pub execution_harness_sha256: String,
    pub materialization_sha256: String,
    pub test_materialization_sha256: Option<String>,
    pub language: String,
    pub slot_number: usize,
    pub canonical_repository: String,
    pub base_commit_oid: String,
    pub patched_commit_oid: String,
    pub base_image_name: String,
    pub dockerfile_path: String,
    pub dockerfile_blob_oid: String,
    pub install_commands: Vec<String>,
    pub install_command_sha256: Vec<String>,
    pub test_commands: Vec<String>,
    pub test_script_sha256: String,
    pub policy: HistoricalV2ExecutionPolicy,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2ExecutionSide {
    Base,
    Patched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2ExecutionPhase {
    Install,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExecutionCommandEvidence {
    pub side: HistoricalV2ExecutionSide,
    pub phase: HistoricalV2ExecutionPhase,
    pub command_index: usize,
    pub command_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_millis: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub retained_stdout: String,
    pub retained_stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2IdenticalTestExclusionReason {
    InstallCommandFailed {
        side: HistoricalV2ExecutionSide,
        command_index: usize,
    },
    InstallCommandTimedOut {
        side: HistoricalV2ExecutionSide,
        command_index: usize,
    },
    TestCommandsFailed {
        side: HistoricalV2ExecutionSide,
    },
    TestCommandsTimedOut {
        side: HistoricalV2ExecutionSide,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2IdenticalTestOutcome {
    Passed,
    Excluded {
        reason: HistoricalV2IdenticalTestExclusionReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2RawIdenticalTestExecution {
    pub image_id: String,
    pub events: Vec<HistoricalV2ExecutionCommandEvidence>,
    pub outcome: HistoricalV2IdenticalTestOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2IdenticalTestExecution {
    pub schema_version: u32,
    pub execution_contract: String,
    pub plan_sha256: String,
    pub image_id: String,
    pub events: Vec<HistoricalV2ExecutionCommandEvidence>,
    pub outcome: HistoricalV2IdenticalTestOutcome,
    pub execution_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalV2ExecutionErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2ExecutionError {
    pub kind: HistoricalV2ExecutionErrorKind,
    pub detail: String,
}

pub struct HistoricalV2IdenticalTestExecutionRequest<'a> {
    pub plan: &'a HistoricalV2IdenticalTestPlan,
    pub harness_repository_root: &'a Path,
    pub repository_root: &'a Path,
}

pub trait HistoricalV2IdenticalTestExecutor {
    fn execute(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV2RawIdenticalTestExecution, HistoricalV2ExecutionError>;
}

pub trait HistoricalV2RecoverableTestExecutor: HistoricalV2IdenticalTestExecutor {
    fn recover(
        &self,
        plan: &HistoricalV2IdenticalTestPlan,
    ) -> Result<(), HistoricalV2ExecutionError>;
}
