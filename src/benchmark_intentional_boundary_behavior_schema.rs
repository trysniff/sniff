use super::{IntentionalBoundaryBehaviorTestProofKind, IntentionalBoundarySemanticTestKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryBehaviorProvider {
    CargoTest,
    Pytest,
    GoTest,
    JavaScriptTest,
    GradleTest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum IntentionalBoundaryBehaviorSelector {
    CargoTest {
        test_name: String,
    },
    Pytest {
        repository_path: String,
        test_name: String,
    },
    GoTest {
        package_repository_path: String,
        test_name: String,
    },
    JavaScriptTest {
        repository_path: String,
        test_name: String,
    },
    GradleTest {
        repository_path: String,
        test_name: String,
    },
}

impl IntentionalBoundaryBehaviorSelector {
    pub fn provider(&self) -> IntentionalBoundaryBehaviorProvider {
        match self {
            Self::CargoTest { .. } => IntentionalBoundaryBehaviorProvider::CargoTest,
            Self::Pytest { .. } => IntentionalBoundaryBehaviorProvider::Pytest,
            Self::GoTest { .. } => IntentionalBoundaryBehaviorProvider::GoTest,
            Self::JavaScriptTest { .. } => IntentionalBoundaryBehaviorProvider::JavaScriptTest,
            Self::GradleTest { .. } => IntentionalBoundaryBehaviorProvider::GradleTest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryBehaviorUnresolvedReason {
    ProductionRelationshipUnresolved,
    TestSymbolUnresolved,
    TestMethodUnavailable,
    UnsupportedTargetSelector,
    RecipeUnavailable,
    RecipeMismatch,
    RuntimeUnavailable,
    SandboxUnavailable,
    PreparationFailed,
    TargetedTestFailed,
    TargetCountMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryBehaviorWitnessOutcome {
    Passed {
        proof: IntentionalBoundaryBehaviorTestProofKind,
        execution_id: String,
    },
    Unresolved {
        reason: IntentionalBoundaryBehaviorUnresolvedReason,
        detail: String,
        execution_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryBehaviorWitness {
    pub witness_id: String,
    pub candidate_id: String,
    pub production_parser_unit_id: String,
    pub production_symbol_id: String,
    pub test_parser_unit_id: Option<String>,
    pub test_symbol_id: String,
    pub relationship_kind: IntentionalBoundarySemanticTestKind,
    pub selector: Option<IntentionalBoundaryBehaviorSelector>,
    pub outcome: IntentionalBoundaryBehaviorWitnessOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryBehaviorCandidateStatus {
    Passed { witness_ids: Vec<String> },
    NoResolvedBehaviorTest,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryBehaviorCandidate {
    pub candidate_id: String,
    pub production_parser_unit_id: String,
    pub production_symbol_id: String,
    pub status: IntentionalBoundaryBehaviorCandidateStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryBehaviorExecution {
    pub execution_id: String,
    pub revision: String,
    pub provider: IntentionalBoundaryBehaviorProvider,
    pub selector: IntentionalBoundaryBehaviorSelector,
    pub recipe_sha256: String,
    pub recipe_json: String,
    pub command: Vec<String>,
    pub runtime_identity_sha256: String,
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub network_enabled: bool,
    pub test_executed: bool,
    pub executed_test_count: usize,
    pub matched_test_count: usize,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub raw_result_sha256: String,
    pub raw_result_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryBehaviorCensus {
    pub schema_version: u32,
    pub behavior_contract: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub base_evidence_census_sha256: String,
    pub candidates: Vec<IntentionalBoundaryBehaviorCandidate>,
    pub witnesses: Vec<IntentionalBoundaryBehaviorWitness>,
    pub executions: Vec<IntentionalBoundaryBehaviorExecution>,
    pub candidate_count_by_status: BTreeMap<String, usize>,
    pub witness_count_by_status: BTreeMap<String, usize>,
    pub behavior_census_sha256: String,
}
