use super::super::{
    BoundaryGitEntryKind, HistoricalV3RankIdentity, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySourceCensus, IntentionalBoundarySourceCensusFailureEvidence,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_SOURCE_CENSUS_SCHEMA_VERSION: u32 = 3;
pub const HISTORICAL_V3_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3SourceSide {
    Base,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3SourceCensusExclusionReason {
    NoSupportedSources,
    UnsupportedProjectShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceMethodFacts {
    pub parser_unit_id: String,
    pub source_sha256: String,
    pub non_whitespace_line_count: usize,
    pub syntax_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceFileFacts {
    pub repository_path: String,
    pub source_sha256: String,
    pub non_whitespace_line_count: usize,
    pub syntax_sha256: String,
    pub methods: Vec<HistoricalV3SourceMethodFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3RecipeInputInterpretation {
    Opaque,
    YarnLock {
        generation: HistoricalV3YarnLockGeneration,
    },
    NodePackage {
        has_test_script: bool,
    },
    PythonProject {
        has_pytest_configuration: bool,
    },
    PythonRequirements {
        hash_locked: bool,
        contains_pytest: bool,
    },
    GradleWrapperProperties {
        distribution_sha256: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3YarnLockGeneration {
    Classic,
    Berry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3RecipeInputStatus {
    Committed {
        content_sha256: String,
        interpretation: HistoricalV3RecipeInputInterpretation,
    },
    InvalidContent {
        content_sha256: String,
    },
    FileTooLarge,
    TotalLimitExceeded,
    UnsupportedEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3RecipeInputFact {
    pub repository_path: String,
    pub mode: String,
    pub entry_kind: BoundaryGitEntryKind,
    pub object_id: String,
    pub byte_length: Option<u64>,
    pub input_status: HistoricalV3RecipeInputStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceSnapshot {
    pub side: HistoricalV3SourceSide,
    pub revision: String,
    pub inventory: IntentionalBoundaryRepositoryInventory,
    pub source_census: IntentionalBoundarySourceCensus,
    pub source_file_facts: Vec<HistoricalV3SourceFileFacts>,
    pub recipe_input_facts: Vec<HistoricalV3RecipeInputFact>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3SourceSnapshotEvidence {
    Completed {
        snapshot: Box<HistoricalV3SourceSnapshot>,
    },
    Excluded {
        side: HistoricalV3SourceSide,
        revision: String,
        inventory: Box<IntentionalBoundaryRepositoryInventory>,
        reason: HistoricalV3SourceCensusExclusionReason,
        failures: Vec<IntentionalBoundarySourceCensusFailureEvidence>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceCensus {
    pub schema_version: u32,
    pub source_census_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_extension_contract: String,
    pub base: HistoricalV3SourceSnapshot,
    pub merge: HistoricalV3SourceSnapshot,
    pub source_census_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_extension_contract: String,
    pub sides: Vec<HistoricalV3SourceSnapshotEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3SourceCensusOutcome {
    Completed(Box<HistoricalV3SourceCensus>),
    Excluded(Box<HistoricalV3SourceCensusExclusion>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3SourceCensusStageRun {
    Completed {
        artifact: Box<HistoricalV3SourceCensus>,
        resumed: bool,
    },
    Excluded {
        artifact: Box<HistoricalV3SourceCensusExclusion>,
        resumed: bool,
    },
}
