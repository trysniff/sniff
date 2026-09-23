use super::super::{HistoricalV3RankIdentity, HistoricalV3TestRecipeSelector};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V3_TEST_RECIPE_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_TEST_RECIPE_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3RecipeCommand {
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3TestRecipeInputBinding {
    pub repository_path: String,
    pub base_object_id: String,
    pub merge_object_id: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3TestRecipeExclusionReason {
    MissingRecipeInputs,
    ChangedRecipeInputs,
    AmbiguousRecipeInputs,
    InvalidRecipeInput,
    InputFileTooLarge,
    InputTotalTooLarge,
    UnsupportedInputKind,
    NoTestsDeclared,
    UnreproducibleDependencies,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3TestRecipe {
    pub schema_version: u32,
    pub recipe_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub qualification_sha256: String,
    pub selector: HistoricalV3TestRecipeSelector,
    pub execution_platform: String,
    pub image_digest: String,
    pub toolchain_manifest_sha256: String,
    pub dependency_store_sha256: String,
    pub preparation_commands: Vec<HistoricalV3RecipeCommand>,
    pub test_command: HistoricalV3RecipeCommand,
    pub runtime_program: String,
    pub inputs: Vec<HistoricalV3TestRecipeInputBinding>,
    pub changed_method_count: usize,
    pub changed_methods_sha256: String,
    pub command_identity_sha256: String,
    pub toolchain_identity_sha256: String,
    pub recipe_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3TestRecipeExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub qualification_sha256: String,
    pub recipe_inputs_sha256: String,
    pub reason: HistoricalV3TestRecipeExclusionReason,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3TestRecipeOutcome {
    Selected(Box<HistoricalV3TestRecipe>),
    Excluded(Box<HistoricalV3TestRecipeExclusion>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3TestRecipeStageRun {
    Selected {
        artifact: Box<HistoricalV3TestRecipe>,
        resumed: bool,
    },
    Excluded {
        artifact: Box<HistoricalV3TestRecipeExclusion>,
        resumed: bool,
    },
}
