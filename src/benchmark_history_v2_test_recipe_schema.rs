use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2TestRecipeExclusionReason {
    MissingInstallConfig,
    InvalidInstallConfigJson,
    InvalidBaseImageName,
    TooManyInstallCommands,
    InvalidInstallCommand,
    InvalidTestCommand,
    InvalidLogParser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2TestRecipeOutcome {
    Selected {
        base_image_name: String,
        install_commands: Vec<String>,
        test_command: String,
        log_parser: String,
    },
    Excluded {
        reason: HistoricalV2TestRecipeExclusionReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2TestRecipe {
    pub schema_version: u32,
    pub test_recipe_contract: String,
    pub assessment_identity_sha256: String,
    pub qualification_sha256: String,
    pub install_config_sha256: Option<String>,
    pub outcome: HistoricalV2TestRecipeOutcome,
    pub test_recipe_sha256: String,
}
