use super::HistoricalV2GitCommandRejectionEvidence;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2TestMaterializationSide {
    Base,
    Patched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2TestMaterializationExclusionReason {
    TestPatchDoesNotApply,
    TestPatchProducesNoTreeChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2TestPatchRejectionEvidence {
    pub side: HistoricalV2TestMaterializationSide,
    pub command: HistoricalV2GitCommandRejectionEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2TestMaterializationExclusionEvidence {
    TestPatchRejected {
        test_patch_sha256: String,
        rejections: Vec<HistoricalV2TestPatchRejectionEvidence>,
    },
    TestPatchProducesNoTreeChange {
        test_patch_sha256: String,
        unchanged_sides: Vec<HistoricalV2TestMaterializationSide>,
        base_input_tree_oid: String,
        base_test_tree_oid: String,
        patched_input_tree_oid: String,
        patched_test_tree_oid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2TestMaterializationExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub materialization_sha256: String,
    pub test_patch_sha256: String,
    pub reason: HistoricalV2TestMaterializationExclusionReason,
    pub evidence: HistoricalV2TestMaterializationExclusionEvidence,
    pub exclusion_sha256: String,
}
