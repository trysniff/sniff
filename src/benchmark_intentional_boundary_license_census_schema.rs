use super::BoundaryGitEntryKind;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_LICENSE_CENSUS_STAGE_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_LICENSE_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryLicenseFilenameRule {
    RootLicense,
    RootLicensePreferredExtension,
    RootCopying,
    RootCopyingPreferredExtension,
    RootLicenseOtherExtension,
    RootCopyingAnyExtension,
    RootLicenseDescriptor,
    RootCopyingDescriptor,
    RootPrefixedLicense,
    RootPrefixedCopying,
    RootOflPreferredExtension,
    RootOflOtherExtension,
    RootOfl,
    RootCopyright,
    RootCopyrightPreferredExtension,
    RootCopyrightOtherExtension,
    RootCopyrightDescriptor,
    RootPatents,
    RootPatentsOtherExtension,
    LicensesSpdxLike,
    LicensesLicenseRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLicenseArtifact {
    pub repository_path: String,
    pub object_id: String,
    pub byte_length: u64,
    pub content_sha256: String,
    pub filename_rule: IntentionalBoundaryLicenseFilenameRule,
    pub filename_score_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentionalBoundaryLicenseCandidateRejection {
    EmptyOrWhitespace {
        repository_path: String,
        object_id: String,
        byte_length: u64,
        content_sha256: String,
        filename_rule: IntentionalBoundaryLicenseFilenameRule,
        filename_score_basis_points: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentionalBoundaryLicenseFailureEvidence {
    CandidateIsNotBlob {
        repository_path: String,
        object_id: String,
        entry_kind: BoundaryGitEntryKind,
        filename_rule: IntentionalBoundaryLicenseFilenameRule,
        filename_score_basis_points: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryLicenseCensusExclusionReason {
    MissingLicense,
    UnsupportedProjectShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLicenseCensusStage {
    pub schema_version: u32,
    pub stage_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub filename_contract: String,
    pub tracked_entry_count: usize,
    pub matched_candidate_count: usize,
    pub license_artifacts: Vec<IntentionalBoundaryLicenseArtifact>,
    pub rejected_candidates: Vec<IntentionalBoundaryLicenseCandidateRejection>,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLicenseCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub repository: String,
    pub revision: String,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub filename_contract: String,
    pub reason: IntentionalBoundaryLicenseCensusExclusionReason,
    pub tracked_entry_count: usize,
    pub matched_candidate_count: usize,
    pub rejected_candidates: Vec<IntentionalBoundaryLicenseCandidateRejection>,
    pub failures: Vec<IntentionalBoundaryLicenseFailureEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundaryLicenseCensusStageOutcome {
    Completed(IntentionalBoundaryLicenseCensusStage),
    Excluded(IntentionalBoundaryLicenseCensusExclusion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryLicenseCensusStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryLicenseCensusStageError {
    pub kind: IntentionalBoundaryLicenseCensusStageErrorKind,
    pub detail: String,
}
