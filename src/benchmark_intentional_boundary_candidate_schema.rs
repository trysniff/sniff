use super::{BoundaryEvidenceKind, IntentionalBoundaryCategory};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryCandidate {
    pub candidate_id: String,
    pub category: IntentionalBoundaryCategory,
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub exact_symbol_identity: String,
    pub evidence_kinds: Vec<BoundaryEvidenceKind>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryCandidateCensus {
    pub schema_version: u32,
    pub candidate_contract: String,
    pub protocol_sha256: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub evidence_census_sha256: String,
    pub candidates: Vec<IntentionalBoundaryCandidate>,
    pub candidate_count_by_category: BTreeMap<IntentionalBoundaryCategory, usize>,
    pub candidate_census_sha256: String,
}
