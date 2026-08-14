use super::{IntentionalBoundarySemanticRange, IntentionalBoundarySemanticUnresolvedReason};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntentionalBoundaryAstFact {
    ThinDelegation {
        call_expression: IntentionalBoundarySemanticRange,
        compiler_callsite: IntentionalBoundarySemanticRange,
        resolved_callee_symbol_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryAstMethodStatus {
    Resolved {
        subject_symbol_id: String,
        facts: Vec<IntentionalBoundaryAstFact>,
    },
    CompilerExcluded {
        reason: String,
    },
    Unresolved {
        reason: IntentionalBoundarySemanticUnresolvedReason,
        raw_target: Option<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryAstMethod {
    pub parser_unit_id: String,
    pub repository_path: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub status: IntentionalBoundaryAstMethodStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryAstCensus {
    pub schema_version: u32,
    pub ast_contract: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub languages: Vec<String>,
    pub methods: Vec<IntentionalBoundaryAstMethod>,
    pub method_count: usize,
    pub fact_count: usize,
    pub ast_census_sha256: String,
}
