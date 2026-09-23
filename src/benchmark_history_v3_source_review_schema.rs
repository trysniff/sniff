use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3ExecutionPhase, HistoricalV3ExecutionSide,
    HistoricalV3IdenticalTests, HistoricalV3Materialization, HistoricalV3MechanicalQualification,
    HistoricalV3Protocol, HistoricalV3RecipeCommand, HistoricalV3SemanticCensus,
    HistoricalV3SimplificationKind, HistoricalV3SourceCensus, HistoricalV3SourceSide,
    HistoricalV3TestRecipe, IntentionalBoundarySemanticMethod,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const HISTORICAL_V3_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy)]
pub struct HistoricalV3SourceReviewInputs<'a> {
    pub protocol: &'a HistoricalV3Protocol,
    pub collection: &'a HistoricalV3CandidateCollection,
    pub materialization: &'a HistoricalV3Materialization,
    pub source_census: &'a HistoricalV3SourceCensus,
    pub semantic_census: &'a HistoricalV3SemanticCensus,
    pub qualification: &'a HistoricalV3MechanicalQualification,
    pub recipe: &'a HistoricalV3TestRecipe,
    pub execution: &'a HistoricalV3IdenticalTests,
}

#[derive(Debug, Clone, Copy)]
pub struct HistoricalV3SourceReviewRoots<'a> {
    pub base_root: &'a Path,
    pub merge_root: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewMethod {
    pub side: HistoricalV3SourceSide,
    pub language: String,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub source: String,
    pub semantic: IntentionalBoundarySemanticMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewCommandResult {
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
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewBehaviorEvidence {
    pub preparation_commands: Vec<HistoricalV3RecipeCommand>,
    pub test_command: HistoricalV3RecipeCommand,
    pub execution_platform: String,
    pub image_digest: String,
    pub toolchain_manifest_sha256: String,
    pub dependency_store_sha256: String,
    pub results: Vec<HistoricalV3ReviewCommandResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceReviewBundle {
    pub schema_version: u32,
    pub bundle_contract: String,
    pub review_item_id: String,
    pub language: String,
    pub source_only: bool,
    pub repository_identity_included: bool,
    pub change_metadata_included: bool,
    pub sniff_output_included: bool,
    pub prior_labels_included: bool,
    pub public_surface_preserved: bool,
    pub public_surface_delta_sha256: String,
    pub simplifications: Vec<HistoricalV3SimplificationKind>,
    pub methods: Vec<HistoricalV3ReviewMethod>,
    pub behavior: HistoricalV3ReviewBehaviorEvidence,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3SourceReviewStageRun {
    pub artifact: Box<HistoricalV3SourceReviewBundle>,
    pub resumed: bool,
}
