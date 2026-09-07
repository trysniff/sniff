use super::{
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticUnresolvedReason,
};
use crate::semantic_index::{SemanticIndexVariant, SemanticPositionEncoding};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION: u32 = 18;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticIndexerVariantCensus {
    pub variant: SemanticIndexVariant,
    pub indexed_document_paths: Vec<String>,
    pub ignored_document_paths: Vec<String>,
    pub census: IntentionalBoundarySemanticIndexerCensus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum HistoricalV2SemanticVariantCondition {
    Unqualified,
    Qualified {
        dimensions: BTreeMap<String, String>,
    },
}

impl From<&SemanticIndexVariant> for HistoricalV2SemanticVariantCondition {
    fn from(variant: &SemanticIndexVariant) -> Self {
        match variant {
            SemanticIndexVariant::Unqualified => Self::Unqualified,
            SemanticIndexVariant::Qualified { dimensions, .. } => Self::Qualified {
                dimensions: dimensions.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticSymbol {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub variant: SemanticIndexVariant,
    pub is_public_surface: bool,
    pub is_public_root_evidence: bool,
    pub is_reexport_evidence: bool,
    pub symbol: IntentionalBoundarySemanticSymbolFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HistoricalV2SemanticMethodStatus {
    Resolved {
        symbol_id: String,
        joined_definition: Option<IntentionalBoundarySemanticRange>,
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
pub struct HistoricalV2SemanticMethodObservation {
    pub variant: SemanticIndexVariant,
    pub status: HistoricalV2SemanticMethodStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticMethod {
    pub parser_unit_id: String,
    pub repository_path: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub indexer: IntentionalBoundaryIndexerKind,
    pub observations: Vec<HistoricalV2SemanticMethodObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SemanticPublicBindingKind {
    Definition,
    Reference,
    ReexportExpansion,
    OwnerExpansion,
    PackageExposure,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticPublicBinding {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub variant: SemanticIndexVariant,
    pub surface_unit_id: String,
    pub declaration_unit_id: String,
    pub origin_declaration_unit_id: String,
    pub reexport_path: Vec<String>,
    pub repository_path: String,
    pub symbol_id: String,
    pub owner_symbol_id: Option<String>,
    pub exposing_owner_declaration_unit_id: Option<String>,
    pub package_exposure_id: Option<String>,
    pub binding: HistoricalV2SemanticPublicBindingKind,
    pub externally_reachable: bool,
    pub position_encoding: SemanticPositionEncoding,
    pub compiler_anchor: IntentionalBoundarySemanticRange,
    pub owner_compiler_anchor: Option<IntentionalBoundarySemanticRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticPublicReexportHop {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub variant: SemanticIndexVariant,
    pub reexport_unit_id: String,
    pub repository_path: String,
    pub target_repository_path: String,
    pub module_symbol_id: String,
    pub position_encoding: SemanticPositionEncoding,
    pub compiler_anchor: IntentionalBoundarySemanticRange,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticPublicRoot {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub variant: SemanticIndexVariant,
    pub repository_path: String,
    pub module_symbol_id: String,
    pub compiler_definition: IntentionalBoundarySemanticRange,
    pub origin: HistoricalV2SemanticPublicRootOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HistoricalV2SemanticPublicRootOrigin {
    RustCargoLibrary,
    NodePackageExposure {
        exposure_id: String,
        surface_slot_id: String,
    },
    PythonDistributionModule {
        module_exposure_id: String,
        surface_slot_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticGoPackageRoot {
    pub variant: SemanticIndexVariant,
    pub variant_target_ids: Vec<String>,
    pub surface_slot_id: String,
    pub module_path: String,
    pub import_path: String,
    pub source_repository_paths: Vec<String>,
    pub ignored_source_repository_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticSnapshotCensus {
    pub revision: String,
    pub source_snapshot_census_sha256: String,
    pub required_document_paths: Vec<String>,
    pub public_surface_document_paths: Vec<String>,
    pub indexers: Vec<HistoricalV2SemanticIndexerVariantCensus>,
    pub methods: Vec<HistoricalV2SemanticMethod>,
    pub public_bindings: Vec<HistoricalV2SemanticPublicBinding>,
    pub public_roots: Vec<HistoricalV2SemanticPublicRoot>,
    pub go_package_roots: Vec<HistoricalV2SemanticGoPackageRoot>,
    pub public_reexport_hops: Vec<HistoricalV2SemanticPublicReexportHop>,
    pub symbols: Vec<HistoricalV2SemanticSymbol>,
    pub symbol_count: usize,
    pub public_binding_count: usize,
    pub public_root_count: usize,
    pub go_package_root_count: usize,
    pub public_reexport_hop_count: usize,
    pub public_symbol_count: usize,
    pub resolved_method_count: usize,
    pub compiler_excluded_method_count: usize,
    pub unresolved_method_count: usize,
    pub semantic_snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticCensus {
    pub schema_version: u32,
    pub semantic_census_contract: String,
    pub canonical_repository: String,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub changed_indexers: Vec<IntentionalBoundaryIndexerKind>,
    pub base: HistoricalV2SemanticSnapshotCensus,
    pub patched: HistoricalV2SemanticSnapshotCensus,
    pub semantic_census_sha256: String,
}
