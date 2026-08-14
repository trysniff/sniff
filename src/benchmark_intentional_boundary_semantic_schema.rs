use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryIndexerKind {
    TypeScriptJavaScript,
    Python,
    Go,
    Kotlin,
    Rust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticSymbolCategory {
    Unknown,
    Callable,
    Constructor,
    Method,
    Type,
    TraitOrInterface,
    Module,
    Namespace,
    Package,
    FieldOrProperty,
    Parameter,
    Variable,
    Constant,
    Macro,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticVisibility {
    Unknown,
    Private,
    Package,
    Protected,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticOrigin {
    Unknown,
    Repository,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticSurface {
    PublicApi,
    Entrypoint,
    Route,
    Command,
    Job,
    Callback,
    Plugin,
    FrameworkRegistration,
    Configuration,
    Schema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticUnresolvedReason {
    DynamicDispatch,
    Ambiguous,
    MissingDefinition,
    MissingIndexerFact,
    UnsupportedConstruct,
    ExternalContractUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticDispatch {
    Static,
    Virtual,
    Dynamic,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticRelationshipKind {
    Reference,
    Implementation,
    TypeDefinition,
    Definition,
    Override,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticOccurrenceRole {
    Definition,
    Import,
    Write,
    Read,
    Generated,
    Test,
    ForwardDefinition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticTestKind {
    Exercises,
    Mocks,
    Replaces,
    AssertsContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticRange {
    pub repository_path: String,
    pub start_line_zero_based: u32,
    pub start_character_zero_based: u32,
    pub end_line_zero_based: u32,
    pub end_character_zero_based: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticResolution<T> {
    Resolved {
        value: T,
    },
    Unresolved {
        reason: IntentionalBoundarySemanticUnresolvedReason,
        raw_target: Option<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticSymbolFacts {
    pub symbol_id: String,
    pub provider_identity: String,
    pub display_name: Option<String>,
    pub category: IntentionalBoundarySemanticSymbolCategory,
    pub provider_kind: String,
    pub documentation: Vec<String>,
    pub signature: Option<String>,
    pub signature_referenced_symbols: Vec<String>,
    pub owner: Option<IntentionalBoundarySemanticResolution<String>>,
    pub definitions: Vec<IntentionalBoundarySemanticRange>,
    pub visibility: IntentionalBoundarySemanticVisibility,
    pub surfaces: Vec<IntentionalBoundarySemanticSurface>,
    pub origin: IntentionalBoundarySemanticOrigin,
    pub ambiguity_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticOccurrenceFacts {
    pub location: IntentionalBoundarySemanticRange,
    pub roles: Vec<IntentionalBoundarySemanticOccurrenceRole>,
    pub override_documentation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticCallFacts {
    pub caller: String,
    pub callee: IntentionalBoundarySemanticResolution<String>,
    pub callsite: IntentionalBoundarySemanticRange,
    pub dispatch: IntentionalBoundarySemanticDispatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticRelationshipFacts {
    pub source: String,
    pub target: String,
    pub kind: IntentionalBoundarySemanticRelationshipKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticImportFacts {
    pub location: IntentionalBoundarySemanticRange,
    pub target: IntentionalBoundarySemanticResolution<String>,
    pub reexport: IntentionalBoundarySemanticResolution<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticTestFacts {
    pub test_symbol: String,
    pub production: IntentionalBoundarySemanticResolution<String>,
    pub kind: IntentionalBoundarySemanticTestKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticMethodStatus {
    Resolved {
        symbol: Box<IntentionalBoundarySemanticSymbolFacts>,
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
pub struct IntentionalBoundarySemanticMethod {
    pub parser_unit_id: String,
    pub repository_path: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub indexer: IntentionalBoundaryIndexerKind,
    pub status: IntentionalBoundarySemanticMethodStatus,
    pub occurrences: Vec<IntentionalBoundarySemanticOccurrenceFacts>,
    pub calls: Vec<IntentionalBoundarySemanticCallFacts>,
    pub relationships: Vec<IntentionalBoundarySemanticRelationshipFacts>,
    pub imports: Vec<IntentionalBoundarySemanticImportFacts>,
    pub test_relationships: Vec<IntentionalBoundarySemanticTestFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticIndexerCensus {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub tool_name: String,
    pub tool_version: Option<String>,
    pub semantic_facts_sha256: String,
    pub diagnostic_count: usize,
    pub diagnostics_sha256: String,
    pub document_count: usize,
    pub symbol_count: usize,
    pub relationship_count: usize,
    pub import_count: usize,
    pub call_count: usize,
    pub test_relationship_count: usize,
    pub unresolved_edge_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticCensus {
    pub schema_version: u32,
    pub semantic_contract: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub indexers: Vec<IntentionalBoundarySemanticIndexerCensus>,
    pub methods: Vec<IntentionalBoundarySemanticMethod>,
    pub resolved_method_count: usize,
    pub compiler_excluded_method_count: usize,
    pub unresolved_method_count: usize,
    pub semantic_census_sha256: String,
}
