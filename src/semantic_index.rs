use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SEMANTIC_INDEX_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticSymbolId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepositoryPath(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticIndex {
    pub format_version: u32,
    pub repository_root: String,
    pub provenance: SemanticIndexProvenance,
    pub documents: BTreeMap<RepositoryPath, SemanticDocument>,
    pub symbols: BTreeMap<SemanticSymbolId, SemanticSymbol>,
    pub relationships: BTreeSet<SemanticRelationship>,
    pub imports: BTreeSet<SemanticImportEdge>,
    pub calls: BTreeSet<SemanticCallEdge>,
    pub test_relationships: BTreeSet<SemanticTestRelationship>,
    pub unresolved_edges: BTreeSet<SemanticUnresolvedEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticIndexProvenance {
    pub format: String,
    pub tool_name: String,
    pub tool_version: Option<String>,
    pub arguments: Vec<String>,
    pub source_text_encoding: Option<SemanticTextEncoding>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDocument {
    pub path: RepositoryPath,
    pub language: String,
    pub position_encoding: SemanticPositionEncoding,
    pub embedded_text: Option<String>,
    pub occurrences: Vec<SemanticOccurrence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticPositionEncoding {
    Utf8,
    Utf16,
    Utf32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTextEncoding {
    Utf8,
    Utf16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticPosition {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticSourceRange {
    pub start: SemanticPosition,
    pub end: SemanticPosition,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticLocation {
    pub document: RepositoryPath,
    pub range: SemanticSourceRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticOccurrence {
    pub range: SemanticSourceRange,
    pub symbol: Option<SemanticSymbolId>,
    pub roles: BTreeSet<SemanticOccurrenceRole>,
    pub override_documentation: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticOccurrenceRole {
    Definition,
    Import,
    Write,
    Read,
    Generated,
    Test,
    ForwardDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSymbol {
    pub id: SemanticSymbolId,
    pub provider_identity: String,
    pub display_name: Option<String>,
    pub kind: SemanticSymbolKind,
    pub documentation: Vec<String>,
    pub signature: Option<SemanticSignature>,
    pub owner: Option<SemanticResolution<SemanticSymbolId>>,
    pub definitions: BTreeSet<SemanticLocation>,
    pub visibility: SemanticVisibility,
    pub surfaces: BTreeSet<SemanticSurface>,
    pub origin: SemanticSymbolOrigin,
    pub ambiguity_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSymbolKind {
    pub category: SemanticSymbolCategory,
    pub provider_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSymbolCategory {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSignature {
    pub language: String,
    pub text: String,
    pub referenced_symbols: BTreeSet<SemanticSymbolId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticVisibility {
    Unknown,
    Private,
    Package,
    Protected,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSymbolOrigin {
    Unknown,
    Repository,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSurface {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticRelationship {
    pub source: SemanticSymbolId,
    pub target: SemanticSymbolId,
    pub kind: SemanticRelationshipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelationshipKind {
    Reference,
    Implementation,
    TypeDefinition,
    Definition,
    Override,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticImportEdge {
    pub document: RepositoryPath,
    pub range: SemanticSourceRange,
    pub target: SemanticResolution<SemanticSymbolId>,
    pub reexport: SemanticResolution<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticCallEdge {
    pub caller: SemanticSymbolId,
    pub callsite: SemanticLocation,
    pub callee: SemanticResolution<SemanticSymbolId>,
    pub dispatch: SemanticDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDispatch {
    Static,
    Virtual,
    Dynamic,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticTestRelationship {
    pub test: SemanticSymbolId,
    pub production: SemanticResolution<SemanticSymbolId>,
    pub kind: SemanticTestRelationshipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTestRelationshipKind {
    Exercises,
    Mocks,
    Replaces,
    AssertsContract,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SemanticResolution<T> {
    Resolved {
        value: T,
    },
    Unresolved {
        reason: SemanticUnresolvedReason,
        raw_target: Option<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticUnresolvedReason {
    DynamicDispatch,
    Ambiguous,
    MissingDefinition,
    MissingIndexerFact,
    UnsupportedConstruct,
    ExternalContractUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticUnresolvedEdge {
    pub source: Option<SemanticSymbolId>,
    pub location: SemanticLocation,
    pub edge_kind: SemanticUnresolvedEdgeKind,
    pub reason: SemanticUnresolvedReason,
    pub raw_target: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticUnresolvedEdgeKind {
    Call,
    Import,
    Reexport,
    Ownership,
    Implementation,
    TestProduction,
}
