use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SEMANTIC_INDEX_FORMAT_VERSION: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticSymbolId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepositoryPath(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticVariantId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SemanticIndexVariant {
    Unqualified,
    Qualified {
        identity: SemanticVariantId,
        dimensions: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIndexerVariantPlan {
    pub identity: SemanticVariantId,
    pub dimensions: BTreeMap<String, String>,
    pub environment: BTreeMap<String, String>,
    pub compiler_project: Option<RepositoryPath>,
    pub selected_documents: BTreeSet<RepositoryPath>,
    pub ignored_documents: BTreeSet<RepositoryPath>,
}

impl SemanticIndexerVariantPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.identity.0.trim().is_empty()
            || self.dimensions.is_empty()
            || self
                .dimensions
                .iter()
                .any(|(name, value)| name.trim().is_empty() || value.trim().is_empty())
            || self
                .environment
                .iter()
                .any(|(name, value)| name.trim().is_empty() || value.contains('\0'))
            || self
                .compiler_project
                .as_ref()
                .is_some_and(|path| !is_canonical_repository_path(&path.0))
            || self
                .selected_documents
                .iter()
                .chain(&self.ignored_documents)
                .any(|path| !is_canonical_repository_path(&path.0))
            || !self.selected_documents.is_disjoint(&self.ignored_documents)
        {
            return Err(format!(
                "semantic compiler variant plan {} is incomplete",
                self.identity.0
            ));
        }
        Ok(())
    }

    pub fn index_variant(&self) -> SemanticIndexVariant {
        SemanticIndexVariant::Qualified {
            identity: self.identity.clone(),
            dimensions: self.dimensions.clone(),
        }
    }
}

fn is_canonical_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .as_bytes()
            .get(1)
            .is_none_or(|separator| *separator != b':')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SemanticIndexSet {
    Unqualified {
        index: Box<SemanticIndex>,
    },
    Qualified {
        variants: BTreeMap<SemanticVariantId, QualifiedSemanticIndex>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSemanticIndex {
    pub index: SemanticIndex,
    pub ignored_documents: BTreeSet<RepositoryPath>,
}

impl SemanticIndexSet {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Unqualified { index } => {
                if index.variant != SemanticIndexVariant::Unqualified {
                    return Err(
                        "unqualified semantic index set contains a qualified index".to_string()
                    );
                }
            }
            Self::Qualified { variants } => {
                if variants.is_empty() {
                    return Err("qualified semantic index set contains no variants".to_string());
                }
                for (identity, qualified) in variants {
                    let index = &qualified.index;
                    let SemanticIndexVariant::Qualified {
                        identity: index_identity,
                        dimensions,
                    } = &index.variant
                    else {
                        return Err(format!(
                            "qualified semantic index set contains unqualified variant {}",
                            identity.0
                        ));
                    };
                    if identity != index_identity
                        || identity.0.trim().is_empty()
                        || dimensions.is_empty()
                        || dimensions
                            .iter()
                            .any(|(name, value)| name.trim().is_empty() || value.trim().is_empty())
                    {
                        return Err(format!(
                            "qualified semantic index set has an invalid variant {}",
                            identity.0
                        ));
                    }
                    if !index
                        .documents
                        .keys()
                        .all(|document| !qualified.ignored_documents.contains(document))
                        || qualified
                            .ignored_documents
                            .iter()
                            .any(|document| document.0.trim().is_empty())
                    {
                        return Err(format!(
                            "qualified semantic index {} has conflicting document coverage",
                            identity.0
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn into_unqualified(self) -> Result<SemanticIndex, String> {
        self.validate()?;
        match self {
            Self::Unqualified { index } => Ok(*index),
            Self::Qualified { .. } => {
                Err("qualified semantic indexes cannot be flattened".to_string())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticIndex {
    pub format_version: u32,
    pub repository_root: String,
    pub provenance: SemanticIndexProvenance,
    pub variant: SemanticIndexVariant,
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
    pub invocations: Vec<SemanticIndexerInvocation>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticIndexerInvocation {
    pub arguments: Vec<String>,
    pub context: BTreeMap<String, String>,
    pub contribution: SemanticIndexerContribution,
    pub output_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticIndexerContribution {
    CompleteIndex,
    BuildContextDiscovery,
    PackageInventory,
    DocumentShard,
    ImplementationPair,
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
    pub signatures: BTreeSet<SemanticSignature>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[cfg(test)]
mod variant_tests {
    use super::*;

    fn plan() -> SemanticIndexerVariantPlan {
        SemanticIndexerVariantPlan {
            identity: SemanticVariantId("variant-a".to_string()),
            dimensions: BTreeMap::from([
                ("GOARCH".to_string(), "amd64".to_string()),
                ("GOOS".to_string(), "linux".to_string()),
            ]),
            environment: BTreeMap::from([
                ("CGO_ENABLED".to_string(), "0".to_string()),
                ("GOARCH".to_string(), "amd64".to_string()),
                ("GOOS".to_string(), "linux".to_string()),
            ]),
            compiler_project: None,
            selected_documents: BTreeSet::from([RepositoryPath("api_linux.go".to_string())]),
            ignored_documents: BTreeSet::from([RepositoryPath("api_windows.go".to_string())]),
        }
    }

    #[test]
    fn compiler_variant_plan_binds_identity_dimensions_and_document_partition() {
        let plan = plan();

        plan.validate().unwrap();
        assert_eq!(
            plan.index_variant(),
            SemanticIndexVariant::Qualified {
                identity: SemanticVariantId("variant-a".to_string()),
                dimensions: plan.dimensions.clone(),
            }
        );
    }

    #[test]
    fn compiler_variant_plan_rejects_overlapping_document_states() {
        let mut plan = plan();
        plan.ignored_documents = plan.selected_documents.clone();

        let error = plan.validate().unwrap_err();

        assert!(error.contains("incomplete"), "{error}");
    }

    #[test]
    fn compiler_variant_plan_allows_an_explicit_empty_world() {
        let mut plan = plan();
        plan.selected_documents.clear();
        plan.ignored_documents.clear();

        plan.validate().unwrap();
    }

    #[test]
    fn compiler_variant_plan_rejects_noncanonical_repository_paths() {
        for invalid in [
            "../tsconfig.json",
            "nested/../tsconfig.json",
            "/tsconfig.json",
            "C:/repo/tsconfig.json",
            "nested\\tsconfig.json",
            "nested//tsconfig.json",
        ] {
            let mut plan = plan();
            plan.compiler_project = Some(RepositoryPath(invalid.to_string()));

            let error = plan.validate().unwrap_err();

            assert!(error.contains("incomplete"), "{invalid}: {error}");
        }
    }
}
