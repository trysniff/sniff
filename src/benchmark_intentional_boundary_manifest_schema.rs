use super::IntentionalBoundarySemanticRange;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_MANIFEST_CENSUS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestProvider {
    CargoManifest,
    NodePackageManifest,
    PythonProjectManifest,
    GoPackageMetadata,
    GradleProjectModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestDeclarationKind {
    PublishedModule,
    RuntimeEntrypoint,
    BuildScript,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestTarget {
    RepositoryPath {
        repository_path: String,
    },
    RepositoryPaths {
        repository_paths: Vec<String>,
    },
    PythonObject {
        module: Vec<String>,
        qualname: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestDocument {
    pub provider: IntentionalBoundaryManifestProvider,
    pub repository_path: String,
    pub object_id: String,
    pub source_sha256: String,
    pub declaration_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestDeclaration {
    pub declaration_id: String,
    pub provider: IntentionalBoundaryManifestProvider,
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub declaration_kind: IntentionalBoundaryManifestDeclarationKind,
    pub declaration_location: IntentionalBoundarySemanticRange,
    pub target: IntentionalBoundaryManifestTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestCensus {
    pub schema_version: u32,
    pub manifest_contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub documents: Vec<IntentionalBoundaryManifestDocument>,
    pub document_count_by_provider: BTreeMap<IntentionalBoundaryManifestProvider, usize>,
    pub declarations: Vec<IntentionalBoundaryManifestDeclaration>,
    pub declaration_count_by_kind: BTreeMap<IntentionalBoundaryManifestDeclarationKind, usize>,
    pub manifest_census_sha256: String,
}
