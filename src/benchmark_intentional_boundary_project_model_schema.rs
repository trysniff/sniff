use super::{IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelProvider {
    CargoMetadata,
    GoList,
    GradleToolingApi,
    TypeScriptCompilerApi,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelTypeScriptConfigRead {
    pub repository_path: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelTypeScriptProject {
    pub config_repository_path: Option<String>,
    pub config_object_id: Option<String>,
    pub config_reads: Vec<IntentionalBoundaryProjectModelTypeScriptConfigRead>,
    pub project_references: Vec<String>,
    pub effective_compiler_options_json: String,
    pub source_repository_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelGradlePublication {
    pub name: String,
    pub publication_type: String,
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelKotlinSourceSet {
    pub name: String,
    pub source_repository_paths: Vec<String>,
    pub depends_on_source_sets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelKotlinCompilation {
    pub name: String,
    pub default_source_set: String,
    pub source_sets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelKotlinTarget {
    pub name: String,
    pub platform_type: String,
    pub publishable: bool,
    pub component_names: Vec<String>,
    pub compilations: Vec<IntentionalBoundaryProjectModelKotlinCompilation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelGradleKotlinProject {
    pub project_path: String,
    pub component_names: Vec<String>,
    pub publications: Vec<IntentionalBoundaryProjectModelGradlePublication>,
    pub source_sets: Vec<IntentionalBoundaryProjectModelKotlinSourceSet>,
    pub targets: Vec<IntentionalBoundaryProjectModelKotlinTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelVariant {
    Default,
    Gradle {
        kotlin_projects: Vec<IntentionalBoundaryProjectModelGradleKotlinProject>,
    },
    Go {
        goos: String,
        goarch: String,
        cgo_enabled: bool,
        build_tags: Vec<String>,
        architecture: IntentionalBoundaryProjectModelGoArchitecture,
    },
    TypeScript {
        root_config_repository_path: Option<String>,
        compiler_version: String,
        projects: Vec<IntentionalBoundaryProjectModelTypeScriptProject>,
        selected_source_repository_paths: Vec<String>,
        ignored_source_repository_paths: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelGoArchitecture {
    Default,
    Explicit {
        environment_variable: String,
        value: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelNonBoundaryReason {
    ExampleTarget,
    TestTarget,
    BenchmarkTarget,
    CompilerProject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelUnresolvedReason {
    ConflictingTargetKinds,
    UnknownTargetKind,
    SourceSetEmpty,
    SourceOutsideRepository,
    SourceNotTracked,
    SourceNotRegularBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelTargetStatus {
    Boundary {
        declaration_kind: IntentionalBoundaryManifestDeclarationKind,
        target: IntentionalBoundaryManifestTarget,
    },
    NonBoundary {
        reason: IntentionalBoundaryProjectModelNonBoundaryReason,
    },
    Unresolved {
        reason: IntentionalBoundaryProjectModelUnresolvedReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelProducerTask {
    pub task_path: String,
    pub task_type: String,
    pub output_repository_paths: Vec<String>,
    pub source_repository_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelTarget {
    pub target_id: String,
    pub execution_id: String,
    pub provider: IntentionalBoundaryProjectModelProvider,
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub package_name: String,
    pub package_version: String,
    pub target_name: String,
    pub provider_kinds: Vec<String>,
    pub provider_output_types: Vec<String>,
    pub source_repository_paths: Vec<String>,
    pub ignored_source_repository_paths: Vec<String>,
    pub producer_tasks: Vec<IntentionalBoundaryProjectModelProducerTask>,
    pub required_features: Vec<String>,
    pub target_status: IntentionalBoundaryProjectModelTargetStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelExecution {
    pub execution_id: String,
    pub provider: IntentionalBoundaryProjectModelProvider,
    pub variant: IntentionalBoundaryProjectModelVariant,
    pub invocation_anchor_repository_path: String,
    pub invocation_anchor_object_id: String,
    pub toolchain_identity_sha256: String,
    pub command_contract: String,
    pub normalized_model_sha256: String,
    pub covered_manifest_repository_paths: Vec<String>,
    pub target_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelCensus {
    pub schema_version: u32,
    pub project_model_contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub executions: Vec<IntentionalBoundaryProjectModelExecution>,
    pub targets: Vec<IntentionalBoundaryProjectModelTarget>,
    pub execution_count_by_provider: BTreeMap<IntentionalBoundaryProjectModelProvider, usize>,
    pub target_count_by_status: BTreeMap<String, usize>,
    pub project_model_census_sha256: String,
}
