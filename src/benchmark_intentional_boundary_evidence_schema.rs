use super::{BoundaryEvidenceKind, IntentionalBoundarySemanticRange};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_EVIDENCE_CENSUS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryCompilerProofKind {
    PublicSymbol,
    IncomingCall,
    ResolvedImport,
    Implementation,
    Override,
    TestMock,
    TestReplacement,
    FrameworkRegistrationSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryAstProofKind {
    ThinDelegation,
    DistinctOutcomeBranches,
    TestInjectionOrReplacement,
    FrameworkRegistration,
    GeneratorMarker,
    VersionedCompatibilityAnnotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestProofKind {
    PublishedExport,
    RuntimeEntrypoint,
    GeneratorConfiguration,
    VersionedCompatibilityDeclaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryBehaviorTestProofKind {
    BaselinePass,
    TargetedBehaviorPass,
    DistinctRetryOutcomePass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryGeneratorProofKind {
    ReproducedTrackedOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "source", content = "kind", rename_all = "snake_case")]
pub enum IntentionalBoundaryEvidenceProof {
    CompilerSemanticIndex(IntentionalBoundaryCompilerProofKind),
    SourceAst(IntentionalBoundaryAstProofKind),
    ManifestContract(IntentionalBoundaryManifestProofKind),
    ExecutedBehaviorTest(IntentionalBoundaryBehaviorTestProofKind),
    GeneratorReplay(IntentionalBoundaryGeneratorProofKind),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryEvidenceAtom {
    pub evidence_id: String,
    pub evidence_kind: BoundaryEvidenceKind,
    pub subject_parser_unit_id: String,
    pub subject_symbol_id: String,
    pub proof: IntentionalBoundaryEvidenceProof,
    pub locations: Vec<IntentionalBoundarySemanticRange>,
    pub related_symbol_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryEvidenceCensus {
    pub schema_version: u32,
    pub evidence_contract: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub input_census_sha256: BTreeMap<String, String>,
    pub atoms: Vec<IntentionalBoundaryEvidenceAtom>,
    pub atom_count_by_kind: BTreeMap<BoundaryEvidenceKind, usize>,
    pub evidence_census_sha256: String,
}
