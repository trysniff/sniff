use super::{
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCallFacts, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticDispatch, IntentionalBoundarySemanticImportFacts,
    IntentionalBoundarySemanticIndexerCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOccurrenceFacts,
    IntentionalBoundarySemanticOccurrenceRole, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticReferenceTarget,
    IntentionalBoundarySemanticRelationshipFacts, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSourceReference,
    IntentionalBoundarySemanticSurface, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticSymbolFacts, IntentionalBoundarySemanticTestFacts,
    IntentionalBoundarySemanticTestKind, IntentionalBoundarySemanticUnresolvedReason,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceCensus,
    IntentionalBoundarySourceFile, intentional_boundary_file_records,
    validate_intentional_boundary_source_census,
};
use crate::semantic_index::{
    SemanticDispatch, SemanticIndex, SemanticLocation, SemanticOccurrenceRole,
    SemanticRelationshipKind, SemanticResolution, SemanticSurface, SemanticSymbolCategory,
    SemanticSymbolId, SemanticSymbolOrigin, SemanticTestRelationshipKind, SemanticUnresolvedReason,
    SemanticVisibility,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_method_join::{SemanticMethodCoverage, join_methods};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::intentional_boundary_runtime_snapshot::IntentionalBoundaryRuntimeSnapshot;

pub(super) const SEMANTIC_CENSUS_CONTRACT: &str =
    "sniffbench-intentional-boundary-compiler-semantic-census-v3";
type MethodJoinKey = (String, String, u32, u32);
type ExpectedMethodMap<'a> = BTreeMap<MethodJoinKey, &'a IntentionalBoundaryMethodCensusEntry>;

#[path = "benchmark_intentional_boundary_semantic_validation.rs"]
mod validation;

pub use validation::validate_intentional_boundary_semantic_census;
pub(super) use validation::validate_intentional_boundary_semantic_census_scoped;

pub async fn census_intentional_boundary_semantics(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
) -> Result<IntentionalBoundarySemanticCensus, String> {
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    let runtime = prepare_semantic_runtime_snapshot(revision, root, inventory, source_census)?;
    let indexes =
        crate::semantic_indexer_runner::run_required_indexers(runtime.root(), runtime.files())
            .await?;
    let census = build_semantic_census(runtime.root(), source_census, runtime.files(), &indexes)?;
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    Ok(census)
}

struct SemanticRuntimeSnapshot {
    snapshot: IntentionalBoundaryRuntimeSnapshot,
    files: Vec<FileRecord>,
}

impl SemanticRuntimeSnapshot {
    fn root(&self) -> &Path {
        self.snapshot.path()
    }

    fn files(&self) -> &[FileRecord] {
        &self.files
    }
}

fn prepare_semantic_runtime_snapshot(
    revision: &str,
    source_root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
) -> Result<SemanticRuntimeSnapshot, String> {
    let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
        source_root,
        revision,
        "sniff-semantic-snapshot",
    )?;
    let files = intentional_boundary_file_records(snapshot.path(), inventory, source_census)?;
    Ok(SemanticRuntimeSnapshot { snapshot, files })
}

pub(super) fn build_semantic_census(
    root: &Path,
    source_census: &IntentionalBoundarySourceCensus,
    files: &[FileRecord],
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> Result<IntentionalBoundarySemanticCensus, String> {
    let expected_indexers = source_census
        .source_files
        .iter()
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?;
    let actual_indexers = indexes.keys().copied().collect::<BTreeSet<_>>();
    if actual_indexers != expected_indexers {
        return Err("intentional-boundary semantic indexer set is incomplete".to_string());
    }

    let mut expected_methods = method_identity_map(&source_census.source_files)?;
    let mut methods = Vec::with_capacity(source_census.method_count);
    let mut indexers = Vec::with_capacity(indexes.len());
    let mut source_references = Vec::new();
    for (kind, index) in indexes {
        let files_for_indexer = crate::semantic_indexer_runner::files_for_indexer(files, *kind);
        let join = join_methods(root, &files_for_indexer, index)?;
        for binding in join.bindings.values() {
            let key = (
                binding.method.file.0.clone(),
                binding.method.name.clone(),
                binding.method.start_line,
                binding.method.end_line,
            );
            let expected = expected_methods.remove(&key).ok_or_else(|| {
                format!(
                    "semantic index invented or repeated intentional-boundary method {}::{}:{}-{}",
                    key.0, key.1, key.2, key.3
                )
            })?;
            methods.push(flatten_method(
                indexer_kind(*kind),
                expected,
                binding,
                index,
            )?);
        }
        source_references.extend(flatten_source_references(
            indexer_kind(*kind),
            source_census,
            index,
        )?);
        indexers.push(summarize_index(*kind, index)?);
    }
    if !expected_methods.is_empty() {
        return Err(format!(
            "intentional-boundary semantic census omitted {} method(s)",
            expected_methods.len()
        ));
    }
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    source_references = canonical_source_references(source_references)?;
    indexers.sort_by_key(|indexer| indexer.indexer);
    let resolved_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::CompilerExcluded { .. }
            )
        })
        .count();
    let unresolved_method_count =
        methods.len() - resolved_method_count - compiler_excluded_method_count;
    let mut census = IntentionalBoundarySemanticCensus {
        schema_version: INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: SEMANTIC_CENSUS_CONTRACT.to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers,
        source_references,
        methods,
        resolved_method_count,
        compiler_excluded_method_count,
        unresolved_method_count,
        semantic_census_sha256: String::new(),
    };
    census.semantic_census_sha256 = compute_semantic_census_sha256(&census)?;
    Ok(census)
}

fn method_identity_map(
    files: &[IntentionalBoundarySourceFile],
) -> Result<ExpectedMethodMap<'_>, String> {
    let mut methods = BTreeMap::new();
    for file in files {
        for method in &file.methods {
            let start_line = u32::try_from(method.start_line).map_err(|_| {
                format!(
                    "intentional-boundary method {} exceeds semantic line range",
                    method.parser_unit_id
                )
            })?;
            let end_line = u32::try_from(method.end_line).map_err(|_| {
                format!(
                    "intentional-boundary method {} exceeds semantic line range",
                    method.parser_unit_id
                )
            })?;
            let key = (
                file.repository_path.clone(),
                method.symbol_name.clone(),
                start_line,
                end_line,
            );
            if methods.insert(key, method).is_some() {
                return Err("intentional-boundary source census repeats a method key".to_string());
            }
        }
    }
    Ok(methods)
}

#[path = "benchmark_intentional_boundary_semantic_projection.rs"]
mod projection;

pub(super) use projection::{flatten_method, flatten_symbol, summarize_index};

pub(super) fn compute_semantic_census_sha256(
    census: &IntentionalBoundarySemanticCensus,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.semantic_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.indexers,
        &census.source_references,
        &census.methods,
        census.resolved_method_count,
        census.compiler_excluded_method_count,
        census.unresolved_method_count,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary semantic census: {error}"))?;
    Ok(sha256(&bytes))
}

fn flatten_source_references(
    indexer: IntentionalBoundaryIndexerKind,
    source_census: &IntentionalBoundarySourceCensus,
    index: &SemanticIndex,
) -> Result<Vec<IntentionalBoundarySemanticSourceReference>, String> {
    let source_paths = source_census
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut references = Vec::new();
    for document in index
        .documents
        .values()
        .filter(|document| source_paths.contains(document.path.0.as_str()))
    {
        for occurrence in &document.occurrences {
            let target = match occurrence.symbol.as_ref() {
                Some(symbol_id) => match index.symbols.get(symbol_id) {
                    Some(symbol) => IntentionalBoundarySemanticResolution::Resolved {
                        value: IntentionalBoundarySemanticReferenceTarget {
                            symbol_id: symbol.id.0.clone(),
                            provider_identity: symbol.provider_identity.clone(),
                            display_name: symbol.display_name.clone(),
                            provider_kind: symbol.kind.provider_name.clone(),
                            origin: origin(symbol.origin),
                        },
                    },
                    None => IntentionalBoundarySemanticResolution::Unresolved {
                        reason: IntentionalBoundarySemanticUnresolvedReason::MissingDefinition,
                        raw_target: Some(symbol_id.0.clone()),
                        detail: "compiler occurrence omitted referenced symbol facts".to_string(),
                    },
                },
                None => IntentionalBoundarySemanticResolution::Unresolved {
                    reason: IntentionalBoundarySemanticUnresolvedReason::MissingIndexerFact,
                    raw_target: None,
                    detail: "compiler occurrence has no symbol identity".to_string(),
                },
            };
            references.push(IntentionalBoundarySemanticSourceReference {
                indexer,
                location: flatten_range(&document.path.0, &occurrence.range),
                roles: occurrence
                    .roles
                    .iter()
                    .copied()
                    .map(occurrence_role)
                    .collect(),
                target,
            });
        }
    }
    Ok(references)
}

pub(super) fn canonical_source_references(
    references: Vec<IntentionalBoundarySemanticSourceReference>,
) -> Result<Vec<IntentionalBoundarySemanticSourceReference>, String> {
    let mut canonical = BTreeMap::new();
    for reference in references {
        let identity = source_reference_identity(&reference).map_err(|error| {
            format!("failed to canonicalize intentional-boundary source reference: {error}")
        })?;
        canonical
            .entry(identity)
            .and_modify(
                |existing: &mut IntentionalBoundarySemanticSourceReference| {
                    existing.roles = existing
                        .roles
                        .iter()
                        .chain(&reference.roles)
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                },
            )
            .or_insert(reference);
    }
    Ok(canonical.into_values().collect())
}

pub(super) fn source_reference_identity(
    reference: &IntentionalBoundarySemanticSourceReference,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&(reference.indexer, &reference.location, &reference.target))
}

fn flatten_location(location: &SemanticLocation) -> IntentionalBoundarySemanticRange {
    flatten_range(&location.document.0, &location.range)
}

fn flatten_range(
    repository_path: &str,
    range: &crate::semantic_index::SemanticSourceRange,
) -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: range.start.line,
        start_character_zero_based: range.start.character,
        end_line_zero_based: range.end.line,
        end_character_zero_based: range.end.character,
    }
}

fn flatten_symbol_resolution(
    resolution: &SemanticResolution<SemanticSymbolId>,
) -> IntentionalBoundarySemanticResolution<String> {
    match resolution {
        SemanticResolution::Resolved { value } => IntentionalBoundarySemanticResolution::Resolved {
            value: value.0.clone(),
        },
        SemanticResolution::Unresolved {
            reason,
            raw_target,
            detail,
        } => IntentionalBoundarySemanticResolution::Unresolved {
            reason: unresolved_reason(*reason),
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
    }
}

fn flatten_bool_resolution(
    resolution: &SemanticResolution<bool>,
) -> IntentionalBoundarySemanticResolution<bool> {
    match resolution {
        SemanticResolution::Resolved { value } => {
            IntentionalBoundarySemanticResolution::Resolved { value: *value }
        }
        SemanticResolution::Unresolved {
            reason,
            raw_target,
            detail,
        } => IntentionalBoundarySemanticResolution::Unresolved {
            reason: unresolved_reason(*reason),
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
    }
}

fn indexer_for_language(language: &str) -> Result<SemanticIndexerKind, String> {
    match language {
        "typescript" | "javascript" => Ok(SemanticIndexerKind::TypeScriptJavaScript),
        "python" => Ok(SemanticIndexerKind::Python),
        "go" => Ok(SemanticIndexerKind::Go),
        "kotlin" => Ok(SemanticIndexerKind::Kotlin),
        "rust" => Ok(SemanticIndexerKind::Rust),
        other => Err(format!(
            "intentional-boundary source census contains unsupported language {other}"
        )),
    }
}

pub(super) fn indexer_kind(kind: SemanticIndexerKind) -> IntentionalBoundaryIndexerKind {
    match kind {
        SemanticIndexerKind::TypeScriptJavaScript => {
            IntentionalBoundaryIndexerKind::TypeScriptJavaScript
        }
        SemanticIndexerKind::Python => IntentionalBoundaryIndexerKind::Python,
        SemanticIndexerKind::Go => IntentionalBoundaryIndexerKind::Go,
        SemanticIndexerKind::Kotlin => IntentionalBoundaryIndexerKind::Kotlin,
        SemanticIndexerKind::Rust => IntentionalBoundaryIndexerKind::Rust,
    }
}

fn unresolved_reason(
    reason: SemanticUnresolvedReason,
) -> IntentionalBoundarySemanticUnresolvedReason {
    match reason {
        SemanticUnresolvedReason::DynamicDispatch => {
            IntentionalBoundarySemanticUnresolvedReason::DynamicDispatch
        }
        SemanticUnresolvedReason::Ambiguous => {
            IntentionalBoundarySemanticUnresolvedReason::Ambiguous
        }
        SemanticUnresolvedReason::MissingDefinition => {
            IntentionalBoundarySemanticUnresolvedReason::MissingDefinition
        }
        SemanticUnresolvedReason::MissingIndexerFact => {
            IntentionalBoundarySemanticUnresolvedReason::MissingIndexerFact
        }
        SemanticUnresolvedReason::UnsupportedConstruct => {
            IntentionalBoundarySemanticUnresolvedReason::UnsupportedConstruct
        }
        SemanticUnresolvedReason::ExternalContractUnavailable => {
            IntentionalBoundarySemanticUnresolvedReason::ExternalContractUnavailable
        }
    }
}

fn symbol_category(category: SemanticSymbolCategory) -> IntentionalBoundarySemanticSymbolCategory {
    match category {
        SemanticSymbolCategory::Unknown => IntentionalBoundarySemanticSymbolCategory::Unknown,
        SemanticSymbolCategory::Callable => IntentionalBoundarySemanticSymbolCategory::Callable,
        SemanticSymbolCategory::Constructor => {
            IntentionalBoundarySemanticSymbolCategory::Constructor
        }
        SemanticSymbolCategory::Method => IntentionalBoundarySemanticSymbolCategory::Method,
        SemanticSymbolCategory::Type => IntentionalBoundarySemanticSymbolCategory::Type,
        SemanticSymbolCategory::TraitOrInterface => {
            IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
        }
        SemanticSymbolCategory::Module => IntentionalBoundarySemanticSymbolCategory::Module,
        SemanticSymbolCategory::Namespace => IntentionalBoundarySemanticSymbolCategory::Namespace,
        SemanticSymbolCategory::Package => IntentionalBoundarySemanticSymbolCategory::Package,
        SemanticSymbolCategory::FieldOrProperty => {
            IntentionalBoundarySemanticSymbolCategory::FieldOrProperty
        }
        SemanticSymbolCategory::Parameter => IntentionalBoundarySemanticSymbolCategory::Parameter,
        SemanticSymbolCategory::Variable => IntentionalBoundarySemanticSymbolCategory::Variable,
        SemanticSymbolCategory::Constant => IntentionalBoundarySemanticSymbolCategory::Constant,
        SemanticSymbolCategory::Macro => IntentionalBoundarySemanticSymbolCategory::Macro,
        SemanticSymbolCategory::Other => IntentionalBoundarySemanticSymbolCategory::Other,
    }
}

fn visibility(value: SemanticVisibility) -> IntentionalBoundarySemanticVisibility {
    match value {
        SemanticVisibility::Unknown => IntentionalBoundarySemanticVisibility::Unknown,
        SemanticVisibility::Private => IntentionalBoundarySemanticVisibility::Private,
        SemanticVisibility::Package => IntentionalBoundarySemanticVisibility::Package,
        SemanticVisibility::Protected => IntentionalBoundarySemanticVisibility::Protected,
        SemanticVisibility::Public => IntentionalBoundarySemanticVisibility::Public,
    }
}

fn origin(value: SemanticSymbolOrigin) -> IntentionalBoundarySemanticOrigin {
    match value {
        SemanticSymbolOrigin::Unknown => IntentionalBoundarySemanticOrigin::Unknown,
        SemanticSymbolOrigin::Repository => IntentionalBoundarySemanticOrigin::Repository,
        SemanticSymbolOrigin::External => IntentionalBoundarySemanticOrigin::External,
    }
}

fn surface(value: SemanticSurface) -> IntentionalBoundarySemanticSurface {
    match value {
        SemanticSurface::PublicApi => IntentionalBoundarySemanticSurface::PublicApi,
        SemanticSurface::Entrypoint => IntentionalBoundarySemanticSurface::Entrypoint,
        SemanticSurface::Route => IntentionalBoundarySemanticSurface::Route,
        SemanticSurface::Command => IntentionalBoundarySemanticSurface::Command,
        SemanticSurface::Job => IntentionalBoundarySemanticSurface::Job,
        SemanticSurface::Callback => IntentionalBoundarySemanticSurface::Callback,
        SemanticSurface::Plugin => IntentionalBoundarySemanticSurface::Plugin,
        SemanticSurface::FrameworkRegistration => {
            IntentionalBoundarySemanticSurface::FrameworkRegistration
        }
        SemanticSurface::Configuration => IntentionalBoundarySemanticSurface::Configuration,
        SemanticSurface::Schema => IntentionalBoundarySemanticSurface::Schema,
    }
}

fn dispatch(value: SemanticDispatch) -> IntentionalBoundarySemanticDispatch {
    match value {
        SemanticDispatch::Static => IntentionalBoundarySemanticDispatch::Static,
        SemanticDispatch::Virtual => IntentionalBoundarySemanticDispatch::Virtual,
        SemanticDispatch::Dynamic => IntentionalBoundarySemanticDispatch::Dynamic,
        SemanticDispatch::Unknown => IntentionalBoundarySemanticDispatch::Unknown,
    }
}

fn relationship_kind(
    value: SemanticRelationshipKind,
) -> IntentionalBoundarySemanticRelationshipKind {
    match value {
        SemanticRelationshipKind::Reference => {
            IntentionalBoundarySemanticRelationshipKind::Reference
        }
        SemanticRelationshipKind::Implementation => {
            IntentionalBoundarySemanticRelationshipKind::Implementation
        }
        SemanticRelationshipKind::TypeDefinition => {
            IntentionalBoundarySemanticRelationshipKind::TypeDefinition
        }
        SemanticRelationshipKind::Definition => {
            IntentionalBoundarySemanticRelationshipKind::Definition
        }
        SemanticRelationshipKind::Override => IntentionalBoundarySemanticRelationshipKind::Override,
    }
}

fn occurrence_role(value: SemanticOccurrenceRole) -> IntentionalBoundarySemanticOccurrenceRole {
    match value {
        SemanticOccurrenceRole::Definition => IntentionalBoundarySemanticOccurrenceRole::Definition,
        SemanticOccurrenceRole::Import => IntentionalBoundarySemanticOccurrenceRole::Import,
        SemanticOccurrenceRole::Write => IntentionalBoundarySemanticOccurrenceRole::Write,
        SemanticOccurrenceRole::Read => IntentionalBoundarySemanticOccurrenceRole::Read,
        SemanticOccurrenceRole::Generated => IntentionalBoundarySemanticOccurrenceRole::Generated,
        SemanticOccurrenceRole::Test => IntentionalBoundarySemanticOccurrenceRole::Test,
        SemanticOccurrenceRole::ForwardDefinition => {
            IntentionalBoundarySemanticOccurrenceRole::ForwardDefinition
        }
    }
}

fn test_kind(value: SemanticTestRelationshipKind) -> IntentionalBoundarySemanticTestKind {
    match value {
        SemanticTestRelationshipKind::Exercises => IntentionalBoundarySemanticTestKind::Exercises,
        SemanticTestRelationshipKind::Mocks => IntentionalBoundarySemanticTestKind::Mocks,
        SemanticTestRelationshipKind::Replaces => IntentionalBoundarySemanticTestKind::Replaces,
        SemanticTestRelationshipKind::AssertsContract => {
            IntentionalBoundarySemanticTestKind::AssertsContract
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_semantic_tests.rs"]
mod tests;
