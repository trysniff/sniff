use super::history_v2_semantic_exclusion::{
    RETAINED_EVIDENCE_LIMIT, seal_semantic_census_exclusion,
};
use super::intentional_boundary_inventory::read_intentional_boundary_git_blob;
use super::intentional_boundary_semantic::{flatten_method, flatten_symbol, summarize_index};
use super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2PublicSymbol, HistoricalV2SemanticCensus,
    HistoricalV2SemanticCensusExclusion, HistoricalV2SemanticCensusExclusionReason,
    HistoricalV2SemanticCensusFailureEvidence, HistoricalV2SemanticCensusFailurePhase,
    HistoricalV2SemanticProcessEvidence, HistoricalV2SemanticSnapshotCensus,
    HistoricalV2SemanticSnapshotSide, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2SourceCensus, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, HistoricalV2StageResult, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, validate_historical_v2_source_census,
};
use crate::semantic_index::{SemanticIndex, SemanticSymbolOrigin, SemanticVisibility};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_indexer_runner::{
    SemanticIndexerBatchOutcome, SemanticIndexerProcessEvidence, SemanticIndexerRunFailure,
    SemanticIndexerRunFailureKind, SemanticIndexerRunPhase,
};
use crate::semantic_method_join::join_methods;
use crate::types::FileRecord;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SEMANTIC_CENSUS_CONTRACT: &str = "sniffbench-historical-v2-compiler-semantic-census-v2";
const UNCHANGED_DOCUMENT_EXCLUSION: &str =
    "compiler omitted an unchanged source document outside the exact historical patch";
const UNTOUCHED_LANGUAGE_EXCLUSION: &str =
    "source language is untouched by the exact historical patch";
type MethodKey = (String, String, u32, u32);
type SemanticCensusStageResult =
    HistoricalV2StageResult<HistoricalV2SemanticCensus, HistoricalV2SemanticCensusExclusion>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoricalV2SemanticScope {
    changed_indexers: BTreeSet<SemanticIndexerKind>,
    base_required_paths: BTreeSet<String>,
    patched_required_paths: BTreeSet<String>,
}

#[path = "benchmark_history_v2_semantic_validation.rs"]
mod validation;

#[path = "benchmark_history_v2_semantic_stage_support.rs"]
mod stage_support;

#[path = "benchmark_history_v2_semantic_progress.rs"]
mod progress;

use stage_support::*;

pub use validation::validate_historical_v2_semantic_census_commitment;

pub fn recover_historical_v2_semantic_progress(root: &Path) -> Result<(), String> {
    progress::HistoricalV2SemanticProgress::recover_existing(root)
}

struct HistoricalV2SemanticSnapshotInputs<'a> {
    side: HistoricalV2SemanticSnapshotSide,
    root: &'a Path,
    source: &'a HistoricalV2SourceSnapshotCensus,
    all_files: &'a [FileRecord],
    scoped_files: &'a [FileRecord],
    required_documents: &'a [FileRecord],
    required_paths: &'a BTreeSet<String>,
}

#[path = "benchmark_history_v2_semantic_execution.rs"]
mod execution;

pub use execution::{
    census_historical_v2_semantics, census_historical_v2_semantics_typed,
    census_historical_v2_semantics_typed_resumable,
};

pub async fn validate_historical_v2_semantic_census(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    census: &HistoricalV2SemanticCensus,
) -> Result<(), String> {
    validate_historical_v2_semantic_census_commitment(
        materialization,
        roots,
        source_census,
        census,
    )?;
    let expected = match census_historical_v2_semantics_typed(materialization, roots, source_census)
        .await
        .map_err(|error| error.detail)?
    {
        HistoricalV2StageResult::Completed(census) => census,
        HistoricalV2StageResult::Excluded(_) => {
            return Err(
                "historical-v2 semantic census claims completion for excluded source".to_string(),
            );
        }
    };
    if census != &expected {
        return Err("historical-v2 compiler semantic replay changed".to_string());
    }
    Ok(())
}

fn semantic_scope(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
) -> Result<HistoricalV2SemanticScope, String> {
    let changed = super::non_blind_history_git::changed_paths(
        &roots.repository_root,
        &materialization.base_revision,
        &materialization.patched_commit_oid,
    )?;
    derive_semantic_scope(&changed, &source_census.base, &source_census.patched)
}

fn derive_semantic_scope(
    changed: &[super::HistoricalChangedPath],
    base: &HistoricalV2SourceSnapshotCensus,
    patched: &HistoricalV2SourceSnapshotCensus,
) -> Result<HistoricalV2SemanticScope, String> {
    let base_sources = required_sources_by_path(base)?;
    let patched_sources = required_sources_by_path(patched)?;
    let mut base_required_paths = BTreeSet::new();
    let mut patched_required_paths = BTreeSet::new();
    let mut changed_indexers = BTreeSet::new();

    for change in changed {
        if let Some(previous_path) = &change.previous_path
            && let Some(file) = base_sources.get(previous_path.as_str())
        {
            base_required_paths.insert(previous_path.clone());
            changed_indexers.insert(indexer_for_language(&file.language)?);
        }
        if let Some(file) = base_sources.get(change.path.as_str()) {
            base_required_paths.insert(change.path.clone());
            changed_indexers.insert(indexer_for_language(&file.language)?);
        }
        if let Some(file) = patched_sources.get(change.path.as_str()) {
            patched_required_paths.insert(change.path.clone());
            changed_indexers.insert(indexer_for_language(&file.language)?);
        }
    }

    Ok(HistoricalV2SemanticScope {
        changed_indexers,
        base_required_paths,
        patched_required_paths,
    })
}

fn required_sources_by_path(
    source: &HistoricalV2SourceSnapshotCensus,
) -> Result<BTreeMap<&str, &super::HistoricalV2SourceFile>, String> {
    let mut files = BTreeMap::new();
    for file in &source.source_files {
        if file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required {
            continue;
        }
        if files.insert(file.repository_path.as_str(), file).is_some() {
            return Err("historical-v2 source scope repeats a repository path".to_string());
        }
    }
    Ok(files)
}

fn scoped_file_records(
    root: &Path,
    files: &[FileRecord],
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_paths: &BTreeSet<String>,
) -> Result<(Vec<FileRecord>, Vec<FileRecord>), String> {
    let mut execution = Vec::new();
    let mut required = Vec::new();
    let mut seen_required = BTreeSet::new();
    for file in files {
        let kind = indexer_for_language(&file.language)?;
        if !changed_indexers.contains(&kind) {
            continue;
        }
        let path = file_repository_path(root, file)?;
        execution.push(file.clone());
        if required_paths.contains(&path) {
            seen_required.insert(path);
            required.push(file.clone());
        }
    }
    if &seen_required != required_paths {
        return Err("historical-v2 changed semantic document scope is incomplete".to_string());
    }
    Ok((execution, required))
}

fn file_repository_path(root: &Path, file: &FileRecord) -> Result<String, String> {
    let path = Path::new(&file.file_path);
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "historical-v2 semantic source {} is outside {}",
            path.display(),
            root.display()
        )
    })?;
    let path = relative.to_string_lossy().replace('\\', "/");
    if path.is_empty() || path.starts_with("../") || path.contains('\0') {
        return Err("historical-v2 semantic source path is unsafe".to_string());
    }
    Ok(path)
}

fn build_semantic_snapshot(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    files: &[FileRecord],
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> Result<HistoricalV2SemanticSnapshotCensus, String> {
    let expected_indexers = files
        .iter()
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?;
    let expected_indexers = expected_indexers
        .intersection(changed_indexers)
        .copied()
        .collect::<BTreeSet<_>>();
    if indexes.keys().copied().collect::<BTreeSet<_>>() != expected_indexers {
        return Err("historical-v2 semantic indexer set is incomplete".to_string());
    }
    let mut expected_methods = expected_method_map(source)?;
    let required_paths = source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut methods = Vec::<IntentionalBoundarySemanticMethod>::with_capacity(source.method_count);
    let mut public_symbols = Vec::new();
    let mut indexers = Vec::with_capacity(indexes.len());
    for (kind, index) in indexes {
        let files_for_indexer = crate::semantic_indexer_runner::files_for_indexer(files, *kind);
        let mut indexed_files = Vec::new();
        for file in files_for_indexer {
            let path = file_repository_path(root, &file)?;
            if index
                .documents
                .contains_key(&crate::semantic_index::RepositoryPath(path.clone()))
            {
                indexed_files.push(file);
                continue;
            }
            if required_document_paths.contains(&path) {
                return Err(format!(
                    "historical-v2 compiler omitted changed source document {path}"
                ));
            }
            push_compiler_excluded_file_methods(
                &path,
                &file,
                indexer_kind(*kind),
                UNCHANGED_DOCUMENT_EXCLUSION,
                &mut expected_methods,
                &mut methods,
            )?;
        }
        let join = join_methods(root, &indexed_files, index)?;
        for binding in join.bindings.values() {
            let key = (
                binding.method.file.0.clone(),
                binding.method.name.clone(),
                binding.method.start_line,
                binding.method.end_line,
            );
            let expected = expected_methods.remove(&key).ok_or_else(|| {
                format!(
                    "historical-v2 semantic index invented or repeated method {}::{}:{}-{}",
                    key.0, key.1, key.2, key.3
                )
            })?;
            methods.push(flatten_method(
                indexer_kind(*kind),
                &expected,
                binding,
                index,
            )?);
        }
        public_symbols.extend(
            index
                .symbols
                .values()
                .filter(|symbol| {
                    symbol.origin == SemanticSymbolOrigin::Repository
                        && symbol.definitions.iter().any(|definition| {
                            required_paths.contains(definition.document.0.as_str())
                        })
                        && (matches!(
                            symbol.visibility,
                            SemanticVisibility::Public | SemanticVisibility::Protected
                        ) || !symbol.surfaces.is_empty())
                })
                .map(|symbol| HistoricalV2PublicSymbol {
                    indexer: indexer_kind(*kind),
                    symbol: flatten_symbol(symbol),
                }),
        );
        indexers.push(summarize_index(*kind, index)?);
    }
    for file in files {
        let kind = indexer_for_language(&file.language)?;
        if indexes.contains_key(&kind) {
            continue;
        }
        let path = file_repository_path(root, file)?;
        push_compiler_excluded_file_methods(
            &path,
            file,
            indexer_kind(kind),
            UNTOUCHED_LANGUAGE_EXCLUSION,
            &mut expected_methods,
            &mut methods,
        )?;
    }
    if !expected_methods.is_empty() {
        return Err(format!(
            "historical-v2 semantic census omitted {} method(s)",
            expected_methods.len()
        ));
    }
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    public_symbols.sort_by(|left, right| {
        (left.indexer, left.symbol.symbol_id.as_str())
            .cmp(&(right.indexer, right.symbol.symbol_id.as_str()))
    });
    if public_symbols.windows(2).any(|pair| {
        pair[0].indexer == pair[1].indexer && pair[0].symbol.symbol_id == pair[1].symbol.symbol_id
    }) {
        return Err("historical-v2 semantic census repeats a public symbol".to_string());
    }
    indexers.sort_by_key(|indexer| indexer.indexer);
    let resolved_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                super::IntentionalBoundarySemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                super::IntentionalBoundarySemanticMethodStatus::CompilerExcluded { .. }
            )
        })
        .count();
    let unresolved_method_count = methods
        .len()
        .checked_sub(resolved_method_count + compiler_excluded_method_count)
        .ok_or_else(|| "historical-v2 semantic method counts underflowed".to_string())?;
    let mut snapshot = HistoricalV2SemanticSnapshotCensus {
        revision: source.revision.clone(),
        source_snapshot_census_sha256: source.snapshot_census_sha256.clone(),
        required_document_paths: required_document_paths.iter().cloned().collect(),
        indexers,
        methods,
        public_symbol_count: public_symbols.len(),
        public_symbols,
        resolved_method_count,
        compiler_excluded_method_count,
        unresolved_method_count,
        semantic_snapshot_sha256: String::new(),
    };
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot)?;
    Ok(snapshot)
}

fn push_compiler_excluded_file_methods(
    repository_path: &str,
    file: &FileRecord,
    indexer: IntentionalBoundaryIndexerKind,
    reason: &str,
    expected_methods: &mut BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>,
    methods: &mut Vec<IntentionalBoundarySemanticMethod>,
) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("historical-v2 compiler exclusion has no evidence".to_string());
    }
    for method in &file.methods {
        let start_line = u32::try_from(method.start_line)
            .map_err(|_| "historical-v2 excluded method start exceeds SCIP range".to_string())?;
        let end_line = u32::try_from(method.end_line)
            .map_err(|_| "historical-v2 excluded method end exceeds SCIP range".to_string())?;
        let key = (
            repository_path.to_string(),
            method.name.clone(),
            start_line,
            end_line,
        );
        let expected = expected_methods.remove(&key).ok_or_else(|| {
            format!(
                "historical-v2 compiler exclusion invented or repeated method {}::{}:{}-{}",
                key.0, key.1, key.2, key.3
            )
        })?;
        methods.push(IntentionalBoundarySemanticMethod {
            parser_unit_id: expected.parser_unit_id,
            repository_path: key.0,
            symbol_name: expected.symbol_name,
            start_line: expected.start_line,
            end_line: expected.end_line,
            indexer,
            status: IntentionalBoundarySemanticMethodStatus::CompilerExcluded {
                reason: reason.to_string(),
            },
            occurrences: Vec::new(),
            calls: Vec::new(),
            relationships: Vec::new(),
            imports: Vec::new(),
            test_relationships: Vec::new(),
        });
    }
    Ok(())
}

fn snapshot_file_records(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
) -> Result<Vec<FileRecord>, String> {
    let mut records = Vec::with_capacity(source.source_files.len());
    for file in &source.source_files {
        if file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required {
            continue;
        }
        let bytes = read_intentional_boundary_git_blob(root, &file.object_id, file.byte_length)?;
        if sha256(&bytes) != file.source_sha256 {
            return Err(format!(
                "historical-v2 semantic source bytes changed: {}",
                file.repository_path
            ));
        }
        let absolute = root.join(Path::new(&file.repository_path));
        let absolute = absolute.to_str().ok_or_else(|| {
            format!(
                "historical-v2 semantic source path is not UTF-8: {}",
                file.repository_path
            )
        })?;
        let record = crate::parser::parse_source_checked(absolute, &bytes)?;
        if record.language != file.language || record.methods.len() != file.methods.len() {
            return Err(format!(
                "historical-v2 semantic parser census changed: {}",
                file.repository_path
            ));
        }
        for (method, expected) in record.methods.iter().zip(&file.methods) {
            if method.name != expected.symbol_name
                || method.start_line != expected.start_line
                || method.end_line != expected.end_line
                || method.is_exported != expected.is_exported
                || sha256(method.source.as_bytes()) != expected.source_sha256
            {
                return Err(format!(
                    "historical-v2 semantic method identity changed: {}",
                    expected.parser_unit_id
                ));
            }
        }
        records.push(record);
    }
    Ok(records)
}

fn expected_method_map(
    source: &HistoricalV2SourceSnapshotCensus,
) -> Result<BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>, String> {
    let mut methods = BTreeMap::new();
    for file in &source.source_files {
        if file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required {
            continue;
        }
        for method in &file.methods {
            let start_line = u32::try_from(method.start_line)
                .map_err(|_| "historical-v2 method start exceeds semantic range".to_string())?;
            let end_line = u32::try_from(method.end_line)
                .map_err(|_| "historical-v2 method end exceeds semantic range".to_string())?;
            let key = (
                file.repository_path.clone(),
                method.symbol_name.clone(),
                start_line,
                end_line,
            );
            let value = IntentionalBoundaryMethodCensusEntry {
                parser_unit_id: method.parser_unit_id.clone(),
                symbol_name: method.symbol_name.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: method.source_sha256.clone(),
                is_exported: method.is_exported,
            };
            if methods.insert(key, value).is_some() {
                return Err("historical-v2 source census repeats a semantic method key".to_string());
            }
        }
    }
    Ok(methods)
}

pub(super) fn indexer_for_language(language: &str) -> Result<SemanticIndexerKind, String> {
    match language {
        "typescript" | "javascript" => Ok(SemanticIndexerKind::TypeScriptJavaScript),
        "python" => Ok(SemanticIndexerKind::Python),
        "go" => Ok(SemanticIndexerKind::Go),
        "kotlin" => Ok(SemanticIndexerKind::Kotlin),
        "rust" => Ok(SemanticIndexerKind::Rust),
        other => Err(format!(
            "historical-v2 source census contains unsupported language {other}"
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

pub(super) fn semantic_snapshot_sha256(
    value: &HistoricalV2SemanticSnapshotCensus,
) -> Result<String, String> {
    hash_json(&(
        &value.revision,
        &value.source_snapshot_census_sha256,
        &value.required_document_paths,
        &value.indexers,
        &value.methods,
        &value.public_symbols,
        value.public_symbol_count,
        value.resolved_method_count,
        value.compiler_excluded_method_count,
        value.unresolved_method_count,
    ))
}

pub(super) fn semantic_census_sha256(value: &HistoricalV2SemanticCensus) -> Result<String, String> {
    hash_json(&(
        value.schema_version,
        &value.semantic_census_contract,
        &value.canonical_repository,
        &value.materialization_sha256,
        &value.source_census_sha256,
        &value.changed_indexers,
        &value.base,
        &value.patched,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 semantic census: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SemanticCensus,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn infrastructure(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SemanticCensus,
        kind: HistoricalV2SlotStageErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_history_v2_semantic_tests.rs"]
mod tests;
