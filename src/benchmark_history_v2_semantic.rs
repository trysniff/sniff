use super::history_v2_semantic_exclusion::{
    RETAINED_EVIDENCE_LIMIT, seal_semantic_census_exclusion,
};
use super::intentional_boundary_inventory::read_intentional_boundary_git_blobs;
use super::intentional_boundary_semantic::{
    flatten_location, flatten_symbol, summarize_index, unresolved_reason,
};
use super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2SemanticCensus, HistoricalV2SemanticCensusExclusion,
    HistoricalV2SemanticCensusExclusionReason, HistoricalV2SemanticCensusFailureEvidence,
    HistoricalV2SemanticCensusFailurePhase, HistoricalV2SemanticMethod,
    HistoricalV2SemanticMethodStatus, HistoricalV2SemanticProcessEvidence,
    HistoricalV2SemanticPublicBinding, HistoricalV2SemanticPublicBindingKind,
    HistoricalV2SemanticPublicReexportHop, HistoricalV2SemanticSnapshotCensus,
    HistoricalV2SemanticSnapshotSide, HistoricalV2SemanticSymbol, HistoricalV2SlotStage,
    HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind, HistoricalV2SourceCensus,
    HistoricalV2SourceFile, HistoricalV2SourcePublicBindingKind,
    HistoricalV2SourcePublicDeclaration, HistoricalV2SourcePublicNamespace,
    HistoricalV2SourcePublicReexport, HistoricalV2SourcePublicReexportKind,
    HistoricalV2SourcePublicSymbolKind, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, HistoricalV2StageResult, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryMethodCensusEntry, validate_historical_v2_source_census,
};
use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticLocation, SemanticPosition, SemanticPositionEncoding,
    SemanticResolution, SemanticSourceRange, SemanticSymbol, SemanticSymbolCategory,
    SemanticSymbolOrigin,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_indexer_runner::{
    SemanticIndexerBatchOutcome, SemanticIndexerProcessEvidence, SemanticIndexerRunFailure,
    SemanticIndexerRunFailureKind, SemanticIndexerRunPhase,
};
use crate::semantic_method_join::{SemanticMethodBinding, SemanticMethodCoverage, join_methods};
use crate::types::FileRecord;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SEMANTIC_CENSUS_CONTRACT: &str = "sniffbench-historical-v2-compiler-semantic-census-v7";
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

#[path = "benchmark_history_v2_semantic_public_surface_validation.rs"]
mod public_surface_validation;

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
    let mut methods = Vec::<HistoricalV2SemanticMethod>::with_capacity(source.method_count);
    let mut symbols = BTreeMap::new();
    let mut public_bindings = Vec::new();
    let mut public_reexport_hops = BTreeMap::new();
    let mut public_surface_document_paths = BTreeSet::new();
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
            methods.push(flatten_historical_method(
                indexer_kind(*kind),
                &expected,
                binding,
                index,
                &mut symbols,
            )?);
        }
        bind_public_surface(
            root,
            source,
            &indexed_files,
            *kind,
            index,
            &mut symbols,
            &mut public_bindings,
            &mut public_reexport_hops,
            &mut public_surface_document_paths,
        )?;
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
    public_bindings.sort();
    if public_bindings
        .windows(2)
        .any(|pair| pair[0].declaration_unit_id == pair[1].declaration_unit_id)
    {
        return Err("historical-v2 public surface repeats a declaration binding".to_string());
    }
    let public_reexport_hops = public_reexport_hops.into_values().collect::<Vec<_>>();
    let symbols = symbols.into_values().collect::<Vec<_>>();
    indexers.sort_by_key(|indexer| indexer.indexer);
    let resolved_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                HistoricalV2SemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                HistoricalV2SemanticMethodStatus::CompilerExcluded { .. }
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
        public_surface_document_paths: public_surface_document_paths.into_iter().collect(),
        indexers,
        methods,
        public_binding_count: public_bindings.len(),
        public_bindings,
        public_reexport_hop_count: public_reexport_hops.len(),
        public_reexport_hops,
        symbol_count: symbols.len(),
        public_symbol_count: symbols
            .iter()
            .filter(|symbol| symbol.is_public_surface)
            .count(),
        symbols,
        resolved_method_count,
        compiler_excluded_method_count,
        unresolved_method_count,
        semantic_snapshot_sha256: String::new(),
    };
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot)?;
    Ok(snapshot)
}

fn flatten_historical_method(
    indexer: IntentionalBoundaryIndexerKind,
    expected: &IntentionalBoundaryMethodCensusEntry,
    binding: &SemanticMethodBinding,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
) -> Result<HistoricalV2SemanticMethod, String> {
    let status = match (&binding.coverage, &binding.symbol) {
        (SemanticMethodCoverage::CompilerExcluded { reason }, _) => {
            HistoricalV2SemanticMethodStatus::CompilerExcluded {
                reason: reason.clone(),
            }
        }
        (
            _,
            SemanticResolution::Unresolved {
                reason,
                raw_target,
                detail,
            },
        ) => HistoricalV2SemanticMethodStatus::Unresolved {
            reason: unresolved_reason(*reason),
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
        (_, SemanticResolution::Resolved { value }) => {
            let symbol = index.symbols.get(value).ok_or_else(|| {
                format!(
                    "historical-v2 semantic binding references missing symbol {}",
                    value.0
                )
            })?;
            retain_symbol(symbols, indexer, symbol, false, false)?;
            HistoricalV2SemanticMethodStatus::Resolved {
                symbol_id: value.0.clone(),
                joined_definition: binding.definition.as_ref().map(flatten_location),
            }
        }
    };
    Ok(HistoricalV2SemanticMethod {
        parser_unit_id: expected.parser_unit_id.clone(),
        repository_path: binding.method.file.0.clone(),
        symbol_name: binding.method.name.clone(),
        start_line: binding.method.start_line as usize,
        end_line: binding.method.end_line as usize,
        indexer,
        status,
    })
}

fn retain_symbol(
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    indexer: IntentionalBoundaryIndexerKind,
    symbol: &SemanticSymbol,
    is_public_surface: bool,
    is_reexport_evidence: bool,
) -> Result<(), String> {
    let key = (indexer, symbol.id.0.clone());
    let facts = flatten_symbol(symbol);
    if let Some(existing) = symbols.get_mut(&key) {
        if existing.symbol != facts {
            return Err(format!(
                "historical-v2 compiler changed repeated symbol facts for {}",
                symbol.id.0
            ));
        }
        existing.is_public_surface |= is_public_surface;
        existing.is_reexport_evidence |= is_reexport_evidence;
        return Ok(());
    }
    symbols.insert(
        key,
        HistoricalV2SemanticSymbol {
            indexer,
            is_public_surface,
            is_reexport_evidence,
            symbol: facts,
        },
    );
    Ok(())
}

fn bind_public_surface(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    indexed_files: &[FileRecord],
    kind: SemanticIndexerKind,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    bindings: &mut Vec<HistoricalV2SemanticPublicBinding>,
    reexport_hops: &mut BTreeMap<String, HistoricalV2SemanticPublicReexportHop>,
    public_surface_document_paths: &mut BTreeSet<String>,
) -> Result<(), String> {
    let records = indexed_files
        .iter()
        .map(|file| Ok((file_repository_path(root, file)?, file)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let source_files = source
        .source_files
        .iter()
        .filter(|file| {
            file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required
                && indexer_for_language(&file.language) == Ok(kind)
        })
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut direct_bindings = BTreeMap::new();
    for file in source_files.values() {
        let path = RepositoryPath(file.repository_path.clone());
        let Some(document) = index.documents.get(&path) else {
            continue;
        };
        public_surface_document_paths.insert(file.repository_path.clone());
        if file.public_surface_coverage != super::HistoricalV2PublicSurfaceCoverage::Complete {
            return Err(format!(
                "historical-v2 public-surface collector is incomplete for {}",
                file.repository_path
            ));
        }
        let record = records.get(&file.repository_path).ok_or_else(|| {
            format!(
                "historical-v2 public-surface source is missing from parser records: {}",
                file.repository_path
            )
        })?;
        for declaration in &file.public_declarations {
            let location = declaration_location(
                file,
                declaration,
                &record.source,
                document.position_encoding,
            )?;
            let (binding, symbol) = match declaration.binding {
                HistoricalV2SourcePublicBindingKind::Definition => (
                    HistoricalV2SemanticPublicBindingKind::Definition,
                    symbol_at_exact_definition(index, declaration, &location)?,
                ),
                HistoricalV2SourcePublicBindingKind::Reference => (
                    HistoricalV2SemanticPublicBindingKind::Reference,
                    symbol_at_exact_reference(index, document, declaration, &location)?,
                ),
            };
            retain_symbol(symbols, indexer_kind(kind), symbol, true, false)?;
            let public_binding = HistoricalV2SemanticPublicBinding {
                indexer: indexer_kind(kind),
                surface_unit_id: declaration.surface_unit_id.clone(),
                declaration_unit_id: declaration.declaration_unit_id.clone(),
                origin_declaration_unit_id: declaration.declaration_unit_id.clone(),
                reexport_path: Vec::new(),
                repository_path: file.repository_path.clone(),
                symbol_id: symbol.id.0.clone(),
                binding,
                position_encoding: document.position_encoding,
                compiler_anchor: flatten_location(&location),
            };
            if direct_bindings
                .insert(
                    declaration.declaration_unit_id.clone(),
                    public_binding.clone(),
                )
                .is_some()
            {
                return Err("historical-v2 repeated a direct public declaration".to_string());
            }
            bindings.push(public_binding);
        }
    }

    let mut cache = BTreeMap::new();
    for file in source_files
        .values()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
    {
        let slots = resolve_file_public_slots(
            file,
            &source_files,
            &records,
            &direct_bindings,
            kind,
            index,
            symbols,
            reexport_hops,
            &mut cache,
            &mut Vec::new(),
        )?;
        for slot in slots
            .into_iter()
            .filter(|slot| !slot.binding.reexport_path.is_empty())
        {
            bindings.push(slot.binding);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPublicSlot {
    name: String,
    owner: Option<String>,
    namespace: HistoricalV2SourcePublicNamespace,
    kind: HistoricalV2SourcePublicSymbolKind,
    binding: HistoricalV2SemanticPublicBinding,
}

#[allow(clippy::too_many_arguments)]
fn resolve_file_public_slots(
    file: &HistoricalV2SourceFile,
    source_files: &BTreeMap<&str, &HistoricalV2SourceFile>,
    records: &BTreeMap<String, &FileRecord>,
    direct_bindings: &BTreeMap<String, HistoricalV2SemanticPublicBinding>,
    kind: SemanticIndexerKind,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    reexport_hops: &mut BTreeMap<String, HistoricalV2SemanticPublicReexportHop>,
    cache: &mut BTreeMap<String, Vec<ResolvedPublicSlot>>,
    stack: &mut Vec<String>,
) -> Result<Vec<ResolvedPublicSlot>, String> {
    if let Some(cached) = cache.get(&file.repository_path) {
        return Ok(cached.clone());
    }
    if stack.contains(&file.repository_path) {
        stack.push(file.repository_path.clone());
        return Err(format!(
            "historical-v2 compiler found a cyclic public re-export path: {}",
            stack.join(" -> ")
        ));
    }
    stack.push(file.repository_path.clone());
    if file.public_surface_coverage != super::HistoricalV2PublicSurfaceCoverage::Complete {
        return Err(format!(
            "historical-v2 public-surface collector is incomplete for {}",
            file.repository_path
        ));
    }
    let document = index
        .documents
        .get(&RepositoryPath(file.repository_path.clone()))
        .ok_or_else(|| {
            format!(
                "historical-v2 compiler omitted a public-surface document: {}",
                file.repository_path
            )
        })?;
    let record = records.get(&file.repository_path).ok_or_else(|| {
        format!(
            "historical-v2 public-surface source is missing from parser records: {}",
            file.repository_path
        )
    })?;
    let mut slots = file
        .public_declarations
        .iter()
        .map(|declaration| {
            let binding = direct_bindings
                .get(&declaration.declaration_unit_id)
                .ok_or_else(|| {
                    format!(
                        "historical-v2 compiler omitted direct public binding {}",
                        declaration.declaration_unit_id
                    )
                })?;
            Ok(ResolvedPublicSlot {
                name: declaration.name.clone(),
                owner: declaration.owner.clone(),
                namespace: declaration.namespace,
                kind: declaration.kind,
                binding: binding.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let direct_surfaces = slots
        .iter()
        .map(|slot| slot.binding.surface_unit_id.clone())
        .collect::<BTreeSet<_>>();
    let mut wildcard_symbols = BTreeMap::<String, String>::new();

    for reexport in &file.public_reexports {
        let (hop, module_symbol) =
            resolve_public_reexport(file, reexport, &record.source, document, kind, index)?;
        retain_symbol(symbols, indexer_kind(kind), module_symbol, false, true)?;
        if let Some(existing) = reexport_hops.insert(reexport.reexport_unit_id.clone(), hop.clone())
            && existing != hop
        {
            return Err("historical-v2 compiler changed a repeated re-export hop".to_string());
        }
        let target = source_files
            .get(hop.target_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "historical-v2 public re-export target is not an enumerable repository source: {}",
                    hop.target_repository_path
                )
            })?;
        if indexer_for_language(&target.language)? != kind {
            return Err("historical-v2 public re-export crossed compiler indexers".to_string());
        }
        let target_slots = resolve_file_public_slots(
            target,
            source_files,
            records,
            direct_bindings,
            kind,
            index,
            symbols,
            reexport_hops,
            cache,
            stack,
        )?;
        match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                for target_slot in target_slots
                    .into_iter()
                    .filter(|slot| slot.name != "default")
                {
                    let expanded = expand_reexport_slot(file, reexport, &hop, target_slot, None)?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        continue;
                    }
                    if let Some(existing) = wildcard_symbols.insert(
                        expanded.binding.surface_unit_id.clone(),
                        expanded.binding.symbol_id.clone(),
                    ) && existing != expanded.binding.symbol_id
                    {
                        return Err(format!(
                            "historical-v2 compiler found an ambiguous wildcard export in {}",
                            file.repository_path
                        ));
                    }
                    slots.push(expanded);
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                let name = reexport.name.as_deref().ok_or_else(|| {
                    "historical-v2 namespace re-export has no exposed name".to_string()
                })?;
                if target_slots.is_empty() {
                    return Err(format!(
                        "historical-v2 namespace re-export target has no enumerable bindings: {}",
                        hop.target_repository_path
                    ));
                }
                for target_slot in target_slots {
                    let expanded =
                        expand_reexport_slot(file, reexport, &hop, target_slot, Some(name))?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        return Err(format!(
                            "historical-v2 namespace re-export collides with a direct export in {}",
                            file.repository_path
                        ));
                    }
                    slots.push(expanded);
                }
            }
        }
    }
    stack.pop();
    slots.sort_by(|left, right| left.binding.cmp(&right.binding));
    cache.insert(file.repository_path.clone(), slots.clone());
    Ok(slots)
}

fn expand_reexport_slot(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    hop: &HistoricalV2SemanticPublicReexportHop,
    target: ResolvedPublicSlot,
    namespace_name: Option<&str>,
) -> Result<ResolvedPublicSlot, String> {
    let (name, owner, namespace, kind) = namespace_name.map_or_else(
        || {
            (
                target.name.clone(),
                target.owner.clone(),
                target.namespace,
                target.kind,
            )
        },
        |name| {
            (
                name.to_string(),
                None,
                HistoricalV2SourcePublicNamespace::Module,
                HistoricalV2SourcePublicSymbolKind::Module,
            )
        },
    );
    let module_identity = super::history_v2_source_census::public_module_identity(
        &file.repository_path,
        &file.language,
    );
    let surface_unit_id = super::history_v2_source_census::historical_public_surface_unit_id(
        &file.language,
        &module_identity,
        &name,
        owner.as_deref(),
        namespace,
        kind,
    )?;
    let mut reexport_path = vec![reexport.reexport_unit_id.clone()];
    reexport_path.extend(target.binding.reexport_path);
    let declaration_unit_id = reexport_expansion_declaration_unit_id(
        &surface_unit_id,
        &file.repository_path,
        &target.binding.origin_declaration_unit_id,
        &target.binding.symbol_id,
        &reexport_path,
    )?;
    Ok(ResolvedPublicSlot {
        name,
        owner,
        namespace,
        kind,
        binding: HistoricalV2SemanticPublicBinding {
            indexer: hop.indexer,
            surface_unit_id,
            declaration_unit_id,
            origin_declaration_unit_id: target.binding.origin_declaration_unit_id,
            reexport_path,
            repository_path: file.repository_path.clone(),
            symbol_id: target.binding.symbol_id,
            binding: HistoricalV2SemanticPublicBindingKind::ReexportExpansion,
            position_encoding: hop.position_encoding,
            compiler_anchor: hop.compiler_anchor.clone(),
        },
    })
}

fn reexport_expansion_declaration_unit_id(
    surface_unit_id: &str,
    repository_path: &str,
    origin_declaration_unit_id: &str,
    symbol_id: &str,
    reexport_path: &[String],
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-public-reexport-expansion-v1",
        surface_unit_id,
        repository_path,
        origin_declaration_unit_id,
        symbol_id,
        reexport_path,
    ))
    .map(|hash| format!("h2x-v1:{hash}"))
}

fn resolve_public_reexport<'a>(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    source: &str,
    document: &crate::semantic_index::SemanticDocument,
    kind: SemanticIndexerKind,
    index: &'a SemanticIndex,
) -> Result<(HistoricalV2SemanticPublicReexportHop, &'a SemanticSymbol), String> {
    let location = reexport_location(file, reexport, source, document.position_encoding)?;
    let occurrences = document
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.range == location.range)
        .collect::<Vec<_>>();
    let [occurrence] = occurrences.as_slice() else {
        return Err(format!(
            "historical-v2 compiler emitted {} occurrence(s) at re-export {}",
            occurrences.len(),
            reexport.reexport_unit_id
        ));
    };
    let symbol_id = occurrence.symbol.as_ref().ok_or_else(|| {
        format!(
            "historical-v2 compiler left re-export {} unresolved",
            reexport.reexport_unit_id
        )
    })?;
    let symbol = index.symbols.get(symbol_id).ok_or_else(|| {
        format!(
            "historical-v2 re-export points to missing compiler module {}",
            symbol_id.0
        )
    })?;
    if symbol.origin != SemanticSymbolOrigin::Repository
        || !symbol.ambiguity_notes.is_empty()
        || !matches!(
            symbol.kind.category,
            SemanticSymbolCategory::Module
                | SemanticSymbolCategory::Namespace
                | SemanticSymbolCategory::Package
        )
    {
        return Err(format!(
            "historical-v2 re-export {} has no unambiguous repository module",
            reexport.reexport_unit_id
        ));
    }
    let targets = symbol
        .definitions
        .iter()
        .map(|definition| definition.document.0.clone())
        .collect::<BTreeSet<_>>();
    if targets.len() != 1 {
        return Err(format!(
            "historical-v2 compiler resolved re-export {} to {} module document(s)",
            reexport.reexport_unit_id,
            targets.len()
        ));
    }
    let target_repository_path = targets.iter().next().unwrap();
    if !index
        .documents
        .contains_key(&RepositoryPath(target_repository_path.clone()))
    {
        return Err(format!(
            "historical-v2 compiler omitted re-export target document {}",
            target_repository_path
        ));
    }
    Ok((
        HistoricalV2SemanticPublicReexportHop {
            indexer: indexer_kind(kind),
            reexport_unit_id: reexport.reexport_unit_id.clone(),
            repository_path: file.repository_path.clone(),
            target_repository_path: target_repository_path.clone(),
            module_symbol_id: symbol.id.0.clone(),
            position_encoding: document.position_encoding,
            compiler_anchor: flatten_location(&location),
        },
        symbol,
    ))
}

fn reexport_location(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticLocation, String> {
    let range = reexport.identifier;
    let valid_range = range.start < range.end
        && range.end <= source.len()
        && source.is_char_boundary(range.start)
        && source.is_char_boundary(range.end);
    let valid_text = valid_range
        && match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                let text = &source[range.start..range.end];
                text.len() >= 2
                    && matches!(
                        (text.as_bytes()[0], text.as_bytes()[text.len() - 1]),
                        (b'\'', b'\'') | (b'"', b'"')
                    )
                    && text[1..text.len() - 1] == reexport.source_module
            }
            HistoricalV2SourcePublicReexportKind::Namespace => reexport
                .name
                .as_deref()
                .is_some_and(|name| &source[range.start..range.end] == name),
        };
    if !valid_text {
        return Err(format!(
            "historical-v2 public re-export range changed: {}::{}",
            file.repository_path, reexport.reexport_unit_id
        ));
    }
    Ok(SemanticLocation {
        document: RepositoryPath(file.repository_path.clone()),
        range: SemanticSourceRange {
            start: semantic_position_at_byte(source, range.start, encoding)?,
            end: semantic_position_at_byte(source, range.end, encoding)?,
        },
    })
}

fn symbol_at_exact_definition<'a>(
    index: &'a SemanticIndex,
    declaration: &HistoricalV2SourcePublicDeclaration,
    location: &SemanticLocation,
) -> Result<&'a SemanticSymbol, String> {
    let candidates = index
        .symbols
        .values()
        .filter(|symbol| {
            valid_public_symbol(declaration, symbol) && symbol.definitions.contains(location)
        })
        .collect::<Vec<_>>();
    let [symbol] = candidates.as_slice() else {
        return Err(format!(
            "historical-v2 compiler resolved {} public symbol(s) at the exact definition of {}::{}",
            candidates.len(),
            location.document.0,
            declaration.name
        ));
    };
    Ok(*symbol)
}

fn symbol_at_exact_reference<'a>(
    index: &'a SemanticIndex,
    document: &crate::semantic_index::SemanticDocument,
    declaration: &HistoricalV2SourcePublicDeclaration,
    location: &SemanticLocation,
) -> Result<&'a SemanticSymbol, String> {
    let occurrences = document
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.range == location.range)
        .collect::<Vec<_>>();
    let [occurrence] = occurrences.as_slice() else {
        return Err(format!(
            "historical-v2 compiler emitted {} occurrence(s) at the exact public reference of {}::{}",
            occurrences.len(),
            location.document.0,
            declaration.name
        ));
    };
    let symbol_id = occurrence.symbol.as_ref().ok_or_else(|| {
        format!(
            "historical-v2 compiler left the exact public reference unresolved at {}::{}",
            location.document.0, declaration.name
        )
    })?;
    let symbol = index.symbols.get(symbol_id).ok_or_else(|| {
        format!(
            "historical-v2 public reference points to missing compiler symbol {}",
            symbol_id.0
        )
    })?;
    if !valid_public_symbol(declaration, symbol) {
        return Err(format!(
            "historical-v2 public reference has an incompatible compiler symbol at {}::{}",
            location.document.0, declaration.name
        ));
    }
    Ok(symbol)
}

fn valid_public_symbol(
    declaration: &HistoricalV2SourcePublicDeclaration,
    symbol: &SemanticSymbol,
) -> bool {
    symbol.origin == SemanticSymbolOrigin::Repository
        && symbol.ambiguity_notes.is_empty()
        && compatible_public_symbol_kind(declaration.kind, symbol.kind.category)
}

fn declaration_location(
    file: &HistoricalV2SourceFile,
    declaration: &HistoricalV2SourcePublicDeclaration,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticLocation, String> {
    let range = declaration.identifier;
    if range.start >= range.end
        || range.end > source.len()
        || declaration.exposed_identifier.start >= declaration.exposed_identifier.end
        || declaration.exposed_identifier.end > source.len()
        || !source.is_char_boundary(range.start)
        || !source.is_char_boundary(range.end)
        || !source.is_char_boundary(declaration.exposed_identifier.start)
        || !source.is_char_boundary(declaration.exposed_identifier.end)
        || source[declaration.exposed_identifier.start..declaration.exposed_identifier.end]
            != declaration.name
        || &source[range.start..range.end]
            != match declaration.binding {
                HistoricalV2SourcePublicBindingKind::Definition => declaration.target_name.as_str(),
                HistoricalV2SourcePublicBindingKind::Reference => declaration.name.as_str(),
            }
    {
        return Err(format!(
            "historical-v2 public declaration range changed: {}::{}",
            file.repository_path, declaration.name
        ));
    }
    Ok(SemanticLocation {
        document: RepositoryPath(file.repository_path.clone()),
        range: SemanticSourceRange {
            start: semantic_position_at_byte(source, range.start, encoding)?,
            end: semantic_position_at_byte(source, range.end, encoding)?,
        },
    })
}

fn semantic_position_at_byte(
    source: &str,
    offset: usize,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticPosition, String> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err("historical-v2 public declaration is not on a UTF-8 boundary".to_string());
    }
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let line_prefix = &source[line_start..offset];
    let character = match encoding {
        SemanticPositionEncoding::Utf8 => line_prefix.len(),
        SemanticPositionEncoding::Utf16 => line_prefix.encode_utf16().count(),
        SemanticPositionEncoding::Utf32 => line_prefix.chars().count(),
    };
    Ok(SemanticPosition {
        line: u32::try_from(line)
            .map_err(|_| "historical-v2 public declaration line exceeds u32".to_string())?,
        character: u32::try_from(character)
            .map_err(|_| "historical-v2 public declaration column exceeds u32".to_string())?,
    })
}

fn compatible_public_symbol_kind(
    declaration: HistoricalV2SourcePublicSymbolKind,
    compiler: SemanticSymbolCategory,
) -> bool {
    matches!(
        (declaration, compiler),
        (
            HistoricalV2SourcePublicSymbolKind::CompilerDefined,
            SemanticSymbolCategory::Callable
                | SemanticSymbolCategory::Constructor
                | SemanticSymbolCategory::Method
                | SemanticSymbolCategory::Type
                | SemanticSymbolCategory::TraitOrInterface
                | SemanticSymbolCategory::Module
                | SemanticSymbolCategory::Namespace
                | SemanticSymbolCategory::Package
                | SemanticSymbolCategory::FieldOrProperty
                | SemanticSymbolCategory::Variable
                | SemanticSymbolCategory::Constant
                | SemanticSymbolCategory::Macro
        ) | (
            HistoricalV2SourcePublicSymbolKind::Callable,
            SemanticSymbolCategory::Callable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Module,
            SemanticSymbolCategory::Module
                | SemanticSymbolCategory::Namespace
                | SemanticSymbolCategory::Package
        ) | (
            HistoricalV2SourcePublicSymbolKind::Method,
            SemanticSymbolCategory::Method
        ) | (
            HistoricalV2SourcePublicSymbolKind::Type,
            SemanticSymbolCategory::Type | SemanticSymbolCategory::TraitOrInterface
        ) | (
            HistoricalV2SourcePublicSymbolKind::Field,
            SemanticSymbolCategory::FieldOrProperty
        ) | (
            HistoricalV2SourcePublicSymbolKind::Variable,
            SemanticSymbolCategory::Variable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Constant,
            SemanticSymbolCategory::Constant
        )
    )
}

fn push_compiler_excluded_file_methods(
    repository_path: &str,
    file: &FileRecord,
    indexer: IntentionalBoundaryIndexerKind,
    reason: &str,
    expected_methods: &mut BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>,
    methods: &mut Vec<HistoricalV2SemanticMethod>,
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
        methods.push(HistoricalV2SemanticMethod {
            parser_unit_id: expected.parser_unit_id,
            repository_path: key.0,
            symbol_name: expected.symbol_name,
            start_line: expected.start_line,
            end_line: expected.end_line,
            indexer,
            status: HistoricalV2SemanticMethodStatus::CompilerExcluded {
                reason: reason.to_string(),
            },
        });
    }
    Ok(())
}

fn snapshot_file_records(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
) -> Result<Vec<FileRecord>, String> {
    let mut records = Vec::with_capacity(source.source_files.len());
    let required_files = source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .collect::<Vec<_>>();
    let requests = required_files
        .iter()
        .map(|file| (file.object_id.as_str(), file.byte_length))
        .collect::<Vec<_>>();
    let blobs = read_intentional_boundary_git_blobs(root, &requests)?;
    for (file, bytes) in required_files.into_iter().zip(blobs) {
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
        &value.public_bindings,
        &value.symbols,
        value.symbol_count,
        value.public_binding_count,
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
