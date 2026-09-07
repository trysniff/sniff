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
    HistoricalV2SemanticCensusFailurePhase, HistoricalV2SemanticIndexerVariantCensus,
    HistoricalV2SemanticMethod, HistoricalV2SemanticMethodObservation,
    HistoricalV2SemanticMethodStatus, HistoricalV2SemanticProcessEvidence,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SemanticSnapshotSide,
    HistoricalV2SemanticSymbol, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2SourceCensus, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, HistoricalV2StageResult, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryMethodCensusEntry, validate_historical_v2_source_census_commitment,
};
use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticIndexSet, SemanticIndexVariant, SemanticResolution,
    SemanticSymbol,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
#[cfg(test)]
use crate::semantic_indexer_runner::SemanticIndexerBatchOutcome;
use crate::semantic_indexer_runner::{
    SemanticIndexerProcessEvidence, SemanticIndexerRunFailure, SemanticIndexerRunFailureKind,
    SemanticIndexerRunPhase, SemanticVariantIndexerBatchOutcome,
};
use crate::semantic_method_join::{SemanticMethodBinding, SemanticMethodCoverage, join_methods};
use crate::types::FileRecord;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SEMANTIC_CENSUS_CONTRACT: &str = "sniffbench-historical-v2-compiler-semantic-census-v18";
const UNCHANGED_DOCUMENT_EXCLUSION: &str =
    "compiler omitted an unchanged source document outside the exact historical patch";
const VARIANT_DOCUMENT_EXCLUSION: &str =
    "source document is excluded from this exact compiler variant";
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

#[path = "benchmark_history_v2_semantic_public_surface.rs"]
mod public_surface;

#[path = "benchmark_history_v2_semantic_public_surface_validation.rs"]
mod public_surface_validation;

#[path = "benchmark_history_v2_semantic_stage_support.rs"]
mod stage_support;

#[path = "benchmark_history_v2_semantic_progress.rs"]
mod progress;

#[path = "benchmark_history_v2_semantic_variants.rs"]
mod variants;

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

#[cfg(test)]
fn build_semantic_snapshot(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    files: &[FileRecord],
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> Result<HistoricalV2SemanticSnapshotCensus, String> {
    let index_sets = indexes
        .iter()
        .map(|(kind, index)| {
            (
                *kind,
                SemanticIndexSet::Unqualified {
                    index: Box::new(index.clone()),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    build_semantic_snapshot_from_sets(
        root,
        source,
        files,
        changed_indexers,
        required_document_paths,
        &index_sets,
    )
}

fn build_semantic_snapshot_from_sets(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    files: &[FileRecord],
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
    index_sets: &BTreeMap<SemanticIndexerKind, SemanticIndexSet>,
) -> Result<HistoricalV2SemanticSnapshotCensus, String> {
    let expected_indexers = files
        .iter()
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?;
    let expected_indexers = expected_indexers
        .intersection(changed_indexers)
        .copied()
        .collect::<BTreeSet<_>>();
    if index_sets.keys().copied().collect::<BTreeSet<_>>() != expected_indexers {
        return Err("historical-v2 semantic indexer set is incomplete".to_string());
    }
    let expected_methods = expected_method_map(source)?;
    let mut methods = BTreeMap::<String, HistoricalV2SemanticMethod>::new();
    let mut symbols = BTreeMap::new();
    let mut public_bindings = Vec::new();
    let mut public_roots = Vec::new();
    let mut go_package_roots = Vec::new();
    let mut public_reexport_hops = BTreeMap::new();
    let mut public_surface_document_paths = BTreeSet::new();
    let mut indexers = Vec::new();
    for (kind, set) in index_sets {
        set.validate()?;
        match set {
            SemanticIndexSet::Unqualified { index } => process_semantic_variant(
                SemanticVariantInputs {
                    root,
                    source,
                    files,
                    required_document_paths,
                    expected_methods: &expected_methods,
                    kind: *kind,
                    index,
                    ignored_documents: None,
                },
                SemanticVariantOutputs {
                    methods: &mut methods,
                    symbols: &mut symbols,
                    public_bindings: &mut public_bindings,
                    public_roots: &mut public_roots,
                    go_package_roots: &mut go_package_roots,
                    public_reexport_hops: &mut public_reexport_hops,
                    public_surface_document_paths: &mut public_surface_document_paths,
                    indexers: &mut indexers,
                },
            )?,
            SemanticIndexSet::Qualified { variants } => {
                for qualified in variants.values() {
                    process_semantic_variant(
                        SemanticVariantInputs {
                            root,
                            source,
                            files,
                            required_document_paths,
                            expected_methods: &expected_methods,
                            kind: *kind,
                            index: &qualified.index,
                            ignored_documents: Some(&qualified.ignored_documents),
                        },
                        SemanticVariantOutputs {
                            methods: &mut methods,
                            symbols: &mut symbols,
                            public_bindings: &mut public_bindings,
                            public_roots: &mut public_roots,
                            go_package_roots: &mut go_package_roots,
                            public_reexport_hops: &mut public_reexport_hops,
                            public_surface_document_paths: &mut public_surface_document_paths,
                            indexers: &mut indexers,
                        },
                    )?;
                }
            }
        }
    }
    for file in files {
        let kind = indexer_for_language(&file.language)?;
        if index_sets.contains_key(&kind) {
            continue;
        }
        let path = file_repository_path(root, file)?;
        push_compiler_excluded_file_methods(
            &path,
            file,
            indexer_kind(kind),
            &SemanticIndexVariant::Unqualified,
            UNTOUCHED_LANGUAGE_EXCLUSION,
            &expected_methods,
            &mut methods,
        )?;
    }
    if methods.len() != expected_methods.len() {
        return Err(format!(
            "historical-v2 semantic census omitted {} method(s)",
            expected_methods.len().saturating_sub(methods.len())
        ));
    }
    let mut methods = methods.into_values().collect::<Vec<_>>();
    for method in &mut methods {
        method
            .observations
            .sort_by(|left, right| left.variant.cmp(&right.variant));
        if method.observations.is_empty()
            || method
                .observations
                .windows(2)
                .any(|pair| pair[0].variant >= pair[1].variant)
        {
            return Err(format!(
                "historical-v2 semantic method {} has incomplete compiler variants",
                method.parser_unit_id
            ));
        }
    }
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    public_bindings.sort();
    public_roots.sort();
    go_package_roots.sort();
    if public_roots.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("historical-v2 public roots are repeated".to_string());
    }
    if public_bindings.windows(2).any(|pair| {
        pair[0].variant == pair[1].variant
            && pair[0].declaration_unit_id == pair[1].declaration_unit_id
    }) {
        return Err("historical-v2 public surface repeats a declaration binding".to_string());
    }
    let public_reexport_hops = public_reexport_hops.into_values().collect::<Vec<_>>();
    let symbols = symbols.into_values().collect::<Vec<_>>();
    indexers.sort_by(|left, right| {
        left.census
            .indexer
            .cmp(&right.census.indexer)
            .then_with(|| left.variant.cmp(&right.variant))
    });
    let resolved_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                effective_method_status(method),
                HistoricalV2SemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                effective_method_status(method),
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
        public_root_count: public_roots.len(),
        public_roots,
        go_package_root_count: go_package_roots.len(),
        go_package_roots,
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

struct SemanticVariantInputs<'a> {
    root: &'a Path,
    source: &'a HistoricalV2SourceSnapshotCensus,
    files: &'a [FileRecord],
    required_document_paths: &'a BTreeSet<String>,
    expected_methods: &'a BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>,
    kind: SemanticIndexerKind,
    index: &'a SemanticIndex,
    ignored_documents: Option<&'a BTreeSet<RepositoryPath>>,
}

struct SemanticVariantOutputs<'a> {
    methods: &'a mut BTreeMap<String, HistoricalV2SemanticMethod>,
    symbols: &'a mut BTreeMap<
        (IntentionalBoundaryIndexerKind, SemanticIndexVariant, String),
        HistoricalV2SemanticSymbol,
    >,
    public_bindings: &'a mut Vec<super::HistoricalV2SemanticPublicBinding>,
    public_roots: &'a mut Vec<super::HistoricalV2SemanticPublicRoot>,
    go_package_roots: &'a mut Vec<super::HistoricalV2SemanticGoPackageRoot>,
    public_reexport_hops: &'a mut BTreeMap<
        (SemanticIndexVariant, String),
        super::HistoricalV2SemanticPublicReexportHop,
    >,
    public_surface_document_paths: &'a mut BTreeSet<String>,
    indexers: &'a mut Vec<HistoricalV2SemanticIndexerVariantCensus>,
}

fn process_semantic_variant(
    inputs: SemanticVariantInputs<'_>,
    outputs: SemanticVariantOutputs<'_>,
) -> Result<(), String> {
    let SemanticVariantInputs {
        root,
        source,
        files,
        required_document_paths,
        expected_methods,
        kind,
        index,
        ignored_documents,
    } = inputs;
    let SemanticVariantOutputs {
        methods,
        symbols,
        public_bindings,
        public_roots,
        go_package_roots,
        public_reexport_hops,
        public_surface_document_paths,
        indexers,
    } = outputs;
    let files_for_indexer = crate::semantic_indexer_runner::files_for_indexer(files, kind);
    let mut indexed_files = Vec::new();
    for file in files_for_indexer {
        let path = file_repository_path(root, &file)?;
        let repository_path = RepositoryPath(path.clone());
        if index.documents.contains_key(&repository_path) {
            indexed_files.push(file);
            continue;
        }
        let exclusion =
            if ignored_documents.is_some_and(|ignored| ignored.contains(&repository_path)) {
                VARIANT_DOCUMENT_EXCLUSION
            } else if ignored_documents.is_none() && !required_document_paths.contains(&path) {
                UNCHANGED_DOCUMENT_EXCLUSION
            } else {
                return Err(if required_document_paths.contains(&path) {
                    format!("historical-v2 compiler omitted changed source document {path}")
                } else {
                    format!(
                        "historical-v2 compiler variant omitted unclassified source document {path}"
                    )
                });
            };
        push_compiler_excluded_file_methods(
            &path,
            &file,
            indexer_kind(kind),
            &index.variant,
            exclusion,
            expected_methods,
            methods,
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
        let expected = expected_methods.get(&key).ok_or_else(|| {
            format!(
                "historical-v2 semantic index invented method {}::{}:{}-{}",
                key.0, key.1, key.2, key.3
            )
        })?;
        let observation =
            flatten_historical_method_observation(indexer_kind(kind), binding, index, symbols)?;
        push_method_observation(
            expected,
            &binding.method.file.0,
            indexer_kind(kind),
            observation,
            methods,
        )?;
    }
    let mut variant_bindings = Vec::new();
    let mut variant_roots = Vec::new();
    let mut variant_go_roots = Vec::new();
    bind_public_surface(
        PublicSurfaceBindingInputs {
            root,
            source,
            indexed_files: &indexed_files,
            kind,
            index,
        },
        PublicSurfaceBindingOutputs {
            symbols,
            bindings: &mut variant_bindings,
            roots: &mut variant_roots,
            go_package_roots: &mut variant_go_roots,
            reexport_hops: public_reexport_hops,
            public_surface_document_paths,
        },
    )?;
    public_bindings.extend(variant_bindings);
    public_roots.extend(variant_roots);
    go_package_roots.extend(variant_go_roots);
    let mut indexed_document_paths = index
        .documents
        .keys()
        .map(|path| path.0.clone())
        .collect::<Vec<_>>();
    indexed_document_paths.sort();
    let mut ignored_document_paths = ignored_documents
        .into_iter()
        .flat_map(|paths| paths.iter())
        .map(|path| path.0.clone())
        .collect::<Vec<_>>();
    ignored_document_paths.sort();
    indexers.push(HistoricalV2SemanticIndexerVariantCensus {
        variant: index.variant.clone(),
        indexed_document_paths,
        ignored_document_paths,
        census: summarize_index(kind, index)?,
    });
    Ok(())
}

fn flatten_historical_method_observation(
    indexer: IntentionalBoundaryIndexerKind,
    binding: &SemanticMethodBinding,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<
        (IntentionalBoundaryIndexerKind, SemanticIndexVariant, String),
        HistoricalV2SemanticSymbol,
    >,
) -> Result<HistoricalV2SemanticMethodObservation, String> {
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
            retain_symbol(
                symbols,
                indexer,
                &index.variant,
                symbol,
                false,
                false,
                false,
            )?;
            HistoricalV2SemanticMethodStatus::Resolved {
                symbol_id: value.0.clone(),
                joined_definition: binding.definition.as_ref().map(flatten_location),
            }
        }
    };
    Ok(HistoricalV2SemanticMethodObservation {
        variant: index.variant.clone(),
        status,
    })
}

fn retain_symbol(
    symbols: &mut BTreeMap<
        (IntentionalBoundaryIndexerKind, SemanticIndexVariant, String),
        HistoricalV2SemanticSymbol,
    >,
    indexer: IntentionalBoundaryIndexerKind,
    variant: &SemanticIndexVariant,
    symbol: &SemanticSymbol,
    is_public_surface: bool,
    is_public_root_evidence: bool,
    is_reexport_evidence: bool,
) -> Result<(), String> {
    let key = (indexer, variant.clone(), symbol.id.0.clone());
    let facts = flatten_symbol(symbol);
    if let Some(existing) = symbols.get_mut(&key) {
        if existing.symbol != facts {
            return Err(format!(
                "historical-v2 compiler changed repeated symbol facts for {}",
                symbol.id.0
            ));
        }
        existing.is_public_surface |= is_public_surface;
        existing.is_public_root_evidence |= is_public_root_evidence;
        existing.is_reexport_evidence |= is_reexport_evidence;
        return Ok(());
    }
    symbols.insert(
        key,
        HistoricalV2SemanticSymbol {
            indexer,
            variant: variant.clone(),
            is_public_surface,
            is_public_root_evidence,
            is_reexport_evidence,
            symbol: facts,
        },
    );
    Ok(())
}

#[cfg(test)]
use public_surface::semantic_position_at_byte;
use public_surface::{
    PublicSurfaceBindingInputs, PublicSurfaceBindingOutputs, bind_public_surface,
    reexport_expansion_declaration_unit_id,
};

fn push_compiler_excluded_file_methods(
    repository_path: &str,
    file: &FileRecord,
    indexer: IntentionalBoundaryIndexerKind,
    variant: &SemanticIndexVariant,
    reason: &str,
    expected_methods: &BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>,
    methods: &mut BTreeMap<String, HistoricalV2SemanticMethod>,
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
        let expected = expected_methods.get(&key).ok_or_else(|| {
            format!(
                "historical-v2 compiler exclusion invented method {}::{}:{}-{}",
                key.0, key.1, key.2, key.3
            )
        })?;
        push_method_observation(
            expected,
            &key.0,
            indexer,
            HistoricalV2SemanticMethodObservation {
                variant: variant.clone(),
                status: HistoricalV2SemanticMethodStatus::CompilerExcluded {
                    reason: reason.to_string(),
                },
            },
            methods,
        )?;
    }
    Ok(())
}

fn push_method_observation(
    expected: &IntentionalBoundaryMethodCensusEntry,
    repository_path: &str,
    indexer: IntentionalBoundaryIndexerKind,
    observation: HistoricalV2SemanticMethodObservation,
    methods: &mut BTreeMap<String, HistoricalV2SemanticMethod>,
) -> Result<(), String> {
    let method = methods
        .entry(expected.parser_unit_id.clone())
        .or_insert_with(|| HistoricalV2SemanticMethod {
            parser_unit_id: expected.parser_unit_id.clone(),
            repository_path: repository_path.to_string(),
            symbol_name: expected.symbol_name.clone(),
            start_line: expected.start_line,
            end_line: expected.end_line,
            indexer,
            observations: Vec::new(),
        });
    if method.repository_path != repository_path
        || method.symbol_name != expected.symbol_name
        || method.start_line != expected.start_line
        || method.end_line != expected.end_line
        || method.indexer != indexer
        || method
            .observations
            .iter()
            .any(|existing| existing.variant == observation.variant)
    {
        return Err(format!(
            "historical-v2 semantic method {} repeated or changed compiler identity",
            expected.parser_unit_id
        ));
    }
    method.observations.push(observation);
    Ok(())
}

pub(super) fn effective_method_status(
    method: &HistoricalV2SemanticMethod,
) -> HistoricalV2SemanticMethodStatus {
    if let Some(unresolved) = method.observations.iter().find_map(|observation| {
        if let HistoricalV2SemanticMethodStatus::Unresolved {
            reason,
            raw_target,
            detail,
        } = &observation.status
        {
            Some(HistoricalV2SemanticMethodStatus::Unresolved {
                reason: *reason,
                raw_target: raw_target.clone(),
                detail: detail.clone(),
            })
        } else {
            None
        }
    }) {
        return unresolved;
    }
    let resolved = method
        .observations
        .iter()
        .filter_map(|observation| {
            if let HistoricalV2SemanticMethodStatus::Resolved {
                symbol_id,
                joined_definition,
            } = &observation.status
            {
                Some((symbol_id.clone(), joined_definition.clone()))
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    match resolved.len() {
        0 => {
            let reasons = method
                .observations
                .iter()
                .filter_map(|observation| {
                    if let HistoricalV2SemanticMethodStatus::CompilerExcluded { reason } =
                        &observation.status
                    {
                        Some(reason.clone())
                    } else {
                        None
                    }
                })
                .collect::<BTreeSet<_>>();
            HistoricalV2SemanticMethodStatus::CompilerExcluded {
                reason: if reasons.len() == 1 {
                    reasons.into_iter().next().unwrap_or_default()
                } else {
                    "compiler excluded the method in every committed variant".to_string()
                },
            }
        }
        1 => resolved.into_iter().next().map_or_else(
            || HistoricalV2SemanticMethodStatus::Unresolved {
                reason: super::IntentionalBoundarySemanticUnresolvedReason::MissingIndexerFact,
                raw_target: None,
                detail: "compiler variant resolution disappeared".to_string(),
            },
            |(symbol_id, joined_definition)| HistoricalV2SemanticMethodStatus::Resolved {
                symbol_id,
                joined_definition,
            },
        ),
        _ => HistoricalV2SemanticMethodStatus::Unresolved {
            reason: super::IntentionalBoundarySemanticUnresolvedReason::Ambiguous,
            raw_target: None,
            detail: "compiler variants resolved the method to conflicting symbols or definitions"
                .to_string(),
        },
    }
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
    let mut committed = value.clone();
    committed.semantic_snapshot_sha256.clear();
    hash_json(&committed)
}

fn build_semantic_snapshot_from_index_sets(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    files: &[FileRecord],
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
    indexes: BTreeMap<SemanticIndexerKind, SemanticIndexSet>,
) -> Result<HistoricalV2SemanticSnapshotCensus, String> {
    build_semantic_snapshot_from_sets(
        root,
        source,
        files,
        changed_indexers,
        required_document_paths,
        &indexes,
    )
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
