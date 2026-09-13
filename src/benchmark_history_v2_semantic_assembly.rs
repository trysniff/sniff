use super::super::{
    HistoricalV2SemanticGoPackageRoot, HistoricalV2SemanticKotlinCompilationRoot,
    HistoricalV2SemanticPublicBinding, HistoricalV2SemanticPublicReexportHop,
    HistoricalV2SemanticPublicRoot,
};
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub(super) enum SemanticSnapshotAssemblyError {
    Evidence(String),
    Progress(String),
}

#[cfg(test)]
impl SemanticSnapshotAssemblyError {
    pub(super) fn into_detail(self) -> String {
        match self {
            Self::Evidence(detail) | Self::Progress(detail) => detail,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HistoricalV2SemanticVariantContribution {
    pub(super) indexer: HistoricalV2SemanticIndexerVariantCensus,
    pub(super) methods: Vec<HistoricalV2SemanticMethod>,
    pub(super) symbols: Vec<HistoricalV2SemanticSymbol>,
    pub(super) public_bindings: Vec<HistoricalV2SemanticPublicBinding>,
    pub(super) public_roots: Vec<HistoricalV2SemanticPublicRoot>,
    pub(super) go_package_roots: Vec<HistoricalV2SemanticGoPackageRoot>,
    pub(super) kotlin_compilation_roots: Vec<HistoricalV2SemanticKotlinCompilationRoot>,
    pub(super) public_reexport_hops: Vec<HistoricalV2SemanticPublicReexportHop>,
    pub(super) public_surface_document_paths: Vec<String>,
}

pub(super) struct SemanticContributionProgress<'a> {
    pub(super) store: &'a progress::HistoricalV2SemanticProgress,
    pub(super) materialization: &'a HistoricalV2Materialization,
    pub(super) source_census: &'a HistoricalV2SourceCensus,
    pub(super) side: HistoricalV2SemanticSnapshotSide,
}

#[derive(Default)]
struct SemanticSnapshotAccumulator {
    methods: BTreeMap<String, HistoricalV2SemanticMethod>,
    symbols: BTreeMap<
        (IntentionalBoundaryIndexerKind, SemanticIndexVariant, String),
        HistoricalV2SemanticSymbol,
    >,
    public_bindings: Vec<HistoricalV2SemanticPublicBinding>,
    public_roots: Vec<HistoricalV2SemanticPublicRoot>,
    go_package_roots: Vec<HistoricalV2SemanticGoPackageRoot>,
    kotlin_compilation_roots: Vec<HistoricalV2SemanticKotlinCompilationRoot>,
    public_reexport_hops:
        BTreeMap<(SemanticIndexVariant, String), HistoricalV2SemanticPublicReexportHop>,
    public_surface_document_paths: BTreeSet<String>,
    indexers: Vec<HistoricalV2SemanticIndexerVariantCensus>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_semantic_snapshot_from_sets(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    files: &[FileRecord],
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
    index_sets: &BTreeMap<SemanticIndexerKind, SemanticIndexSet>,
    progress: Option<SemanticContributionProgress<'_>>,
) -> Result<HistoricalV2SemanticSnapshotCensus, SemanticSnapshotAssemblyError> {
    let expected_indexers = files
        .iter()
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()
        .map_err(SemanticSnapshotAssemblyError::Evidence)?;
    let expected_indexers = expected_indexers
        .intersection(changed_indexers)
        .copied()
        .collect::<BTreeSet<_>>();
    if index_sets.keys().copied().collect::<BTreeSet<_>>() != expected_indexers {
        return Err(SemanticSnapshotAssemblyError::Evidence(
            "historical-v2 semantic indexer set is incomplete".to_string(),
        ));
    }
    let expected_methods =
        expected_method_map(source).map_err(SemanticSnapshotAssemblyError::Evidence)?;
    let mut accumulator = SemanticSnapshotAccumulator::default();
    for (kind, set) in index_sets {
        set.validate()
            .map_err(SemanticSnapshotAssemblyError::Evidence)?;
        match set {
            SemanticIndexSet::Unqualified { index } => {
                process_variant(
                    VariantAssemblyInputs {
                        root,
                        source,
                        files,
                        changed_indexers,
                        required_document_paths,
                        expected_methods: &expected_methods,
                        kind: *kind,
                        index,
                        ignored_documents: None,
                    },
                    progress.as_ref(),
                    &mut accumulator,
                )?;
            }
            SemanticIndexSet::Qualified { variants } => {
                for qualified in variants.values() {
                    process_variant(
                        VariantAssemblyInputs {
                            root,
                            source,
                            files,
                            changed_indexers,
                            required_document_paths,
                            expected_methods: &expected_methods,
                            kind: *kind,
                            index: &qualified.index,
                            ignored_documents: Some(&qualified.ignored_documents),
                        },
                        progress.as_ref(),
                        &mut accumulator,
                    )?;
                }
            }
        }
    }
    add_untouched_language_methods(
        root,
        files,
        index_sets,
        &expected_methods,
        &mut accumulator.methods,
    )
    .map_err(SemanticSnapshotAssemblyError::Evidence)?;
    finish_snapshot(
        source,
        required_document_paths,
        expected_methods.len(),
        accumulator,
    )
    .map_err(SemanticSnapshotAssemblyError::Evidence)
}

struct VariantAssemblyInputs<'a> {
    root: &'a Path,
    source: &'a HistoricalV2SourceSnapshotCensus,
    files: &'a [FileRecord],
    changed_indexers: &'a BTreeSet<SemanticIndexerKind>,
    required_document_paths: &'a BTreeSet<String>,
    expected_methods: &'a BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>,
    kind: SemanticIndexerKind,
    index: &'a SemanticIndex,
    ignored_documents: Option<&'a BTreeSet<RepositoryPath>>,
}

fn process_variant(
    inputs: VariantAssemblyInputs<'_>,
    progress: Option<&SemanticContributionProgress<'_>>,
    accumulator: &mut SemanticSnapshotAccumulator,
) -> Result<(), SemanticSnapshotAssemblyError> {
    let indexer = indexer_variant_census(inputs.kind, inputs.index, inputs.ignored_documents)
        .map_err(SemanticSnapshotAssemblyError::Evidence)?;
    let contribution = match progress {
        Some(progress) => match progress
            .store
            .load_contribution(
                progress.materialization,
                progress.source_census,
                progress.side,
                inputs.source,
                inputs.changed_indexers,
                inputs.required_document_paths,
                &indexer,
            )
            .map_err(SemanticSnapshotAssemblyError::Progress)?
        {
            Some(contribution) => contribution,
            None => {
                let contribution = build_variant_contribution(&inputs, &indexer)
                    .map_err(SemanticSnapshotAssemblyError::Evidence)?;
                progress
                    .store
                    .publish_contribution(
                        progress.materialization,
                        progress.source_census,
                        progress.side,
                        inputs.source,
                        inputs.changed_indexers,
                        inputs.required_document_paths,
                        &indexer,
                        contribution,
                    )
                    .map_err(SemanticSnapshotAssemblyError::Progress)?
            }
        },
        None => build_variant_contribution(&inputs, &indexer)
            .map_err(SemanticSnapshotAssemblyError::Evidence)?,
    };
    merge_variant_contribution(accumulator, contribution)
        .map_err(SemanticSnapshotAssemblyError::Evidence)
}

fn indexer_variant_census(
    kind: SemanticIndexerKind,
    index: &SemanticIndex,
    ignored_documents: Option<&BTreeSet<RepositoryPath>>,
) -> Result<HistoricalV2SemanticIndexerVariantCensus, String> {
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
    Ok(HistoricalV2SemanticIndexerVariantCensus {
        variant: index.variant.clone(),
        indexed_document_paths,
        ignored_document_paths,
        census: summarize_index(kind, index)?,
    })
}

fn build_variant_contribution(
    inputs: &VariantAssemblyInputs<'_>,
    indexer: &HistoricalV2SemanticIndexerVariantCensus,
) -> Result<HistoricalV2SemanticVariantContribution, String> {
    let mut methods = BTreeMap::new();
    let mut symbols = BTreeMap::new();
    let mut public_bindings = Vec::new();
    let mut public_roots = Vec::new();
    let mut go_package_roots = Vec::new();
    let mut kotlin_compilation_roots = Vec::new();
    let mut public_reexport_hops = BTreeMap::new();
    let mut public_surface_document_paths = BTreeSet::new();
    let mut indexers = Vec::new();
    process_semantic_variant(
        SemanticVariantInputs {
            root: inputs.root,
            source: inputs.source,
            files: inputs.files,
            required_document_paths: inputs.required_document_paths,
            expected_methods: inputs.expected_methods,
            kind: inputs.kind,
            index: inputs.index,
            ignored_documents: inputs.ignored_documents,
            indexer_census: indexer,
        },
        SemanticVariantOutputs {
            methods: &mut methods,
            symbols: &mut symbols,
            public_bindings: &mut public_bindings,
            public_roots: &mut public_roots,
            go_package_roots: &mut go_package_roots,
            kotlin_compilation_roots: &mut kotlin_compilation_roots,
            public_reexport_hops: &mut public_reexport_hops,
            public_surface_document_paths: &mut public_surface_document_paths,
            indexers: &mut indexers,
        },
    )?;
    if indexers.len() != 1 || &indexers[0] != indexer {
        return Err("historical-v2 semantic variant emitted an invalid indexer census".to_string());
    }
    let mut methods = methods.into_values().collect::<Vec<_>>();
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    let mut symbols = symbols.into_values().collect::<Vec<_>>();
    symbols.sort_by(symbol_key_cmp);
    public_bindings.sort();
    public_roots.sort();
    go_package_roots.sort();
    kotlin_compilation_roots.sort();
    let contribution = HistoricalV2SemanticVariantContribution {
        indexer: indexer.clone(),
        methods,
        symbols,
        public_bindings,
        public_roots,
        go_package_roots,
        kotlin_compilation_roots,
        public_reexport_hops: public_reexport_hops.into_values().collect(),
        public_surface_document_paths: public_surface_document_paths.into_iter().collect(),
    };
    validate_variant_contribution(&contribution, indexer)?;
    Ok(contribution)
}

pub(super) fn validate_variant_contribution(
    contribution: &HistoricalV2SemanticVariantContribution,
    expected_indexer: &HistoricalV2SemanticIndexerVariantCensus,
) -> Result<(), String> {
    let variant = &expected_indexer.variant;
    let indexer = expected_indexer.census.indexer;
    if &contribution.indexer != expected_indexer
        || contribution
            .methods
            .windows(2)
            .any(|pair| pair[0].parser_unit_id >= pair[1].parser_unit_id)
        || contribution.methods.iter().any(|method| {
            method.indexer != indexer
                || method.observations.len() != 1
                || method.observations[0].variant != *variant
        })
        || contribution
            .symbols
            .windows(2)
            .any(|pair| symbol_key_cmp(&pair[0], &pair[1]).is_ge())
        || contribution
            .symbols
            .iter()
            .any(|symbol| symbol.indexer != indexer || symbol.variant != *variant)
        || contribution
            .public_bindings
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || contribution
            .public_bindings
            .iter()
            .any(|binding| binding.indexer != indexer || binding.variant != *variant)
        || contribution
            .public_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || contribution
            .public_roots
            .iter()
            .any(|root| root.indexer != indexer || root.variant != *variant)
        || contribution
            .go_package_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || contribution
            .go_package_roots
            .iter()
            .any(|root| root.variant != *variant)
        || contribution
            .kotlin_compilation_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || contribution
            .kotlin_compilation_roots
            .iter()
            .any(|root| root.variant != *variant)
        || contribution
            .public_reexport_hops
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || contribution
            .public_reexport_hops
            .iter()
            .any(|hop| hop.indexer != indexer || hop.variant != *variant)
        || contribution
            .public_surface_document_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(
            "historical-v2 semantic variant contribution changed compiler identity".to_string(),
        );
    }
    Ok(())
}

fn symbol_key_cmp(
    left: &HistoricalV2SemanticSymbol,
    right: &HistoricalV2SemanticSymbol,
) -> std::cmp::Ordering {
    (left.indexer, &left.variant, left.symbol.symbol_id.as_str()).cmp(&(
        right.indexer,
        &right.variant,
        right.symbol.symbol_id.as_str(),
    ))
}

fn merge_variant_contribution(
    accumulator: &mut SemanticSnapshotAccumulator,
    contribution: HistoricalV2SemanticVariantContribution,
) -> Result<(), String> {
    if accumulator.indexers.iter().any(|existing| {
        existing.census.indexer == contribution.indexer.census.indexer
            && existing.variant == contribution.indexer.variant
    }) {
        return Err("historical-v2 semantic assembly repeated a compiler variant".to_string());
    }
    for method in contribution.methods {
        merge_method(&mut accumulator.methods, method)?;
    }
    for symbol in contribution.symbols {
        let key = (
            symbol.indexer,
            symbol.variant.clone(),
            symbol.symbol.symbol_id.clone(),
        );
        if let Some(existing) = accumulator.symbols.get_mut(&key) {
            if existing.symbol != symbol.symbol {
                return Err(
                    "historical-v2 semantic assembly changed repeated symbol facts".to_string(),
                );
            }
            existing.is_public_surface |= symbol.is_public_surface;
            existing.is_public_root_evidence |= symbol.is_public_root_evidence;
            existing.is_reexport_evidence |= symbol.is_reexport_evidence;
        } else {
            accumulator.symbols.insert(key, symbol);
        }
    }
    accumulator
        .public_bindings
        .extend(contribution.public_bindings);
    accumulator.public_roots.extend(contribution.public_roots);
    accumulator
        .go_package_roots
        .extend(contribution.go_package_roots);
    accumulator
        .kotlin_compilation_roots
        .extend(contribution.kotlin_compilation_roots);
    for hop in contribution.public_reexport_hops {
        let key = (hop.variant.clone(), hop.reexport_unit_id.clone());
        if let Some(existing) = accumulator.public_reexport_hops.insert(key, hop.clone())
            && existing != hop
        {
            return Err("historical-v2 compiler changed a repeated re-export hop".to_string());
        }
    }
    accumulator
        .public_surface_document_paths
        .extend(contribution.public_surface_document_paths);
    accumulator.indexers.push(contribution.indexer);
    Ok(())
}

fn merge_method(
    methods: &mut BTreeMap<String, HistoricalV2SemanticMethod>,
    mut incoming: HistoricalV2SemanticMethod,
) -> Result<(), String> {
    let Some(existing) = methods.get_mut(&incoming.parser_unit_id) else {
        methods.insert(incoming.parser_unit_id.clone(), incoming);
        return Ok(());
    };
    if existing.repository_path != incoming.repository_path
        || existing.symbol_name != incoming.symbol_name
        || existing.start_line != incoming.start_line
        || existing.end_line != incoming.end_line
        || existing.indexer != incoming.indexer
        || incoming.observations.iter().any(|observation| {
            existing
                .observations
                .iter()
                .any(|current| current.variant == observation.variant)
        })
    {
        return Err(format!(
            "historical-v2 semantic method {} repeated or changed compiler identity",
            incoming.parser_unit_id
        ));
    }
    existing.observations.append(&mut incoming.observations);
    Ok(())
}

fn add_untouched_language_methods(
    root: &Path,
    files: &[FileRecord],
    index_sets: &BTreeMap<SemanticIndexerKind, SemanticIndexSet>,
    expected_methods: &BTreeMap<MethodKey, IntentionalBoundaryMethodCensusEntry>,
    methods: &mut BTreeMap<String, HistoricalV2SemanticMethod>,
) -> Result<(), String> {
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
            expected_methods,
            methods,
        )?;
    }
    Ok(())
}

fn finish_snapshot(
    source: &HistoricalV2SourceSnapshotCensus,
    required_document_paths: &BTreeSet<String>,
    expected_method_count: usize,
    mut accumulator: SemanticSnapshotAccumulator,
) -> Result<HistoricalV2SemanticSnapshotCensus, String> {
    if accumulator.methods.len() != expected_method_count {
        return Err(format!(
            "historical-v2 semantic census omitted {} method(s)",
            expected_method_count.saturating_sub(accumulator.methods.len())
        ));
    }
    let mut methods = accumulator.methods.into_values().collect::<Vec<_>>();
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
    accumulator.public_bindings.sort();
    accumulator.public_roots.sort();
    accumulator.go_package_roots.sort();
    accumulator.kotlin_compilation_roots.sort();
    if accumulator
        .public_roots
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err("historical-v2 public roots are repeated".to_string());
    }
    if accumulator.public_bindings.windows(2).any(|pair| {
        pair[0].variant == pair[1].variant
            && pair[0].declaration_unit_id == pair[1].declaration_unit_id
    }) {
        return Err("historical-v2 public surface repeats a declaration binding".to_string());
    }
    let public_reexport_hops = accumulator
        .public_reexport_hops
        .into_values()
        .collect::<Vec<_>>();
    let symbols = accumulator.symbols.into_values().collect::<Vec<_>>();
    accumulator.indexers.sort_by(|left, right| {
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
        public_surface_document_paths: accumulator
            .public_surface_document_paths
            .into_iter()
            .collect(),
        indexers: accumulator.indexers,
        methods,
        public_binding_count: accumulator.public_bindings.len(),
        public_bindings: accumulator.public_bindings,
        public_root_count: accumulator.public_roots.len(),
        public_roots: accumulator.public_roots,
        go_package_root_count: accumulator.go_package_roots.len(),
        go_package_roots: accumulator.go_package_roots,
        kotlin_compilation_root_count: accumulator.kotlin_compilation_roots.len(),
        kotlin_compilation_roots: accumulator.kotlin_compilation_roots,
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
