use super::super::history_v2_go_package_surface::{go_package_exposures, go_package_source_map};
use super::super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2NodeConsumerResolution,
    HistoricalV2PublicSurfaceCoverage, HistoricalV2PythonDistributionModule,
    HistoricalV2PythonModuleKind, HistoricalV2SemanticCensus, HistoricalV2SemanticGoPackageRoot,
    HistoricalV2SemanticMethodStatus, HistoricalV2SemanticPublicBinding,
    HistoricalV2SemanticPublicBindingKind, HistoricalV2SemanticPublicReexportHop,
    HistoricalV2SemanticPublicRootOrigin, HistoricalV2SemanticSnapshotCensus,
    HistoricalV2SemanticSymbol, HistoricalV2SemanticVariantCondition, HistoricalV2SourceCensus,
    HistoricalV2SourceFile, HistoricalV2SourcePublicBindingKind,
    HistoricalV2SourcePublicDeclaration, HistoricalV2SourcePublicNamespace,
    HistoricalV2SourcePublicReexport, HistoricalV2SourcePublicReexportKind,
    HistoricalV2SourcePublicSymbolKind, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, IntentionalBoundaryIndexerKind,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, validate_historical_v2_source_census,
};
use super::{
    SEMANTIC_CENSUS_CONTRACT, indexer_for_language, indexer_kind, semantic_census_sha256,
    semantic_scope, semantic_snapshot_sha256,
};
use crate::semantic_index::SemanticIndexVariant;
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use scip::types::descriptor::Suffix;
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_historical_v2_semantic_census_commitment(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    census: &HistoricalV2SemanticCensus,
) -> Result<(), String> {
    validate_historical_v2_source_census(materialization, roots, source_census)?;
    let scope = semantic_scope(materialization, roots, source_census)?;
    let changed_indexers = scope
        .changed_indexers
        .iter()
        .copied()
        .map(indexer_kind)
        .collect::<Vec<_>>();
    if census.schema_version != HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION
        || census.semantic_census_contract != SEMANTIC_CENSUS_CONTRACT
        || census.canonical_repository != materialization.canonical_repository
        || census.materialization_sha256 != materialization.materialization_sha256
        || census.source_census_sha256 != source_census.source_census_sha256
        || census.changed_indexers != changed_indexers
        || census.semantic_census_sha256 != semantic_census_sha256(census)?
    {
        return Err("historical-v2 semantic census commitment changed".to_string());
    }
    validate_snapshot(
        &source_census.base,
        &census.base,
        &scope.changed_indexers,
        &scope.base_required_paths,
    )?;
    validate_snapshot(
        &source_census.patched,
        &census.patched,
        &scope.changed_indexers,
        &scope.patched_required_paths,
    )?;
    Ok(())
}

pub(super) fn validate_snapshot(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
) -> Result<(), String> {
    let public_declaration_count = source
        .source_files
        .iter()
        .map(|file| file.public_declarations.len())
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| "historical-v2 public declaration count overflowed".to_string())?;
    let public_reexport_count = source
        .source_files
        .iter()
        .map(|file| file.public_reexports.len())
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| "historical-v2 public re-export count overflowed".to_string())?;
    if semantic.revision != source.revision
        || semantic.source_snapshot_census_sha256 != source.snapshot_census_sha256
        || semantic.required_document_paths
            != required_document_paths.iter().cloned().collect::<Vec<_>>()
        || !is_sha256(&semantic.semantic_snapshot_sha256)
        || semantic.semantic_snapshot_sha256 != semantic_snapshot_sha256(semantic)?
        || source.public_declaration_count != public_declaration_count
        || source.public_reexport_count != public_reexport_count
    {
        return Err("historical-v2 semantic snapshot identity changed".to_string());
    }

    let expected_indexers = source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?
        .intersection(changed_indexers)
        .copied()
        .map(indexer_kind)
        .collect::<BTreeSet<_>>();
    let committed_variants = validate_indexers(source, semantic, required_document_paths)?;
    let actual_indexers = committed_variants
        .iter()
        .map(|(indexer, _)| *indexer)
        .collect::<BTreeSet<_>>();
    if actual_indexers != expected_indexers {
        return Err("historical-v2 semantic snapshot indexer coverage changed".to_string());
    }

    let all_source_paths = source
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let symbols = validate_symbols(
        semantic,
        &actual_indexers,
        &committed_variants,
        &all_source_paths,
    )?;
    let public_surface_document_paths = validate_public_surface_document_paths(
        source,
        semantic,
        &actual_indexers,
        required_document_paths,
    )?;
    let public_root_symbols = validate_public_roots(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &public_surface_document_paths,
    )?;
    validate_go_package_roots(
        source,
        semantic,
        &actual_indexers,
        &committed_variants,
        &public_surface_document_paths,
    )?;
    validate_kotlin_compilation_roots(
        source,
        semantic,
        &actual_indexers,
        &public_surface_document_paths,
    )?;
    let (reexports, reexport_symbols) = validate_reexport_hops(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &all_source_paths,
        &public_surface_document_paths,
    )?;
    let binding_symbols = validate_public_bindings(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &reexports,
        &public_surface_document_paths,
    )?;
    let referenced_symbols = validate_methods(
        source,
        semantic,
        &actual_indexers,
        &committed_variants,
        &symbols,
        &all_source_paths,
    )?;
    if semantic.symbols.iter().any(|entry| {
        let key = (
            entry.indexer,
            &entry.variant,
            entry.symbol.symbol_id.as_str(),
        );
        !binding_symbols.contains(&key)
            && !reexport_symbols.contains(&key)
            && !public_root_symbols.contains(&key)
            && !referenced_symbols.contains(&key)
    }) {
        return Err("historical-v2 semantic snapshot contains an unrelated symbol".to_string());
    }
    if semantic.symbols.iter().any(|entry| {
        entry.is_public_root_evidence
            != public_root_symbols.contains(&(
                entry.indexer,
                &entry.variant,
                entry.symbol.symbol_id.as_str(),
            ))
    }) {
        return Err("historical-v2 public root evidence classification changed".to_string());
    }
    if semantic.symbols.iter().any(|entry| {
        entry.is_reexport_evidence
            != reexport_symbols.contains(&(
                entry.indexer,
                &entry.variant,
                entry.symbol.symbol_id.as_str(),
            ))
    }) {
        return Err("historical-v2 re-export evidence classification changed".to_string());
    }
    Ok(())
}

fn validate_indexers<'a>(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    required_document_paths: &BTreeSet<String>,
) -> Result<BTreeSet<(IntentionalBoundaryIndexerKind, &'a SemanticIndexVariant)>, String> {
    if semantic.indexers.windows(2).any(|pair| {
        (pair[0].census.indexer, &pair[0].variant) >= (pair[1].census.indexer, &pair[1].variant)
    }) {
        return Err("historical-v2 semantic indexers are not canonical".to_string());
    }
    let mut indexers = BTreeSet::new();
    let mut modes = BTreeMap::new();
    let mut conditions = BTreeSet::new();
    for indexer in &semantic.indexers {
        validate_variant(&indexer.variant)?;
        let indexed = indexer
            .indexed_document_paths
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let ignored = indexer
            .ignored_document_paths
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let qualified = matches!(indexer.variant, SemanticIndexVariant::Qualified { .. });
        let expected_paths = source
            .source_files
            .iter()
            .filter(|file| {
                file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required
                    && indexer_for_language(&file.language).map(indexer_kind)
                        == Ok(indexer.census.indexer)
            })
            .map(|file| file.repository_path.as_str())
            .collect::<BTreeSet<_>>();
        let required_paths = required_document_paths
            .iter()
            .filter(|path| expected_paths.contains(path.as_str()))
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if indexer.census.tool_name.trim().is_empty()
            || !is_sha256(&indexer.census.semantic_facts_sha256)
            || !is_sha256(&indexer.census.diagnostics_sha256)
            || indexer.census.document_count != indexed.len()
            || indexed.len() != indexer.indexed_document_paths.len()
            || ignored.len() != indexer.ignored_document_paths.len()
            || !indexed.is_disjoint(&ignored)
            || indexed.iter().chain(&ignored).any(|path| {
                path.trim().is_empty() || path.starts_with("../") || path.contains('\0')
            })
            || (!qualified && !ignored.is_empty())
            || !indexed.is_subset(&expected_paths)
            || !ignored.is_subset(&expected_paths)
            || (qualified
                && indexed.union(&ignored).copied().collect::<BTreeSet<_>>() != expected_paths)
            || (!qualified && !required_paths.is_subset(&indexed))
            || modes
                .insert(indexer.census.indexer, qualified)
                .is_some_and(|existing| existing != qualified)
            || !indexers.insert((indexer.census.indexer, &indexer.variant))
            || !conditions.insert((
                indexer.census.indexer,
                HistoricalV2SemanticVariantCondition::from(&indexer.variant),
            ))
        {
            return Err("historical-v2 semantic indexer commitment is invalid".to_string());
        }
    }
    Ok(indexers)
}

fn validate_variant(variant: &SemanticIndexVariant) -> Result<(), String> {
    if let SemanticIndexVariant::Qualified {
        identity,
        dimensions,
    } = variant
        && (identity.0.trim().is_empty()
            || dimensions.is_empty()
            || dimensions
                .iter()
                .any(|(name, value)| name.trim().is_empty() || value.trim().is_empty()))
    {
        return Err("historical-v2 semantic compiler variant is invalid".to_string());
    }
    Ok(())
}

type IndexerVariantKey<'a> = (IntentionalBoundaryIndexerKind, &'a SemanticIndexVariant);
type SymbolKey<'a> = (
    IntentionalBoundaryIndexerKind,
    &'a SemanticIndexVariant,
    &'a str,
);
type ReexportMap<'a> = BTreeMap<
    (&'a SemanticIndexVariant, &'a str),
    (
        &'a HistoricalV2SourceFile,
        &'a HistoricalV2SourcePublicReexport,
        &'a HistoricalV2SemanticPublicReexportHop,
    ),
>;
type DeclarationMap<'a> = BTreeMap<
    &'a str,
    (
        &'a str,
        IntentionalBoundaryIndexerKind,
        &'a HistoricalV2SourcePublicDeclaration,
    ),
>;

fn validate_public_surface_document_paths<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    required_document_paths: &BTreeSet<String>,
) -> Result<BTreeSet<&'a str>, String> {
    if semantic
        .public_surface_document_paths
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("historical-v2 public-surface document paths are not canonical".to_string());
    }
    let source_files = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let paths = semantic
        .public_surface_document_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for path in &paths {
        let file = source_files.get(path).ok_or_else(|| {
            "historical-v2 public-surface census invented a source document".to_string()
        })?;
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required
            || file.public_surface_coverage != HistoricalV2PublicSurfaceCoverage::Complete
            || !indexers.contains(&indexer)
        {
            return Err(
                "historical-v2 public-surface census included an ineligible document".to_string(),
            );
        }
    }
    for file in source.source_files.iter().filter(|file| {
        required_document_paths.contains(&file.repository_path)
            && file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required
            && file.public_surface_coverage == HistoricalV2PublicSurfaceCoverage::Complete
    }) {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if indexers.contains(&indexer) && !paths.contains(file.repository_path.as_str()) {
            return Err(
                "historical-v2 compiler omitted a required public-surface document".to_string(),
            );
        }
    }
    Ok(paths)
}

fn validate_public_roots<'a>(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<BTreeSet<SymbolKey<'a>>, String> {
    let expected_rust_roots = if indexers.contains(&IntentionalBoundaryIndexerKind::Rust) {
        super::public_surface::rust_public_library_target_roots(source)?
            .into_iter()
            .filter(|path| public_surface_document_paths.contains(path.as_str()))
            .collect()
    } else {
        BTreeSet::new()
    };
    let expected_node_roots =
        if indexers.contains(&IntentionalBoundaryIndexerKind::TypeScriptJavaScript) {
            source
                .node_consumer_profiles
                .profiles
                .iter()
                .map(|profile| (profile.profile_id.as_str(), profile))
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
    let expected_python_roots = if indexers.contains(&IntentionalBoundaryIndexerKind::Python) {
        let unsupported_roots = source
            .python_distribution_surfaces
            .modules
            .iter()
            .filter(|module| python_distribution_module_is_external_entry(module, source))
            .filter(|module| {
                module.kind != HistoricalV2PythonModuleKind::NamespacePackage
                    && !super::public_surface::python_distribution_import_has_compiler_source(
                        module,
                        &source.python_distribution_surfaces.modules,
                    )
            })
            .count();
        if unsupported_roots != 0 {
            return Err(
                "historical-v2 Python distribution has compiler-incomplete public roots"
                    .to_string(),
            );
        }
        source
            .python_distribution_surfaces
            .modules
            .iter()
            .filter(|module| {
                python_distribution_module_is_external_entry(module, source)
                    && super::public_surface::python_distribution_module_is_selected_compiler_source(
                        module,
                        &source.python_distribution_surfaces.modules,
                    )
            })
            .map(|module| (module.module_exposure_id.as_str(), module))
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    if semantic.public_root_count != semantic.public_roots.len()
        || semantic
            .public_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("historical-v2 public root census is noncanonical".to_string());
    }
    let source_languages = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file.language.as_str()))
        .collect::<BTreeMap<_, _>>();
    let source_files = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut rust_paths = BTreeSet::new();
    let mut node_profile_ids = BTreeSet::new();
    let mut python_exposure_ids = BTreeSet::new();
    let mut root_symbols = BTreeSet::new();
    for root in &semantic.public_roots {
        let symbol_key = (root.indexer, &root.variant, root.module_symbol_id.as_str());
        let symbol = symbols
            .get(&symbol_key)
            .ok_or_else(|| "historical-v2 public root references a missing symbol".to_string())?;
        let parsed =
            scip::symbol::parse_symbol(&symbol.symbol.provider_identity).map_err(|error| {
                format!(
                    "historical-v2 public root has invalid compiler identity {:?}: {error:?}",
                    symbol.symbol.provider_identity
                )
            })?;
        if !indexers.contains(&root.indexer)
            || !public_surface_document_paths.contains(root.repository_path.as_str())
            || root.compiler_definition.repository_path != root.repository_path
            || symbol.symbol.category != IntentionalBoundarySemanticSymbolCategory::Module
            || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
            || !symbol.symbol.ambiguity_notes.is_empty()
            || !symbol
                .symbol
                .definitions
                .contains(&root.compiler_definition)
        {
            return Err("historical-v2 public root changed compiler identity".to_string());
        }
        match &root.origin {
            HistoricalV2SemanticPublicRootOrigin::RustCargoLibrary => {
                let [descriptor] = parsed.descriptors.as_slice() else {
                    return Err(
                        "historical-v2 Rust public root has a non-root descriptor path".to_string(),
                    );
                };
                if root.indexer != IntentionalBoundaryIndexerKind::Rust
                    || source_languages.get(root.repository_path.as_str()) != Some(&"rust")
                    || parsed.scheme != "rust-analyzer"
                    || descriptor.name != "crate"
                    || descriptor.suffix.enum_value().ok() != Some(Suffix::Namespace)
                    || !rust_paths.insert((&root.variant, root.repository_path.as_str()))
                {
                    return Err(
                        "historical-v2 Rust public root changed compiler identity".to_string()
                    );
                }
            }
            HistoricalV2SemanticPublicRootOrigin::NodePackageConsumerProfile {
                consumer_profile_id,
                exposure_id,
                surface_slot_id,
            } => {
                let profile = expected_node_roots
                    .get(consumer_profile_id.as_str())
                    .ok_or_else(|| {
                        "historical-v2 Node public root invented a consumer profile".to_string()
                    })?;
                let HistoricalV2NodeConsumerResolution::Resolved {
                    selected_exposure_id,
                    resolved_repository_path,
                    resolved_object_id,
                    ..
                } = &profile.compiler
                else {
                    return Err(
                        "historical-v2 Node public root used an unresolved compiler profile"
                            .to_string(),
                    );
                };
                if root.indexer != IntentionalBoundaryIndexerKind::TypeScriptJavaScript
                    || source_languages
                        .get(root.repository_path.as_str())
                        .is_none_or(|language| !matches!(*language, "typescript" | "javascript"))
                    || parsed.scheme != "scip-typescript"
                    || symbol.symbol.owner.is_some()
                    || selected_exposure_id != exposure_id
                    || resolved_repository_path != &root.repository_path
                    || resolved_object_id.as_deref()
                        != source_files
                            .get(root.repository_path.as_str())
                            .map(|file| file.object_id.as_str())
                    || profile.consumer_surface_slot_id != *surface_slot_id
                    || !matches!(
                        profile.runtime,
                        HistoricalV2NodeConsumerResolution::Resolved { .. }
                    )
                    || !node_profile_ids.insert((&root.variant, consumer_profile_id.as_str()))
                {
                    return Err(
                        "historical-v2 Node public root changed compiler identity".to_string()
                    );
                }
            }
            HistoricalV2SemanticPublicRootOrigin::PythonDistributionModule {
                module_exposure_id,
                surface_slot_id,
            } => {
                let module = expected_python_roots
                    .get(module_exposure_id.as_str())
                    .ok_or_else(|| {
                        "historical-v2 Python public root invented a distribution module"
                            .to_string()
                    })?;
                let [package, init] = parsed.descriptors.as_slice() else {
                    return Err(
                        "historical-v2 Python public root has a non-module descriptor path"
                            .to_string(),
                    );
                };
                let file = source_files
                    .get(root.repository_path.as_str())
                    .copied()
                    .ok_or_else(|| {
                        "historical-v2 Python public root source disappeared".to_string()
                    })?;
                if root.indexer != IntentionalBoundaryIndexerKind::Python
                    || file.language != "python"
                    || parsed.scheme != "scip-python"
                    || package.name != module.import_name
                    || package.suffix.enum_value().ok() != Some(Suffix::Package)
                    || init.name != "__init__"
                    || init.suffix.enum_value().ok() != Some(Suffix::Meta)
                    || symbol.symbol.owner.is_some()
                    || module.surface_slot_id != *surface_slot_id
                    || module.member_sha256.as_deref() != Some(file.source_sha256.as_str())
                    || !python_exposure_ids.insert((&root.variant, module_exposure_id.as_str()))
                {
                    return Err(
                        "historical-v2 Python public root changed compiler identity".to_string()
                    );
                }
            }
        }
        root_symbols.insert(symbol_key);
    }
    let expected_rust_variant_paths = semantic
        .indexers
        .iter()
        .filter(|indexer| indexer.census.indexer == IntentionalBoundaryIndexerKind::Rust)
        .flat_map(|indexer| {
            expected_rust_roots
                .iter()
                .filter(|path| indexer.indexed_document_paths.contains(path))
                .map(move |path| (&indexer.variant, path.as_str()))
        })
        .collect::<BTreeSet<_>>();
    if rust_paths != expected_rust_variant_paths {
        return Err(
            "historical-v2 Rust public roots disagree with Cargo library targets".to_string(),
        );
    }
    let mut expected_node_profile_ids = BTreeSet::new();
    for indexer in semantic.indexers.iter().filter(|indexer| {
        indexer.census.indexer == IntentionalBoundaryIndexerKind::TypeScriptJavaScript
    }) {
        if matches!(indexer.variant, SemanticIndexVariant::Qualified { .. })
            && expected_node_roots
                .values()
                .any(|profile| profile.project_model_execution_id.is_none())
        {
            return Err(
                "historical-v2 Node consumer profile has no compiler-world identity".to_string(),
            );
        }
        for (profile_id, profile) in &expected_node_roots {
            let execution_matches = match &indexer.variant {
                SemanticIndexVariant::Qualified { identity, .. } => {
                    profile.project_model_execution_id.as_deref() == Some(identity.0.as_str())
                }
                SemanticIndexVariant::Unqualified => true,
            };
            if !execution_matches {
                continue;
            }
            let HistoricalV2NodeConsumerResolution::Resolved {
                resolved_repository_path,
                ..
            } = &profile.compiler
            else {
                return Err(
                    "historical-v2 Node consumer compiler profile is unresolved".to_string()
                );
            };
            if !matches!(
                profile.runtime,
                HistoricalV2NodeConsumerResolution::Resolved { .. }
            ) {
                return Err("historical-v2 Node consumer runtime profile is unresolved".to_string());
            }
            if !indexer
                .indexed_document_paths
                .contains(resolved_repository_path)
            {
                return Err(
                    "historical-v2 Node consumer compiler target was not indexed".to_string(),
                );
            }
            expected_node_profile_ids.insert((&indexer.variant, *profile_id));
        }
    }
    if node_profile_ids != expected_node_profile_ids {
        return Err("historical-v2 Node public roots disagree with consumer profiles".to_string());
    }
    let expected_python_exposure_ids = semantic
        .indexers
        .iter()
        .filter(|indexer| indexer.census.indexer == IntentionalBoundaryIndexerKind::Python)
        .flat_map(|indexer| {
            expected_python_roots
                .keys()
                .filter(|exposure_id| {
                    expected_python_roots
                        .get(*exposure_id)
                        .is_some_and(|module| {
                            module.member_sha256.as_deref().is_some_and(|hash| {
                                source_files.values().any(|file| {
                                    file.source_sha256 == hash
                                        && indexer
                                            .indexed_document_paths
                                            .contains(&file.repository_path)
                                })
                            })
                        })
                })
                .map(move |exposure_id| (&indexer.variant, *exposure_id))
        })
        .collect::<BTreeSet<_>>();
    if python_exposure_ids != expected_python_exposure_ids {
        return Err(
            "historical-v2 Python public roots disagree with distribution modules".to_string(),
        );
    }
    Ok(root_symbols)
}

fn validate_go_package_roots(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    committed_variants: &BTreeSet<IndexerVariantKey<'_>>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    if semantic.go_package_root_count != semantic.go_package_roots.len()
        || semantic
            .go_package_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("historical-v2 Go package root census is noncanonical".to_string());
    }

    let go_variants = committed_variants
        .iter()
        .filter(|(indexer, _)| *indexer == IntentionalBoundaryIndexerKind::Go)
        .map(|(_, variant)| *variant)
        .collect::<Vec<_>>();
    let mut expected = if indexers.contains(&IntentionalBoundaryIndexerKind::Go) {
        let packages = go_package_exposures(&source.go_project_model)?;
        let mut roots = Vec::new();
        for package in packages
            .into_iter()
            .filter(|package| package.externally_reachable)
        {
            if go_variants.len() == 1 && matches!(go_variants[0], SemanticIndexVariant::Unqualified)
            {
                let mut variant_target_ids = package
                    .variants
                    .iter()
                    .filter(|variant| variant.externally_reachable)
                    .map(|variant| variant.target_id.clone())
                    .collect::<Vec<_>>();
                variant_target_ids.sort();
                let mut source_repository_paths = package
                    .variants
                    .iter()
                    .filter(|variant| variant.externally_reachable)
                    .flat_map(|variant| variant.source_repository_paths.iter())
                    .cloned()
                    .collect::<Vec<_>>();
                source_repository_paths.sort();
                source_repository_paths.dedup();
                let mut ignored_source_repository_paths = package
                    .variants
                    .iter()
                    .filter(|variant| variant.externally_reachable)
                    .flat_map(|variant| variant.ignored_source_repository_paths.iter())
                    .cloned()
                    .collect::<Vec<_>>();
                ignored_source_repository_paths.sort();
                ignored_source_repository_paths.dedup();
                roots.push(HistoricalV2SemanticGoPackageRoot {
                    variant: SemanticIndexVariant::Unqualified,
                    variant_target_ids,
                    surface_slot_id: package.surface_slot_id,
                    module_path: package.module_path,
                    import_path: package.import_path,
                    source_repository_paths,
                    ignored_source_repository_paths,
                });
                continue;
            }
            for package_variant in package
                .variants
                .iter()
                .filter(|variant| variant.externally_reachable)
            {
                let semantic_variant = go_variants
                    .iter()
                    .copied()
                    .find(|variant| {
                        matches!(
                            variant,
                            SemanticIndexVariant::Qualified { identity, .. }
                                if identity.0 == package_variant.execution_id
                        )
                    })
                    .ok_or_else(|| {
                        format!(
                            "historical-v2 Go package {} has no committed compiler variant {}",
                            package.import_path, package_variant.execution_id
                        )
                    })?;
                roots.push(HistoricalV2SemanticGoPackageRoot {
                    variant: semantic_variant.clone(),
                    variant_target_ids: vec![package_variant.target_id.clone()],
                    surface_slot_id: package.surface_slot_id.clone(),
                    module_path: package.module_path.clone(),
                    import_path: package.import_path.clone(),
                    source_repository_paths: package_variant.source_repository_paths.clone(),
                    ignored_source_repository_paths: package_variant
                        .ignored_source_repository_paths
                        .clone(),
                });
            }
        }
        if !roots
            .iter()
            .flat_map(|root| &root.source_repository_paths)
            .all(|path| public_surface_document_paths.contains(path.as_str()))
        {
            return Err(
                "historical-v2 Go package has compiler-invisible public source".to_string(),
            );
        }
        roots
    } else {
        Vec::new()
    };
    expected.sort();

    if semantic.go_package_roots != expected {
        return Err(
            "historical-v2 Go package roots disagree with compiler package exposures".to_string(),
        );
    }
    Ok(())
}

fn validate_kotlin_compilation_roots(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    if semantic.kotlin_compilation_root_count != semantic.kotlin_compilation_roots.len()
        || semantic
            .kotlin_compilation_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("historical-v2 Kotlin compilation root census is noncanonical".to_string());
    }
    let mut expected = Vec::new();
    if indexers.contains(&IntentionalBoundaryIndexerKind::Kotlin) {
        for committed in semantic
            .indexers
            .iter()
            .filter(|indexer| indexer.census.indexer == IntentionalBoundaryIndexerKind::Kotlin)
        {
            let indexed_paths = committed
                .indexed_document_paths
                .iter()
                .cloned()
                .map(crate::semantic_index::RepositoryPath)
                .collect::<BTreeSet<_>>();
            expected.extend(super::public_surface::expected_kotlin_public_compilations(
                source,
                &committed.variant,
                &indexed_paths,
            )?);
        }
    }
    expected.sort();
    if expected
        .iter()
        .flat_map(|root| &root.source_repository_paths)
        .any(|path| !public_surface_document_paths.contains(path.as_str()))
    {
        return Err(
            "historical-v2 Kotlin compilation has compiler-invisible public source".to_string(),
        );
    }
    if semantic.kotlin_compilation_roots != expected {
        return Err(
            "historical-v2 Kotlin compilation roots disagree with the Gradle project model"
                .to_string(),
        );
    }
    Ok(())
}

fn python_distribution_module_is_external_entry(
    module: &HistoricalV2PythonDistributionModule,
    source: &HistoricalV2SourceSnapshotCensus,
) -> bool {
    let external_entry = module.is_distribution_root
        || module
            .import_name
            .rsplit_once('.')
            .is_some_and(|(parent, _)| {
                source
                    .python_distribution_surfaces
                    .modules
                    .iter()
                    .any(|candidate| {
                        candidate.distribution_id == module.distribution_id
                            && candidate.import_name == parent
                            && candidate.kind == HistoricalV2PythonModuleKind::NamespacePackage
                    })
            });
    external_entry
        && !source
            .python_distribution_surfaces
            .distributions
            .iter()
            .find(|distribution| distribution.distribution_id == module.distribution_id)
            .is_some_and(|distribution| {
                distribution
                    .import_names
                    .iter()
                    .chain(&distribution.import_namespaces)
                    .any(|declaration| {
                        declaration.import_name == module.import_name && declaration.private
                    })
            })
}

fn validate_symbols<'a>(
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    committed_variants: &BTreeSet<IndexerVariantKey<'a>>,
    all_source_paths: &BTreeSet<&str>,
) -> Result<BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>, String> {
    if semantic.symbol_count != semantic.symbols.len()
        || semantic.public_symbol_count
            != semantic
                .symbols
                .iter()
                .filter(|symbol| symbol.is_public_surface)
                .count()
    {
        return Err("historical-v2 semantic symbol counts changed".to_string());
    }
    let mut symbols = BTreeMap::new();
    let mut previous = None;
    for entry in &semantic.symbols {
        let symbol = &entry.symbol;
        let key = (entry.indexer, &entry.variant, symbol.symbol_id.as_str());
        if previous.is_some_and(|previous| previous >= key)
            || !indexers.contains(&entry.indexer)
            || !committed_variants.contains(&(entry.indexer, &entry.variant))
            || symbol.symbol_id.trim().is_empty()
            || symbol.provider_identity.trim().is_empty()
            || symbol.provider_kind.trim().is_empty()
            || symbol.definitions.is_empty()
            || symbol
                .definitions
                .iter()
                .any(|location| !valid_location(location, all_source_paths))
        {
            return Err("historical-v2 semantic symbol is invalid or noncanonical".to_string());
        }
        if symbols.insert(key, entry).is_some() {
            return Err("historical-v2 semantic symbol identity repeated".to_string());
        }
        previous = Some(key);
    }
    Ok(symbols)
}

fn validate_reexport_hops<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    all_source_paths: &BTreeSet<&str>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<(ReexportMap<'a>, BTreeSet<SymbolKey<'a>>), String> {
    if semantic.public_reexport_hop_count != semantic.public_reexport_hops.len()
        || semantic.public_reexport_hops.windows(2).any(|pair| {
            (&pair[0].variant, &pair[0].reexport_unit_id)
                >= (&pair[1].variant, &pair[1].reexport_unit_id)
        })
    {
        return Err("historical-v2 public re-export hop count or order changed".to_string());
    }
    let mut expected = BTreeMap::new();
    let mut mandatory = BTreeSet::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if !indexers.contains(&indexer) {
            continue;
        }
        for reexport in &file.public_reexports {
            if expected
                .insert(
                    reexport.reexport_unit_id.as_str(),
                    (file, reexport, indexer),
                )
                .is_some()
            {
                return Err("historical-v2 source repeats a public re-export".to_string());
            }
            if !matches!(file.language.as_str(), "rust" | "typescript" | "javascript") {
                mandatory.insert(reexport.reexport_unit_id.as_str());
            }
        }
    }

    let mut validated = BTreeMap::new();
    let mut reexport_symbols = BTreeSet::new();
    for hop in &semantic.public_reexport_hops {
        let (file, reexport, expected_indexer) = expected
            .get(hop.reexport_unit_id.as_str())
            .copied()
            .ok_or_else(|| "historical-v2 compiler invented a public re-export hop".to_string())?;
        let expected_anchor =
            source_reexport_semantic_range(&file.repository_path, reexport, hop.position_encoding);
        let symbol_key = (hop.indexer, &hop.variant, hop.module_symbol_id.as_str());
        let symbol = symbols.get(&symbol_key).ok_or_else(|| {
            "historical-v2 public re-export hop references a missing module symbol".to_string()
        })?;
        if hop.indexer != expected_indexer
            || hop.repository_path != file.repository_path
            || hop.target_repository_path == hop.repository_path
            || !all_source_paths.contains(hop.target_repository_path.as_str())
            || !public_surface_document_paths.contains(hop.target_repository_path.as_str())
            || hop.compiler_anchor != expected_anchor
            || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
            || !matches!(
                symbol.symbol.category,
                IntentionalBoundarySemanticSymbolCategory::Module
                    | IntentionalBoundarySemanticSymbolCategory::Namespace
                    | IntentionalBoundarySemanticSymbolCategory::Package
            )
            || !symbol
                .symbol
                .definitions
                .iter()
                .any(|definition| definition.repository_path == hop.target_repository_path)
        {
            return Err("historical-v2 public re-export hop changed compiler identity".to_string());
        }
        validated.insert(
            (&hop.variant, hop.reexport_unit_id.as_str()),
            (file, reexport, hop),
        );
        reexport_symbols.insert(symbol_key);
    }
    if !mandatory.iter().all(|reexport_id| {
        validated
            .keys()
            .any(|(_, actual_id)| actual_id == reexport_id)
    }) {
        return Err("historical-v2 compiler omitted a public re-export hop".to_string());
    }
    Ok((validated, reexport_symbols))
}

fn validate_public_bindings<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    reexports: &ReexportMap<'a>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<BTreeSet<SymbolKey<'a>>, String> {
    if semantic.public_binding_count != semantic.public_bindings.len() {
        return Err("historical-v2 public binding count changed".to_string());
    }
    let go_packages = if indexers.contains(&IntentionalBoundaryIndexerKind::Go) {
        go_package_exposures(&source.go_project_model)?
    } else {
        Vec::new()
    };
    let go_sources = go_package_source_map(&go_packages)?;
    let mut expected = DeclarationMap::new();
    let mut required_declarations = BTreeSet::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if !indexers.contains(&indexer) {
            continue;
        }
        if file.public_surface_coverage != HistoricalV2PublicSurfaceCoverage::Complete {
            return Err(format!(
                "historical-v2 public-surface collector is incomplete for {}",
                file.repository_path
            ));
        }
        for declaration in &file.public_declarations {
            if declaration.surface_unit_id.trim().is_empty()
                || declaration.declaration_unit_id.trim().is_empty()
                || declaration.exposed_identifier.start >= declaration.exposed_identifier.end
                || declaration.identifier.start >= declaration.identifier.end
                || declaration.name.trim().is_empty()
                || expected
                    .insert(
                        declaration.declaration_unit_id.as_str(),
                        (file.repository_path.as_str(), indexer, declaration),
                    )
                    .is_some()
            {
                return Err(
                    "historical-v2 source public declaration is invalid or repeated".to_string(),
                );
            }
            required_declarations.insert(declaration.declaration_unit_id.as_str());
        }
    }

    let mut bound_declarations = BTreeSet::new();
    let mut binding_symbols = BTreeSet::new();
    let mut public_symbols = BTreeSet::new();
    let public_root_variants = semantic
        .public_roots
        .iter()
        .map(|root| (&root.variant, root.repository_path.as_str()))
        .collect::<BTreeSet<_>>();
    let direct_pairs = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            matches!(
                binding.binding,
                HistoricalV2SemanticPublicBindingKind::Definition
                    | HistoricalV2SemanticPublicBindingKind::Reference
            )
        })
        .map(|binding| {
            (
                &binding.variant,
                binding.declaration_unit_id.as_str(),
                binding.symbol_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected_direct_declarations = semantic
        .indexers
        .iter()
        .flat_map(|committed| {
            source
                .source_files
                .iter()
                .filter(move |file| {
                    indexer_for_language(&file.language).map(indexer_kind)
                        == Ok(committed.census.indexer)
                        && committed
                            .indexed_document_paths
                            .contains(&file.repository_path)
                })
                .flat_map(move |file| {
                    file.public_declarations.iter().map(move |declaration| {
                        (
                            committed.variant.clone(),
                            declaration.declaration_unit_id.clone(),
                        )
                    })
                })
        })
        .collect::<BTreeSet<_>>();
    let actual_direct_declarations = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            matches!(
                binding.binding,
                HistoricalV2SemanticPublicBindingKind::Definition
                    | HistoricalV2SemanticPublicBindingKind::Reference
            )
        })
        .map(|binding| (binding.variant.clone(), binding.declaration_unit_id.clone()))
        .collect::<BTreeSet<_>>();
    if expected_direct_declarations != actual_direct_declarations {
        return Err(
            "historical-v2 direct public binding compiler-variant coverage changed".to_string(),
        );
    }
    let mut previous = None;
    for binding in &semantic.public_bindings {
        let key = (
            binding.indexer,
            &binding.variant,
            binding.surface_unit_id.as_str(),
            binding.declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        );
        if previous.is_some_and(|previous| previous >= key) {
            return Err("historical-v2 public bindings are not canonical".to_string());
        }
        let symbol_key = (
            binding.indexer,
            &binding.variant,
            binding.symbol_id.as_str(),
        );
        let symbol = symbols.get(&symbol_key).ok_or_else(|| {
            "historical-v2 public binding references a missing symbol".to_string()
        })?;
        match binding.binding {
            HistoricalV2SemanticPublicBindingKind::Definition
            | HistoricalV2SemanticPublicBindingKind::Reference => {
                let (repository_path, indexer, declaration) = expected
                    .get(binding.declaration_unit_id.as_str())
                    .ok_or_else(|| {
                        "historical-v2 public binding invented a declaration".to_string()
                    })?;
                let expected_anchor = declaration_semantic_range(
                    repository_path,
                    declaration,
                    binding.position_encoding,
                );
                let expected_binding = match declaration.binding {
                    HistoricalV2SourcePublicBindingKind::Definition => {
                        HistoricalV2SemanticPublicBindingKind::Definition
                    }
                    HistoricalV2SourcePublicBindingKind::Reference => {
                        HistoricalV2SemanticPublicBindingKind::Reference
                    }
                };
                let expected_owner_anchor = declaration_owner_semantic_range(
                    repository_path,
                    declaration,
                    binding.position_encoding,
                )?;
                let owner_valid = match (
                    binding.owner_symbol_id.as_deref(),
                    binding.owner_compiler_anchor.as_ref(),
                    expected_owner_anchor.as_ref(),
                ) {
                    (None, None, None) => true,
                    (Some(owner_id), Some(actual_anchor), Some(expected_anchor)) => symbols
                        .get(&(binding.indexer, &binding.variant, owner_id))
                        .is_some_and(|owner| {
                            actual_anchor == expected_anchor
                                && owner.symbol.origin
                                    == IntentionalBoundarySemanticOrigin::Repository
                                && matches!(
                                    owner.symbol.category,
                                    IntentionalBoundarySemanticSymbolCategory::Type
                                        | IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
                                )
                        }),
                    _ => false,
                };
                let expected_reachability = match binding.indexer {
                    IntentionalBoundaryIndexerKind::Rust => {
                        binding.owner_symbol_id.is_none()
                            && public_root_variants.contains(&(&binding.variant, *repository_path))
                    }
                    IntentionalBoundaryIndexerKind::TypeScriptJavaScript
                    | IntentionalBoundaryIndexerKind::Python
                    | IntentionalBoundaryIndexerKind::Kotlin => false,
                    IntentionalBoundaryIndexerKind::Go => {
                        if repository_path.ends_with("_test.go") {
                            false
                        } else {
                            go_sources
                                .get(*repository_path)
                                .ok_or_else(|| {
                                    format!(
                                        "historical-v2 required Go source has no compiler package exposure: {repository_path}"
                                    )
                                })?
                                .externally_reachable
                        }
                    }
                };
                if binding.indexer != *indexer
                    || binding.surface_unit_id != declaration.surface_unit_id
                    || binding.origin_declaration_unit_id != declaration.declaration_unit_id
                    || !binding.reexport_path.is_empty()
                    || binding.exposing_owner_declaration_unit_id.is_some()
                    || binding.package_exposure_id.is_some()
                    || binding.repository_path != *repository_path
                    || binding.binding != expected_binding
                    || binding.compiler_anchor != expected_anchor
                    || binding.compiler_anchor.repository_path != *repository_path
                    || !owner_valid
                    || binding.externally_reachable != expected_reachability
                    || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
                    || (binding.binding == HistoricalV2SemanticPublicBindingKind::Definition
                        && !symbol.symbol.definitions.contains(&binding.compiler_anchor))
                    || !compatible_public_symbol_kind(declaration.kind, symbol.symbol.category)
                    || !bound_declarations
                        .insert((&binding.variant, binding.declaration_unit_id.as_str()))
                {
                    return Err(
                        "historical-v2 public binding changed compiler identity".to_string()
                    );
                }
            }
            HistoricalV2SemanticPublicBindingKind::ReexportExpansion => {
                if binding.package_exposure_id.is_some() {
                    return Err(
                        "historical-v2 re-export expansion claimed a package exposure".to_string(),
                    );
                }
                validate_expanded_public_binding(
                    binding,
                    symbol,
                    &expected,
                    reexports,
                    &direct_pairs,
                    &public_root_variants,
                )?;
            }
            HistoricalV2SemanticPublicBindingKind::OwnerExpansion => {
                if !binding.externally_reachable
                    || binding.exposing_owner_declaration_unit_id.is_none()
                {
                    return Err(
                        "historical-v2 owner expansion changed compiler identity".to_string()
                    );
                }
            }
            HistoricalV2SemanticPublicBindingKind::PackageExposure => match binding.indexer {
                IntentionalBoundaryIndexerKind::TypeScriptJavaScript => {
                    validate_node_package_binding(
                        source,
                        binding,
                        symbol,
                        &expected,
                        reexports,
                        &direct_pairs,
                    )?;
                }
                IntentionalBoundaryIndexerKind::Python => {
                    validate_python_package_binding(
                        source,
                        binding,
                        symbol,
                        &expected,
                        reexports,
                        &direct_pairs,
                    )?;
                }
                IntentionalBoundaryIndexerKind::Kotlin => {
                    validate_kotlin_package_binding(
                        source,
                        semantic,
                        binding,
                        symbol,
                        &expected,
                        &direct_pairs,
                    )?;
                }
                _ => {
                    return Err(
                        "historical-v2 package exposure used an unsupported indexer".to_string()
                    );
                }
            },
        }
        binding_symbols.insert(symbol_key);
        if binding.externally_reachable {
            public_symbols.insert(symbol_key);
        }
        previous = Some(key);
    }
    if !required_declarations.iter().all(|declaration| {
        bound_declarations
            .iter()
            .any(|(_, bound)| bound == declaration)
    }) {
        return Err("historical-v2 changed public declaration has no compiler binding".to_string());
    }
    super::public_surface_validation::validate_complete_reexport_expansions(
        source,
        semantic,
        public_surface_document_paths,
    )?;
    validate_complete_owner_expansions(source, semantic)?;
    if semantic.symbols.iter().any(|entry| {
        entry.is_public_surface
            != public_symbols.contains(&(
                entry.indexer,
                &entry.variant,
                entry.symbol.symbol_id.as_str(),
            ))
    }) {
        return Err("historical-v2 public semantic symbol classification changed".to_string());
    }
    Ok(binding_symbols)
}

fn validate_complete_owner_expansions(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<(), String> {
    let declarations = source
        .source_files
        .iter()
        .flat_map(|file| file.public_declarations.iter())
        .map(|declaration| (declaration.declaration_unit_id.as_str(), declaration))
        .collect::<BTreeMap<_, _>>();
    let members = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            !binding.externally_reachable
                && matches!(
                    binding.binding,
                    HistoricalV2SemanticPublicBindingKind::Definition
                        | HistoricalV2SemanticPublicBindingKind::Reference
                )
                && binding.owner_symbol_id.is_some()
        })
        .collect::<Vec<_>>();
    let owners = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.externally_reachable
                && binding.owner_symbol_id.is_none()
                && binding.binding != HistoricalV2SemanticPublicBindingKind::OwnerExpansion
        })
        .collect::<Vec<_>>();
    let mut expected = BTreeSet::new();
    for member in members {
        let declaration = declarations
            .get(member.origin_declaration_unit_id.as_str())
            .copied()
            .ok_or_else(|| "historical-v2 owner member has no source declaration".to_string())?;
        let source_owner = declaration
            .owner
            .as_deref()
            .ok_or_else(|| "historical-v2 owner member has no source owner".to_string())?;
        for owner in owners.iter().filter(|owner| {
            owner.indexer == member.indexer
                && owner.variant == member.variant
                && Some(owner.symbol_id.as_str()) == member.owner_symbol_id.as_deref()
        }) {
            let surface_unit_id = super::super::history_v2_source_census::historical_public_owner_member_surface_unit_id(
                &owner.surface_unit_id,
                source_owner,
                &declaration.name,
                declaration.namespace,
                declaration.kind,
            )?;
            let declaration_unit_id = super::public_surface::owner_expansion_declaration_unit_id(
                &surface_unit_id,
                &member.origin_declaration_unit_id,
                &member.symbol_id,
                &owner.declaration_unit_id,
            )?;
            let mut expansion = (*member).clone();
            expansion.surface_unit_id = surface_unit_id;
            expansion.declaration_unit_id = declaration_unit_id;
            expansion.exposing_owner_declaration_unit_id = Some(owner.declaration_unit_id.clone());
            expansion.package_exposure_id = owner.package_exposure_id.clone();
            expansion.binding = HistoricalV2SemanticPublicBindingKind::OwnerExpansion;
            expansion.externally_reachable = true;
            expansion.reexport_path.clear();
            expected.insert(expansion);
        }
    }
    let actual = semantic
        .public_bindings
        .iter()
        .filter(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::OwnerExpansion)
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(
            "historical-v2 compiler owner expansion set is incomplete or invented".to_string(),
        );
    }
    Ok(())
}

fn validate_node_package_binding<'a>(
    source: &HistoricalV2SourceSnapshotCensus,
    binding: &HistoricalV2SemanticPublicBinding,
    symbol: &HistoricalV2SemanticSymbol,
    declarations: &DeclarationMap<'a>,
    reexports: &ReexportMap<'a>,
    direct_pairs: &BTreeSet<(&SemanticIndexVariant, &str, &str)>,
) -> Result<(), String> {
    let exposure_id = binding
        .package_exposure_id
        .as_deref()
        .ok_or_else(|| "historical-v2 Node package binding has no exposure identity".to_string())?;
    let _exposure = source
        .node_package_surfaces
        .exposures
        .iter()
        .find(|exposure| exposure.exposure_id == exposure_id)
        .ok_or_else(|| "historical-v2 Node package binding invented an exposure".to_string())?;
    let matching_profiles = source
        .node_consumer_profiles
        .profiles
        .iter()
        .filter(|profile| match &binding.variant {
            SemanticIndexVariant::Qualified { identity, .. } => {
                profile.project_model_execution_id.as_deref() == Some(identity.0.as_str())
            }
            SemanticIndexVariant::Unqualified => true,
        })
        .filter(|profile| {
            matches!(
                &profile.compiler,
                HistoricalV2NodeConsumerResolution::Resolved {
                    selected_exposure_id,
                    resolved_repository_path,
                    ..
                } if selected_exposure_id == exposure_id
                    && resolved_repository_path == &binding.repository_path
            )
        })
        .collect::<Vec<_>>();
    let (origin_path, origin_indexer, origin) = declarations
        .get(binding.origin_declaration_unit_id.as_str())
        .copied()
        .ok_or_else(|| {
            "historical-v2 Node package binding has no origin declaration".to_string()
        })?;
    if binding.indexer != IntentionalBoundaryIndexerKind::TypeScriptJavaScript
        || origin_indexer != IntentionalBoundaryIndexerKind::TypeScriptJavaScript
        || binding.binding != HistoricalV2SemanticPublicBindingKind::PackageExposure
        || !binding.externally_reachable
        || matching_profiles.is_empty()
        || binding.owner_symbol_id.is_some()
        || binding.owner_compiler_anchor.is_some()
        || binding.exposing_owner_declaration_unit_id.is_some()
        || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
        || !compatible_public_symbol_kind(origin.kind, symbol.symbol.category)
        || !direct_pairs.contains(&(
            &binding.variant,
            binding.origin_declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        ))
    {
        return Err("historical-v2 Node package binding changed compiler identity".to_string());
    }

    let mut current_path = binding.repository_path.as_str();
    let mut seen_hops = BTreeSet::new();
    for reexport_id in &binding.reexport_path {
        if !seen_hops.insert(reexport_id.as_str()) {
            return Err("historical-v2 Node package binding contains a cycle".to_string());
        }
        let (file, _, hop) = reexports
            .get(&(&binding.variant, reexport_id.as_str()))
            .copied()
            .ok_or_else(|| {
                "historical-v2 Node package binding references an omitted public re-export hop"
                    .to_string()
            })?;
        if file.repository_path != current_path || hop.indexer != binding.indexer {
            return Err("historical-v2 Node package binding has a disconnected path".to_string());
        }
        current_path = hop.target_repository_path.as_str();
    }
    if current_path != origin_path {
        return Err("historical-v2 Node package binding misses its origin".to_string());
    }

    let mut name = origin.name.clone();
    let mut owner = origin.owner.clone();
    let mut namespace = origin.namespace;
    let mut kind = origin.kind;
    for reexport_id in binding.reexport_path.iter().rev() {
        let (_, reexport, _) = reexports
            .get(&(&binding.variant, reexport_id.as_str()))
            .copied()
            .unwrap();
        match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                if name == "default" {
                    return Err(
                        "historical-v2 Node package wildcard exposed a default export".to_string(),
                    );
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                name = reexport.name.clone().ok_or_else(|| {
                    "historical-v2 Node package namespace has no exposed name".to_string()
                })?;
                owner = None;
                namespace = HistoricalV2SourcePublicNamespace::Module;
                kind = HistoricalV2SourcePublicSymbolKind::Module;
            }
        }
    }
    if owner.is_some() {
        return Err("historical-v2 Node package binding exposed a member directly".to_string());
    }
    let matching_surfaces = matching_profiles
        .iter()
        .map(|profile| {
            super::public_surface::historical_node_package_public_surface_unit_id(
                &profile.consumer_surface_slot_id,
                &name,
                None,
                namespace,
                kind,
            )
            .map(|surface| (*profile, surface))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let selected_surfaces = matching_surfaces
        .iter()
        .filter(|(_, surface)| surface == &binding.surface_unit_id)
        .collect::<Vec<_>>();
    let [(_, expected_surface)] = selected_surfaces.as_slice() else {
        return Err("historical-v2 Node package binding changed public identity".to_string());
    };
    let expected_declaration = super::public_surface::node_package_expansion_declaration_unit_id(
        expected_surface,
        exposure_id,
        &binding.origin_declaration_unit_id,
        &binding.symbol_id,
        &binding.reexport_path,
    )?;
    let (expected_encoding, expected_anchor) =
        if let Some(reexport_id) = binding.reexport_path.first() {
            let hop = reexports
                .get(&(&binding.variant, reexport_id.as_str()))
                .unwrap()
                .2;
            (hop.position_encoding, hop.compiler_anchor.clone())
        } else {
            (
                binding.position_encoding,
                declaration_semantic_range(origin_path, origin, binding.position_encoding),
            )
        };
    if binding.surface_unit_id != *expected_surface
        || binding.declaration_unit_id != expected_declaration
        || binding.position_encoding != expected_encoding
        || binding.compiler_anchor != expected_anchor
    {
        return Err("historical-v2 Node package binding changed public identity".to_string());
    }
    Ok(())
}

fn validate_python_package_binding<'a>(
    source: &HistoricalV2SourceSnapshotCensus,
    binding: &HistoricalV2SemanticPublicBinding,
    symbol: &HistoricalV2SemanticSymbol,
    declarations: &DeclarationMap<'a>,
    reexports: &ReexportMap<'a>,
    direct_pairs: &BTreeSet<(&SemanticIndexVariant, &str, &str)>,
) -> Result<(), String> {
    let exposure_id = binding.package_exposure_id.as_deref().ok_or_else(|| {
        "historical-v2 Python package binding has no module exposure identity".to_string()
    })?;
    let module = source
        .python_distribution_surfaces
        .modules
        .iter()
        .find(|module| module.module_exposure_id == exposure_id)
        .ok_or_else(|| {
            "historical-v2 Python package binding invented a module exposure".to_string()
        })?;
    let root_file = source
        .source_files
        .iter()
        .find(|file| file.repository_path == binding.repository_path)
        .ok_or_else(|| "historical-v2 Python package root source disappeared".to_string())?;
    let (origin_path, origin_indexer, origin) = declarations
        .get(binding.origin_declaration_unit_id.as_str())
        .copied()
        .ok_or_else(|| {
            "historical-v2 Python package binding has no origin declaration".to_string()
        })?;
    if binding.indexer != IntentionalBoundaryIndexerKind::Python
        || origin_indexer != IntentionalBoundaryIndexerKind::Python
        || binding.binding != HistoricalV2SemanticPublicBindingKind::PackageExposure
        || !binding.externally_reachable
        || !python_distribution_module_is_external_entry(module, source)
        || !super::public_surface::python_distribution_module_is_selected_compiler_source(
            module,
            &source.python_distribution_surfaces.modules,
        )
        || module.member_sha256.as_deref() != Some(root_file.source_sha256.as_str())
        || binding.owner_symbol_id.is_some()
        || binding.owner_compiler_anchor.is_some()
        || binding.exposing_owner_declaration_unit_id.is_some()
        || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
        || !compatible_public_symbol_kind(origin.kind, symbol.symbol.category)
        || !direct_pairs.contains(&(
            &binding.variant,
            binding.origin_declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        ))
    {
        return Err("historical-v2 Python package binding changed compiler identity".to_string());
    }

    let mut current_path = binding.repository_path.as_str();
    let mut seen_hops = BTreeSet::new();
    for reexport_id in &binding.reexport_path {
        if !seen_hops.insert(reexport_id.as_str()) {
            return Err("historical-v2 Python package binding contains a cycle".to_string());
        }
        let (file, _, hop) = reexports
            .get(&(&binding.variant, reexport_id.as_str()))
            .copied()
            .ok_or_else(|| {
                "historical-v2 Python package binding references an omitted public re-export hop"
                    .to_string()
            })?;
        if file.repository_path != current_path || hop.indexer != binding.indexer {
            return Err("historical-v2 Python package binding has a disconnected path".to_string());
        }
        current_path = hop.target_repository_path.as_str();
    }
    if current_path != origin_path {
        return Err("historical-v2 Python package binding did not reach its origin".to_string());
    }

    let mut name = origin.name.clone();
    let mut owner = origin.owner.clone();
    let mut namespace = origin.namespace;
    let mut kind = origin.kind;
    for reexport_id in binding.reexport_path.iter().rev() {
        let (_, reexport, _) = reexports
            .get(&(&binding.variant, reexport_id.as_str()))
            .copied()
            .unwrap();
        match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                if name == "default" {
                    return Err(
                        "historical-v2 Python package wildcard exposed a default binding"
                            .to_string(),
                    );
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                name = reexport.name.clone().ok_or_else(|| {
                    "historical-v2 Python package namespace has no exposed name".to_string()
                })?;
                owner = None;
                namespace = HistoricalV2SourcePublicNamespace::Module;
                kind = HistoricalV2SourcePublicSymbolKind::Module;
            }
        }
    }
    if owner.is_some() {
        return Err("historical-v2 Python package binding exposed a member directly".to_string());
    }
    let expected_surface =
        super::public_surface::historical_python_distribution_public_surface_unit_id(
            &module.surface_slot_id,
            &name,
            None,
            namespace,
            kind,
        )?;
    let expected_declaration =
        super::public_surface::python_distribution_expansion_declaration_unit_id(
            &expected_surface,
            exposure_id,
            &binding.origin_declaration_unit_id,
            &binding.symbol_id,
            &binding.reexport_path,
        )?;
    let (expected_encoding, expected_anchor) =
        if let Some(reexport_id) = binding.reexport_path.first() {
            let hop = reexports
                .get(&(&binding.variant, reexport_id.as_str()))
                .unwrap()
                .2;
            (hop.position_encoding, hop.compiler_anchor.clone())
        } else {
            (
                binding.position_encoding,
                declaration_semantic_range(origin_path, origin, binding.position_encoding),
            )
        };
    if binding.surface_unit_id != expected_surface
        || binding.declaration_unit_id != expected_declaration
        || binding.position_encoding != expected_encoding
        || binding.compiler_anchor != expected_anchor
    {
        return Err("historical-v2 Python package binding changed public identity".to_string());
    }
    Ok(())
}

fn validate_kotlin_package_binding<'a>(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    binding: &HistoricalV2SemanticPublicBinding,
    symbol: &HistoricalV2SemanticSymbol,
    declarations: &DeclarationMap<'a>,
    direct_pairs: &BTreeSet<(&SemanticIndexVariant, &str, &str)>,
) -> Result<(), String> {
    let exposure_id = binding.package_exposure_id.as_deref().ok_or_else(|| {
        "historical-v2 Kotlin package binding has no compilation exposure identity".to_string()
    })?;
    let matching_roots = semantic
        .kotlin_compilation_roots
        .iter()
        .filter(|root| root.variant == binding.variant && root.surface_slot_id == exposure_id)
        .collect::<Vec<_>>();
    let [root] = matching_roots.as_slice() else {
        return Err(
            "historical-v2 Kotlin package binding invented or ambiguously selected a compilation root"
                .to_string(),
        );
    };
    let (origin_path, origin_indexer, origin) = declarations
        .get(binding.origin_declaration_unit_id.as_str())
        .copied()
        .ok_or_else(|| {
            "historical-v2 Kotlin package binding has no origin declaration".to_string()
        })?;
    let source_file = source
        .source_files
        .iter()
        .find(|file| file.repository_path == binding.repository_path)
        .ok_or_else(|| "historical-v2 Kotlin compilation source disappeared".to_string())?;
    if binding.indexer != IntentionalBoundaryIndexerKind::Kotlin
        || origin_indexer != IntentionalBoundaryIndexerKind::Kotlin
        || binding.binding != HistoricalV2SemanticPublicBindingKind::PackageExposure
        || !binding.externally_reachable
        || source_file.language != "kotlin"
        || origin_path != binding.repository_path
        || root
            .source_repository_paths
            .binary_search(&binding.repository_path)
            .is_err()
        || binding.owner_symbol_id.is_some()
        || binding.owner_compiler_anchor.is_some()
        || binding.exposing_owner_declaration_unit_id.is_some()
        || !binding.reexport_path.is_empty()
        || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
        || !compatible_public_symbol_kind(origin.kind, symbol.symbol.category)
        || !direct_pairs.contains(&(
            &binding.variant,
            binding.origin_declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        ))
    {
        return Err("historical-v2 Kotlin package binding changed compiler identity".to_string());
    }
    let expected_surface =
        super::public_surface::historical_kotlin_compilation_public_surface_unit_id(
            &root.surface_slot_id,
            &origin.name,
            origin.owner.as_deref(),
            origin.namespace,
            origin.kind,
        )?;
    let expected_declaration =
        super::public_surface::kotlin_compilation_expansion_declaration_unit_id(
            &expected_surface,
            &root.surface_slot_id,
            &binding.origin_declaration_unit_id,
            &binding.symbol_id,
        )?;
    let expected_anchor =
        declaration_semantic_range(origin_path, origin, binding.position_encoding);
    if origin.owner.is_some()
        || binding.surface_unit_id != expected_surface
        || binding.declaration_unit_id != expected_declaration
        || binding.compiler_anchor != expected_anchor
    {
        return Err("historical-v2 Kotlin package binding changed public identity".to_string());
    }
    Ok(())
}

fn validate_expanded_public_binding<'a>(
    binding: &HistoricalV2SemanticPublicBinding,
    symbol: &HistoricalV2SemanticSymbol,
    declarations: &DeclarationMap<'a>,
    reexports: &ReexportMap<'a>,
    direct_pairs: &BTreeSet<(&SemanticIndexVariant, &str, &str)>,
    public_root_variants: &BTreeSet<(&SemanticIndexVariant, &str)>,
) -> Result<(), String> {
    let (origin_path, origin_indexer, origin) = declarations
        .get(binding.origin_declaration_unit_id.as_str())
        .copied()
        .ok_or_else(|| "historical-v2 re-export expansion has no origin declaration".to_string())?;
    if binding.reexport_path.is_empty()
        || !binding.externally_reachable
        || binding.exposing_owner_declaration_unit_id.is_some()
        || binding.indexer != origin_indexer
        || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
        || !compatible_public_symbol_kind(origin.kind, symbol.symbol.category)
        || !direct_pairs.contains(&(
            &binding.variant,
            binding.origin_declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        ))
    {
        return Err("historical-v2 re-export expansion changed compiler identity".to_string());
    }

    let mut current_path = binding.repository_path.as_str();
    let mut seen_hops = BTreeSet::new();
    for reexport_id in &binding.reexport_path {
        if !seen_hops.insert(reexport_id.as_str()) {
            return Err("historical-v2 re-export expansion contains a cycle".to_string());
        }
        let (file, _, hop) = reexports
            .get(&(&binding.variant, reexport_id.as_str()))
            .copied()
            .ok_or_else(|| "historical-v2 re-export expansion invented a hop".to_string())?;
        if file.repository_path != current_path || hop.indexer != binding.indexer {
            return Err("historical-v2 re-export expansion path is disconnected".to_string());
        }
        current_path = hop.target_repository_path.as_str();
    }
    if current_path != origin_path {
        return Err("historical-v2 re-export expansion misses its origin".to_string());
    }

    let mut name = origin.name.clone();
    let mut owner = origin.owner.clone();
    let mut namespace = origin.namespace;
    let mut kind = origin.kind;
    for reexport_id in binding.reexport_path.iter().rev() {
        let (file, reexport, _) = reexports
            .get(&(&binding.variant, reexport_id.as_str()))
            .copied()
            .unwrap();
        match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                if name == "default" {
                    return Err(
                        "historical-v2 wildcard expansion exposed a default export".to_string()
                    );
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                name = reexport.name.clone().ok_or_else(|| {
                    "historical-v2 namespace expansion has no exposed name".to_string()
                })?;
                owner = None;
                namespace = HistoricalV2SourcePublicNamespace::Module;
                kind = HistoricalV2SourcePublicSymbolKind::Module;
            }
        }
        let module_identity = super::super::history_v2_source_census::public_module_identity(
            &file.repository_path,
            &file.language,
        );
        let expected_surface =
            super::super::history_v2_source_census::historical_public_surface_unit_id(
                &file.language,
                &module_identity,
                &name,
                owner.as_deref(),
                namespace,
                kind,
            )?;
        if reexport_id == &binding.reexport_path[0] && binding.surface_unit_id != expected_surface {
            return Err("historical-v2 re-export expansion changed public identity".to_string());
        }
    }
    let outer_hop = reexports
        .get(&(&binding.variant, binding.reexport_path[0].as_str()))
        .map(|(_, _, hop)| *hop)
        .unwrap();
    if binding.indexer == IntentionalBoundaryIndexerKind::Rust
        && !public_root_variants.contains(&(&binding.variant, binding.repository_path.as_str()))
    {
        return Err(
            "historical-v2 Rust re-export expansion does not start at a public root".to_string(),
        );
    }
    let expected_declaration = super::reexport_expansion_declaration_unit_id(
        &binding.surface_unit_id,
        &binding.repository_path,
        &binding.origin_declaration_unit_id,
        &binding.symbol_id,
        &binding.reexport_path,
    )?;
    if binding.declaration_unit_id != expected_declaration
        || binding.position_encoding != outer_hop.position_encoding
        || binding.compiler_anchor != outer_hop.compiler_anchor
    {
        return Err("historical-v2 re-export expansion changed its compiler anchor".to_string());
    }
    Ok(())
}

fn declaration_semantic_range(
    repository_path: &str,
    declaration: &super::super::HistoricalV2SourcePublicDeclaration,
    encoding: crate::semantic_index::SemanticPositionEncoding,
) -> IntentionalBoundarySemanticRange {
    let range = match encoding {
        crate::semantic_index::SemanticPositionEncoding::Utf8 => {
            declaration.identifier_positions.utf8
        }
        crate::semantic_index::SemanticPositionEncoding::Utf16 => {
            declaration.identifier_positions.utf16
        }
        crate::semantic_index::SemanticPositionEncoding::Utf32 => {
            declaration.identifier_positions.utf32
        }
    };
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: range.start.line_zero_based,
        start_character_zero_based: range.start.character_zero_based,
        end_line_zero_based: range.end.line_zero_based,
        end_character_zero_based: range.end.character_zero_based,
    }
}

fn declaration_owner_semantic_range(
    repository_path: &str,
    declaration: &super::super::HistoricalV2SourcePublicDeclaration,
    encoding: crate::semantic_index::SemanticPositionEncoding,
) -> Result<Option<IntentionalBoundarySemanticRange>, String> {
    let positions = match encoding {
        crate::semantic_index::SemanticPositionEncoding::Utf8 => declaration
            .owner_identifier_positions
            .as_ref()
            .map(|positions| positions.utf8),
        crate::semantic_index::SemanticPositionEncoding::Utf16 => declaration
            .owner_identifier_positions
            .as_ref()
            .map(|positions| positions.utf16),
        crate::semantic_index::SemanticPositionEncoding::Utf32 => declaration
            .owner_identifier_positions
            .as_ref()
            .map(|positions| positions.utf32),
    };
    match (declaration.owner_identifier, positions) {
        (None, None) => Ok(None),
        (Some(_), Some(range)) => Ok(Some(IntentionalBoundarySemanticRange {
            repository_path: repository_path.to_string(),
            start_line_zero_based: range.start.line_zero_based,
            start_character_zero_based: range.start.character_zero_based,
            end_line_zero_based: range.end.line_zero_based,
            end_character_zero_based: range.end.character_zero_based,
        })),
        _ => Err("historical-v2 public owner anchor is incomplete".to_string()),
    }
}

fn source_reexport_semantic_range(
    repository_path: &str,
    reexport: &HistoricalV2SourcePublicReexport,
    encoding: crate::semantic_index::SemanticPositionEncoding,
) -> IntentionalBoundarySemanticRange {
    let range = match encoding {
        crate::semantic_index::SemanticPositionEncoding::Utf8 => reexport.identifier_positions.utf8,
        crate::semantic_index::SemanticPositionEncoding::Utf16 => {
            reexport.identifier_positions.utf16
        }
        crate::semantic_index::SemanticPositionEncoding::Utf32 => {
            reexport.identifier_positions.utf32
        }
    };
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: range.start.line_zero_based,
        start_character_zero_based: range.start.character_zero_based,
        end_line_zero_based: range.end.line_zero_based,
        end_character_zero_based: range.end.character_zero_based,
    }
}

fn compatible_public_symbol_kind(
    declaration: HistoricalV2SourcePublicSymbolKind,
    compiler: IntentionalBoundarySemanticSymbolCategory,
) -> bool {
    matches!(
        (declaration, compiler),
        (
            HistoricalV2SourcePublicSymbolKind::CompilerDefined,
            IntentionalBoundarySemanticSymbolCategory::Callable
                | IntentionalBoundarySemanticSymbolCategory::Constructor
                | IntentionalBoundarySemanticSymbolCategory::Method
                | IntentionalBoundarySemanticSymbolCategory::Type
                | IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
                | IntentionalBoundarySemanticSymbolCategory::Module
                | IntentionalBoundarySemanticSymbolCategory::Namespace
                | IntentionalBoundarySemanticSymbolCategory::Package
                | IntentionalBoundarySemanticSymbolCategory::FieldOrProperty
                | IntentionalBoundarySemanticSymbolCategory::Variable
                | IntentionalBoundarySemanticSymbolCategory::Constant
                | IntentionalBoundarySemanticSymbolCategory::Macro
        ) | (
            HistoricalV2SourcePublicSymbolKind::Callable,
            IntentionalBoundarySemanticSymbolCategory::Callable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Module,
            IntentionalBoundarySemanticSymbolCategory::Module
                | IntentionalBoundarySemanticSymbolCategory::Namespace
                | IntentionalBoundarySemanticSymbolCategory::Package
        ) | (
            HistoricalV2SourcePublicSymbolKind::Method,
            IntentionalBoundarySemanticSymbolCategory::Method
        ) | (
            HistoricalV2SourcePublicSymbolKind::Type,
            IntentionalBoundarySemanticSymbolCategory::Type
                | IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
        ) | (
            HistoricalV2SourcePublicSymbolKind::Field,
            IntentionalBoundarySemanticSymbolCategory::FieldOrProperty
        ) | (
            HistoricalV2SourcePublicSymbolKind::Variable,
            IntentionalBoundarySemanticSymbolCategory::Variable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Constant,
            IntentionalBoundarySemanticSymbolCategory::Constant
        )
    )
}

type ExpectedMethod<'a> = (
    &'a str,
    &'a str,
    usize,
    usize,
    IntentionalBoundaryIndexerKind,
);

fn validate_methods<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    committed_variants: &BTreeSet<IndexerVariantKey<'a>>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    source_paths: &BTreeSet<&str>,
) -> Result<BTreeSet<SymbolKey<'a>>, String> {
    let mut expected = BTreeMap::<&str, ExpectedMethod<'_>>::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        for method in &file.methods {
            if expected
                .insert(
                    method.parser_unit_id.as_str(),
                    (
                        file.repository_path.as_str(),
                        method.symbol_name.as_str(),
                        method.start_line,
                        method.end_line,
                        indexer,
                    ),
                )
                .is_some()
            {
                return Err("historical-v2 source repeats a semantic method".to_string());
            }
        }
    }
    if semantic.methods.len() != expected.len()
        || semantic
            .methods
            .windows(2)
            .any(|pair| pair[0].parser_unit_id >= pair[1].parser_unit_id)
    {
        return Err("historical-v2 semantic method coverage changed".to_string());
    }

    let mut referenced_symbols = BTreeSet::new();
    let mut resolved = 0_usize;
    let mut compiler_excluded = 0_usize;
    for method in &semantic.methods {
        let expected = expected
            .get(method.parser_unit_id.as_str())
            .ok_or_else(|| "historical-v2 semantic census invented a method".to_string())?;
        if method.repository_path != expected.0
            || method.symbol_name != expected.1
            || method.start_line != expected.2
            || method.end_line != expected.3
            || method.indexer != expected.4
        {
            return Err("historical-v2 semantic method identity changed".to_string());
        }
        let actual_variants = method
            .observations
            .iter()
            .map(|observation| &observation.variant)
            .collect::<BTreeSet<_>>();
        let expected_variants = committed_variants
            .iter()
            .filter(|(indexer, _)| *indexer == method.indexer)
            .map(|(_, variant)| *variant)
            .collect::<BTreeSet<_>>();
        let untouched = !indexers.contains(&method.indexer);
        if method.observations.is_empty()
            || method
                .observations
                .windows(2)
                .any(|pair| pair[0].variant >= pair[1].variant)
            || (!untouched && actual_variants != expected_variants)
            || (untouched
                && (method.observations.len() != 1
                    || method.observations[0].variant != SemanticIndexVariant::Unqualified
                    || !matches!(
                        method.observations[0].status,
                        HistoricalV2SemanticMethodStatus::CompilerExcluded { .. }
                    )))
        {
            return Err(
                "historical-v2 semantic method compiler-variant coverage changed".to_string(),
            );
        }
        for observation in &method.observations {
            match &observation.status {
                HistoricalV2SemanticMethodStatus::Resolved {
                    symbol_id,
                    joined_definition,
                } => {
                    let key = (method.indexer, &observation.variant, symbol_id.as_str());
                    if symbol_id.trim().is_empty()
                        || !symbols.contains_key(&key)
                        || joined_definition
                            .iter()
                            .any(|location| !valid_location(location, source_paths))
                    {
                        return Err(
                            "historical-v2 resolved method has invalid compiler evidence"
                                .to_string(),
                        );
                    }
                    referenced_symbols.insert(key);
                }
                HistoricalV2SemanticMethodStatus::CompilerExcluded { reason } => {
                    if reason.trim().is_empty() {
                        return Err(
                            "historical-v2 compiler-excluded method has no evidence".to_string()
                        );
                    }
                }
                HistoricalV2SemanticMethodStatus::Unresolved { detail, .. } => {
                    if detail.trim().is_empty() {
                        return Err("historical-v2 unresolved method has no evidence".to_string());
                    }
                }
            }
        }
        match super::effective_method_status(method) {
            HistoricalV2SemanticMethodStatus::Resolved { .. } => resolved += 1,
            HistoricalV2SemanticMethodStatus::CompilerExcluded { .. } => {
                compiler_excluded += 1;
            }
            HistoricalV2SemanticMethodStatus::Unresolved { .. } => {}
        }
    }
    let unresolved = semantic
        .methods
        .len()
        .checked_sub(resolved + compiler_excluded)
        .ok_or_else(|| "historical-v2 semantic method counts underflowed".to_string())?;
    if semantic.resolved_method_count != resolved
        || semantic.compiler_excluded_method_count != compiler_excluded
        || semantic.unresolved_method_count != unresolved
    {
        return Err("historical-v2 semantic method counts changed".to_string());
    }
    Ok(referenced_symbols)
}

fn valid_location(
    location: &IntentionalBoundarySemanticRange,
    source_paths: &BTreeSet<&str>,
) -> bool {
    source_paths.contains(location.repository_path.as_str())
        && (location.end_line_zero_based > location.start_line_zero_based
            || (location.end_line_zero_based == location.start_line_zero_based
                && location.end_character_zero_based >= location.start_character_zero_based))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
