use super::*;
use crate::benchmark::release::IntentionalBoundaryProjectModelVariant;

pub(super) fn compiler_kotlin_public_compilations(
    source: &HistoricalV2SourceSnapshotCensus,
    index: &SemanticIndex,
) -> Result<Vec<HistoricalV2SemanticKotlinCompilationRoot>, String> {
    let indexed_paths = index.documents.keys().cloned().collect::<BTreeSet<_>>();
    expected_kotlin_public_compilations(source, &index.variant, &indexed_paths)
}

pub(crate) fn expected_kotlin_public_compilations(
    source: &HistoricalV2SourceSnapshotCensus,
    variant: &SemanticIndexVariant,
    indexed_paths: &BTreeSet<RepositoryPath>,
) -> Result<Vec<HistoricalV2SemanticKotlinCompilationRoot>, String> {
    let model = &source.gradle_project_model;
    if model.revision != source.revision || model.inventory_sha256 != source.inventory_sha256 {
        return Err("historical-v2 Gradle project-model identity changed".to_string());
    }
    let source_files = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let required_kotlin_paths = source_files
        .values()
        .filter(|file| {
            file.language == "kotlin"
                && file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required
        })
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let modeled_kotlin_paths = model
        .executions
        .iter()
        .flat_map(|execution| match &execution.variant {
            IntentionalBoundaryProjectModelVariant::Gradle { kotlin_projects } => kotlin_projects
                .iter()
                .flat_map(|project| project.source_sets.iter())
                .flat_map(|source_set| source_set.source_repository_paths.iter())
                .map(String::as_str)
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect::<BTreeSet<_>>();
    if let Some(path) = required_kotlin_paths
        .iter()
        .find(|path| !modeled_kotlin_paths.contains(**path))
    {
        return Err(format!(
            "historical-v2 required Kotlin source has no exact Gradle source-set ownership: {path}"
        ));
    }
    let mut roots = Vec::new();
    for execution in &model.executions {
        if execution.provider != IntentionalBoundaryProjectModelProvider::GradleToolingApi {
            return Err("historical-v2 Gradle model mixed project-model providers".to_string());
        }
        let IntentionalBoundaryProjectModelVariant::Gradle { kotlin_projects } = &execution.variant
        else {
            return Err("historical-v2 Gradle model contains an untyped execution".to_string());
        };
        for project in kotlin_projects {
            let matching_targets = model
                .targets
                .iter()
                .filter(|target| {
                    target.execution_id == execution.execution_id
                        && target.target_name == project.project_path
                })
                .collect::<Vec<_>>();
            let [project_target] = matching_targets.as_slice() else {
                return Err(format!(
                    "historical-v2 Gradle Kotlin project {} has {} project-model targets",
                    project.project_path,
                    matching_targets.len()
                ));
            };
            let externally_published = match project_target.target_status {
                IntentionalBoundaryProjectModelTargetStatus::Boundary {
                    declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
                    ..
                } => true,
                IntentionalBoundaryProjectModelTargetStatus::Boundary { .. }
                | IntentionalBoundaryProjectModelTargetStatus::NonBoundary { .. } => false,
                IntentionalBoundaryProjectModelTargetStatus::Unresolved { .. } => {
                    return Err(format!(
                        "historical-v2 Gradle Kotlin project {} has unresolved publication status",
                        project.project_path
                    ));
                }
            };
            for target in project.targets.iter().filter(|target| target.publishable) {
                if !externally_published {
                    continue;
                }
                if target.component_names.is_empty()
                    || target
                        .component_names
                        .iter()
                        .any(|component| project.component_names.binary_search(component).is_err())
                {
                    return Err(format!(
                        "historical-v2 Gradle Kotlin target {} has no exact project component ownership",
                        target.name
                    ));
                }
                let main = target
                    .compilations
                    .iter()
                    .filter(|compilation| compilation.name == "main")
                    .collect::<Vec<_>>();
                let [main] = main.as_slice() else {
                    return Err(format!(
                        "historical-v2 publishable Gradle Kotlin target {} has {} main compilations",
                        target.name,
                        main.len()
                    ));
                };
                let mut source_repository_paths = main
                    .source_sets
                    .iter()
                    .map(|name| {
                        project
                            .source_sets
                            .binary_search_by(|source_set| source_set.name.cmp(name))
                            .map(|index| &project.source_sets[index])
                            .map_err(|_| {
                                format!(
                                    "historical-v2 Gradle Kotlin compilation {} references unknown source set {name}",
                                    target.name
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, String>>()?
                    .into_iter()
                    .flat_map(|source_set| source_set.source_repository_paths.iter().cloned())
                    .collect::<Vec<_>>();
                source_repository_paths.sort();
                source_repository_paths.dedup();
                if source_repository_paths.is_empty() {
                    return Err(format!(
                        "historical-v2 publishable Gradle Kotlin target {} has an empty main compilation",
                        target.name
                    ));
                }
                for path in &source_repository_paths {
                    if project_target
                        .source_repository_paths
                        .binary_search(path)
                        .is_err()
                    {
                        return Err(format!(
                            "historical-v2 Gradle Kotlin source {path} escaped its project-model target"
                        ));
                    }
                    let Some(file) = source_files.get(path.as_str()) else {
                        return Err(format!(
                            "historical-v2 Gradle Kotlin source is absent from the source census: {path}"
                        ));
                    };
                    if file.language != "kotlin"
                        || file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required
                        || !indexed_paths.contains(&RepositoryPath(path.clone()))
                    {
                        return Err(format!(
                            "historical-v2 Gradle Kotlin source is not compiler-indexed required Kotlin: {path}"
                        ));
                    }
                }
                let surface_slot_id = kotlin_compilation_surface_slot_id(
                    &project_target.package_name,
                    &project.project_path,
                    &target.name,
                    &target.platform_type,
                    &target.component_names,
                )?;
                roots.push(HistoricalV2SemanticKotlinCompilationRoot {
                    variant: variant.clone(),
                    project_model_execution_id: execution.execution_id.clone(),
                    project_model_target_id: project_target.target_id.clone(),
                    surface_slot_id,
                    project_path: project.project_path.clone(),
                    target_name: target.name.clone(),
                    platform_type: target.platform_type.clone(),
                    component_names: target.component_names.clone(),
                    source_set_names: main.source_sets.clone(),
                    source_repository_paths,
                });
            }
        }
    }
    roots.sort();
    if roots.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("historical-v2 Gradle Kotlin compilation roots are repeated".to_string());
    }
    Ok(roots)
}

pub(super) fn kotlin_compilation_surface_slot_id(
    package_name: &str,
    project_path: &str,
    target_name: &str,
    platform_type: &str,
    component_names: &[String],
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-kotlin-compilation-surface-v1",
        package_name,
        project_path,
        target_name,
        platform_type,
        component_names,
    ))
    .map(|hash| format!("h2kcs-v1:{hash}"))
}

pub(crate) fn historical_kotlin_compilation_public_surface_unit_id(
    surface_slot_id: &str,
    name: &str,
    owner: Option<&str>,
    namespace: HistoricalV2SourcePublicNamespace,
    kind: HistoricalV2SourcePublicSymbolKind,
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-kotlin-compilation-public-surface-v1",
        surface_slot_id,
        name,
        owner,
        namespace,
        kind,
    ))
    .map(|hash| format!("h2kcps-v1:{hash}"))
}

pub(crate) fn kotlin_compilation_expansion_declaration_unit_id(
    surface_unit_id: &str,
    surface_slot_id: &str,
    origin_declaration_unit_id: &str,
    symbol_id: &str,
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-kotlin-compilation-expansion-v1",
        surface_unit_id,
        surface_slot_id,
        origin_declaration_unit_id,
        symbol_id,
    ))
    .map(|hash| format!("h2kcex-v1:{hash}"))
}
