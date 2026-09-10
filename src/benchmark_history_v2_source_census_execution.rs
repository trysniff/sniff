use super::*;
use serde::de::DeserializeOwned;

pub(super) fn census_historical_v2_sources_typed_inner(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    progress_root: Option<&Path>,
) -> Result<SourceCensusStageResult, HistoricalV2SlotStageError> {
    validate_historical_v2_materialization(materialization, roots).map_err(invalid)?;
    let progress = progress_root
        .map(HistoricalV2SourceProgress::open)
        .transpose()
        .map_err(infrastructure)?;
    let inventory_repository = format!("github.com/{}", materialization.canonical_repository);
    let no_dependencies = Vec::new();
    let base_inventory = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::Inventory,
        &no_dependencies,
        || {
            inventory_intentional_boundary_repository(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
            )
            .map_err(infrastructure)
        },
        |inventory| {
            validate_intentional_boundary_repository_inventory_commitment_typed(
                &inventory_repository,
                &materialization.base_revision,
                inventory,
            )
            .map_err(|error| error.detail)
        },
    )?;
    let patched_inventory = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::Inventory,
        &no_dependencies,
        || {
            inventory_intentional_boundary_repository(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
            )
            .map_err(infrastructure)
        },
        |inventory| {
            validate_intentional_boundary_repository_inventory_commitment_typed(
                &inventory_repository,
                &materialization.patched_commit_oid,
                inventory,
            )
            .map_err(|error| error.detail)
        },
    )?;
    let base_inventory_dependency = vec![base_inventory.inventory_sha256.clone()];
    let patched_inventory_dependency = vec![patched_inventory.inventory_sha256.clone()];
    let base_failures = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::Inspection,
        &base_inventory_dependency,
        || {
            inspect_snapshot_sources(
                HistoricalV2SourceSnapshotSide::Base,
                &roots.base_root,
                &base_inventory,
            )
        },
        |failures| {
            validate_source_inspection_progress(
                materialization,
                HistoricalV2SourceSnapshotSide::Base,
                &materialization.base_revision,
                failures,
            )
        },
    )?;
    let patched_failures = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::Inspection,
        &patched_inventory_dependency,
        || {
            inspect_snapshot_sources(
                HistoricalV2SourceSnapshotSide::Patched,
                &roots.patched_root,
                &patched_inventory,
            )
        },
        |failures| {
            validate_source_inspection_progress(
                materialization,
                HistoricalV2SourceSnapshotSide::Patched,
                &materialization.patched_commit_oid,
                failures,
            )
        },
    )?;
    let mut failures = base_failures.clone();
    failures.extend(patched_failures.clone());
    if !failures.is_empty() {
        let exclusion =
            seal_source_census_exclusion(&materialization.materialization_sha256, failures)
                .map_err(|error| infrastructure(error.detail))?;
        return Ok(HistoricalV2StageResult::Excluded(exclusion));
    }
    let base_parser_dependencies = vec![
        base_inventory.inventory_sha256.clone(),
        hash_json(&base_failures).map_err(infrastructure)?,
    ];
    let patched_parser_dependencies = vec![
        patched_inventory.inventory_sha256.clone(),
        hash_json(&patched_failures).map_err(infrastructure)?,
    ];
    let base_parser_census = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::ParserCensus,
        &base_parser_dependencies,
        || {
            census_intentional_boundary_repository(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
            )
            .map_err(infrastructure)
        },
        |census| validate_source_census_commitment(&base_inventory, census),
    )?;
    let patched_parser_census = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::ParserCensus,
        &patched_parser_dependencies,
        || {
            census_intentional_boundary_repository(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
            )
            .map_err(infrastructure)
        },
        |census| validate_source_census_commitment(&patched_inventory, census),
    )?;
    let base_cargo_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::CargoProjectModel,
        &base_inventory_dependency,
        || {
            census_intentional_boundary_cargo_project_models_typed(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&base_inventory, model)
        },
    )?;
    let patched_cargo_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::CargoProjectModel,
        &patched_inventory_dependency,
        || {
            census_intentional_boundary_cargo_project_models_typed(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&patched_inventory, model)
        },
    )?;
    let base_go_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::GoProjectModel,
        &base_inventory_dependency,
        || {
            census_intentional_boundary_go_project_models_typed(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&base_inventory, model)
        },
    )?;
    let patched_go_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::GoProjectModel,
        &patched_inventory_dependency,
        || {
            census_intentional_boundary_go_project_models_typed(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&patched_inventory, model)
        },
    )?;
    let base_gradle_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::GradleProjectModel,
        &base_inventory_dependency,
        || {
            census_intentional_boundary_gradle_project_models_typed(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&base_inventory, model)
        },
    )?;
    let patched_gradle_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::GradleProjectModel,
        &patched_inventory_dependency,
        || {
            census_intentional_boundary_gradle_project_models_typed(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&patched_inventory, model)
        },
    )?;
    let base_typescript_sources = typescript_project_sources(&base_parser_census);
    let patched_typescript_sources = typescript_project_sources(&patched_parser_census);
    let base_typescript_dependencies = vec![
        base_inventory.inventory_sha256.clone(),
        base_parser_census.census_sha256.clone(),
    ];
    let patched_typescript_dependencies = vec![
        patched_inventory.inventory_sha256.clone(),
        patched_parser_census.census_sha256.clone(),
    ];
    let base_typescript_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::TypeScriptProjectModel,
        &base_typescript_dependencies,
        || {
            census_intentional_boundary_typescript_project_models_typed(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
                &base_typescript_sources,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&base_inventory, model)
        },
    )?;
    let patched_typescript_project_model = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::TypeScriptProjectModel,
        &patched_typescript_dependencies,
        || {
            census_intentional_boundary_typescript_project_models_typed(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
                &patched_typescript_sources,
            )
            .map_err(project_model_stage_error)
        },
        |model| {
            validate_intentional_boundary_project_model_census_commitment(&patched_inventory, model)
        },
    )?;
    let base_node_package_surfaces = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::NodePackageSurfaces,
        &base_inventory_dependency,
        || {
            census_historical_v2_node_package_surfaces(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
            )
            .map_err(infrastructure)
        },
        |census| {
            validate_historical_v2_node_package_surface_census_commitment(
                &roots.base_root,
                &base_inventory,
                census,
            )
        },
    )?;
    let patched_node_package_surfaces = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::NodePackageSurfaces,
        &patched_inventory_dependency,
        || {
            census_historical_v2_node_package_surfaces(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
            )
            .map_err(infrastructure)
        },
        |census| {
            validate_historical_v2_node_package_surface_census_commitment(
                &roots.patched_root,
                &patched_inventory,
                census,
            )
        },
    )?;
    let base_node_consumer_dependencies = vec![
        base_inventory.inventory_sha256.clone(),
        base_node_package_surfaces.census_sha256.clone(),
        base_typescript_project_model
            .project_model_census_sha256
            .clone(),
    ];
    let patched_node_consumer_dependencies = vec![
        patched_inventory.inventory_sha256.clone(),
        patched_node_package_surfaces.census_sha256.clone(),
        patched_typescript_project_model
            .project_model_census_sha256
            .clone(),
    ];
    let base_node_consumer_profiles = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::NodeConsumerProfiles,
        &base_node_consumer_dependencies,
        || {
            census_historical_v2_node_consumer_profiles(
                &roots.base_root,
                &base_inventory,
                &base_node_package_surfaces,
                &base_typescript_project_model,
            )
            .map_err(infrastructure)
        },
        |census| {
            validate_historical_v2_node_consumer_profile_census_commitment(
                &base_inventory,
                &base_node_package_surfaces,
                &base_typescript_project_model,
                census,
            )
        },
    )?;
    let patched_node_consumer_profiles = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::NodeConsumerProfiles,
        &patched_node_consumer_dependencies,
        || {
            census_historical_v2_node_consumer_profiles(
                &roots.patched_root,
                &patched_inventory,
                &patched_node_package_surfaces,
                &patched_typescript_project_model,
            )
            .map_err(infrastructure)
        },
        |census| {
            validate_historical_v2_node_consumer_profile_census_commitment(
                &patched_inventory,
                &patched_node_package_surfaces,
                &patched_typescript_project_model,
                census,
            )
        },
    )?;
    let base_python_distribution_surfaces = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::PythonDistributionSurfaces,
        &base_inventory_dependency,
        || {
            census_historical_v2_python_distribution_surfaces(
                &inventory_repository,
                &materialization.base_revision,
                &roots.base_root,
                &base_inventory,
            )
            .map_err(infrastructure)
        },
        |census| {
            validate_historical_v2_python_distribution_surface_census_commitment_only(
                &base_inventory,
                census,
            )
        },
    )?;
    let patched_python_distribution_surfaces = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::PythonDistributionSurfaces,
        &patched_inventory_dependency,
        || {
            census_historical_v2_python_distribution_surfaces(
                &inventory_repository,
                &materialization.patched_commit_oid,
                &roots.patched_root,
                &patched_inventory,
            )
            .map_err(infrastructure)
        },
        |census| {
            validate_historical_v2_python_distribution_surface_census_commitment_only(
                &patched_inventory,
                census,
            )
        },
    )?;

    let base_snapshot_dependencies = snapshot_progress_dependencies(
        &base_inventory,
        &base_parser_census,
        &base_cargo_project_model,
        &base_go_project_model,
        &base_gradle_project_model,
        &base_typescript_project_model,
        &base_node_package_surfaces,
        &base_node_consumer_profiles,
        &base_python_distribution_surfaces,
    );
    let patched_snapshot_dependencies = snapshot_progress_dependencies(
        &patched_inventory,
        &patched_parser_census,
        &patched_cargo_project_model,
        &patched_go_project_model,
        &patched_gradle_project_model,
        &patched_typescript_project_model,
        &patched_node_package_surfaces,
        &patched_node_consumer_profiles,
        &patched_python_distribution_surfaces,
    );
    let base_snapshot = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &materialization.base_revision,
        HistoricalV2SourceProgressUnit::Snapshot,
        &base_snapshot_dependencies,
        || {
            project_snapshot(
                &roots.base_root,
                &base_inventory,
                &base_parser_census,
                ProjectSnapshotSemanticInputs {
                    cargo_project_model: base_cargo_project_model.clone(),
                    go_project_model: base_go_project_model.clone(),
                    gradle_project_model: base_gradle_project_model.clone(),
                    typescript_project_model: base_typescript_project_model.clone(),
                    node_package_surfaces: base_node_package_surfaces.clone(),
                    node_consumer_profiles: base_node_consumer_profiles.clone(),
                    python_distribution_surfaces: base_python_distribution_surfaces.clone(),
                },
            )
            .map_err(infrastructure)
        },
        |snapshot| validate_snapshot_progress(&base_snapshot_dependencies, snapshot),
    )?;
    let patched_snapshot = source_progress_value(
        progress.as_ref(),
        materialization,
        HistoricalV2SourceSnapshotSide::Patched,
        &materialization.patched_commit_oid,
        HistoricalV2SourceProgressUnit::Snapshot,
        &patched_snapshot_dependencies,
        || {
            project_snapshot(
                &roots.patched_root,
                &patched_inventory,
                &patched_parser_census,
                ProjectSnapshotSemanticInputs {
                    cargo_project_model: patched_cargo_project_model.clone(),
                    go_project_model: patched_go_project_model.clone(),
                    gradle_project_model: patched_gradle_project_model.clone(),
                    typescript_project_model: patched_typescript_project_model.clone(),
                    node_package_surfaces: patched_node_package_surfaces.clone(),
                    node_consumer_profiles: patched_node_consumer_profiles.clone(),
                    python_distribution_surfaces: patched_python_distribution_surfaces.clone(),
                },
            )
            .map_err(infrastructure)
        },
        |snapshot| validate_snapshot_progress(&patched_snapshot_dependencies, snapshot),
    )?;

    let mut census = HistoricalV2SourceCensus {
        schema_version: HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION,
        source_census_contract: SOURCE_CENSUS_CONTRACT.to_string(),
        canonical_repository: materialization.canonical_repository.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        base: base_snapshot,
        patched: patched_snapshot,
        source_census_sha256: String::new(),
    };
    census.source_census_sha256 = source_census_sha256(&census).map_err(infrastructure)?;
    Ok(HistoricalV2StageResult::Completed(census))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn source_progress_value<T, C, V>(
    progress: Option<&HistoricalV2SourceProgress>,
    materialization: &HistoricalV2Materialization,
    side: HistoricalV2SourceSnapshotSide,
    revision: &str,
    unit: HistoricalV2SourceProgressUnit,
    dependency_sha256s: &[String],
    compute: C,
    validate: V,
) -> Result<T, HistoricalV2SlotStageError>
where
    T: Clone + Serialize + DeserializeOwned,
    C: FnOnce() -> Result<T, HistoricalV2SlotStageError>,
    V: Fn(&T) -> Result<(), String>,
{
    if let Some(value) = progress
        .map(|progress| progress.load(materialization, side, revision, unit, dependency_sha256s))
        .transpose()
        .map_err(infrastructure)?
        .flatten()
    {
        validate(&value).map_err(infrastructure)?;
        return Ok(value);
    }
    let value = compute()?;
    validate(&value).map_err(infrastructure)?;
    if let Some(progress) = progress {
        progress
            .publish(
                materialization,
                side,
                revision,
                unit,
                dependency_sha256s,
                &value,
            )
            .map_err(infrastructure)?;
    }
    Ok(value)
}

fn validate_source_inspection_progress(
    materialization: &HistoricalV2Materialization,
    side: HistoricalV2SourceSnapshotSide,
    revision: &str,
    failures: &[HistoricalV2SourceCensusFailureEvidence],
) -> Result<(), String> {
    for failure in failures {
        let (observed_side, observed_revision) = match failure {
            HistoricalV2SourceCensusFailureEvidence::RepositoryContainsGitlink {
                side,
                revision,
                ..
            }
            | HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
                side,
                revision,
                ..
            }
            | HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
                side,
                revision,
                ..
            }
            | HistoricalV2SourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
                side,
                revision,
                ..
            } => (*side, revision.as_str()),
        };
        if observed_side != side || observed_revision != revision {
            return Err("historical-v2 source inspection progress changed identity".to_string());
        }
    }
    if !failures.is_empty() {
        seal_source_census_exclusion(&materialization.materialization_sha256, failures.to_vec())
            .map_err(|error| error.detail)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn snapshot_progress_dependencies(
    inventory: &IntentionalBoundaryRepositoryInventory,
    parser_census: &IntentionalBoundarySourceCensus,
    cargo_project_model: &IntentionalBoundaryProjectModelCensus,
    go_project_model: &IntentionalBoundaryProjectModelCensus,
    gradle_project_model: &IntentionalBoundaryProjectModelCensus,
    typescript_project_model: &IntentionalBoundaryProjectModelCensus,
    node_package_surfaces: &HistoricalV2NodePackageSurfaceCensus,
    node_consumer_profiles: &HistoricalV2NodeConsumerProfileCensus,
    python_distribution_surfaces: &HistoricalV2PythonDistributionSurfaceCensus,
) -> Vec<String> {
    vec![
        inventory.inventory_sha256.clone(),
        parser_census.census_sha256.clone(),
        cargo_project_model.project_model_census_sha256.clone(),
        go_project_model.project_model_census_sha256.clone(),
        gradle_project_model.project_model_census_sha256.clone(),
        typescript_project_model.project_model_census_sha256.clone(),
        node_package_surfaces.census_sha256.clone(),
        node_consumer_profiles.census_sha256.clone(),
        python_distribution_surfaces.census_sha256.clone(),
    ]
}

fn validate_snapshot_progress(
    dependency_sha256s: &[String],
    snapshot: &HistoricalV2SourceSnapshotCensus,
) -> Result<(), String> {
    let observed = vec![
        snapshot.inventory_sha256.clone(),
        snapshot.parser_census_sha256.clone(),
        snapshot
            .cargo_project_model
            .project_model_census_sha256
            .clone(),
        snapshot
            .go_project_model
            .project_model_census_sha256
            .clone(),
        snapshot
            .gradle_project_model
            .project_model_census_sha256
            .clone(),
        snapshot
            .typescript_project_model
            .project_model_census_sha256
            .clone(),
        snapshot.node_package_surfaces.census_sha256.clone(),
        snapshot.node_consumer_profiles.census_sha256.clone(),
        snapshot.python_distribution_surfaces.census_sha256.clone(),
    ];
    if observed != dependency_sha256s
        || snapshot.snapshot_census_sha256 != snapshot_census_sha256(snapshot)?
    {
        return Err("historical-v2 source snapshot progress commitment changed".to_string());
    }
    Ok(())
}
