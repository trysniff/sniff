use super::intentional_boundary_inventory::{
    read_intentional_boundary_git_blob_typed,
    validate_intentional_boundary_repository_inventory_typed,
};
use super::intentional_boundary_manifest::{
    ParsedNodePackageEntryKind, parse_node_package_json, resolve_manifest_path, span_range,
};
use super::{
    BoundaryGitEntryKind, HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION,
    HistoricalV2NodePackageCondition, HistoricalV2NodePackageDocument,
    HistoricalV2NodePackageEntryKind, HistoricalV2NodePackageExposure,
    HistoricalV2NodePackageSurfaceCensus, HistoricalV2NodePackageTargetStatus,
    IntentionalBoundaryRepositoryInventory,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const NODE_PACKAGE_SURFACE_CONTRACT: &str = "sniffbench-historical-v2-node-package-surfaces-v1";

pub(super) fn census_historical_v2_node_package_surfaces(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<HistoricalV2NodePackageSurfaceCensus, String> {
    validate_intentional_boundary_repository_inventory_typed(repository, revision, root, inventory)
        .map_err(|error| error.detail)?;
    let mut documents = Vec::new();
    let mut exposures = Vec::new();
    for entry in inventory.tracked_entries.iter().filter(|entry| {
        entry
            .repository_path
            .rsplit('/')
            .next()
            .is_some_and(|name| name == "package.json")
    }) {
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            return Err(format!(
                "historical-v2 Node package manifest is not a regular Git blob: {}",
                entry.repository_path
            ));
        }
        let byte_length = entry.byte_length.ok_or_else(|| {
            format!(
                "historical-v2 Node package manifest has no committed byte length: {}",
                entry.repository_path
            )
        })?;
        let bytes = read_intentional_boundary_git_blob_typed(root, &entry.object_id, byte_length)
            .map_err(|error| error.detail)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| {
            format!(
                "historical-v2 Node package manifest is not UTF-8: {}",
                entry.repository_path
            )
        })?;
        let parsed = parse_node_package_json(&entry.repository_path, source)?;
        let exposure_start = exposures.len();
        for parsed_exposure in parsed.exposures {
            let target_repository_path =
                resolve_manifest_path(&entry.repository_path, &parsed_exposure.target)?;
            validate_target_within_package(&entry.repository_path, &target_repository_path)?;
            let target_entry = inventory
                .tracked_entries
                .iter()
                .find(|candidate| candidate.repository_path == target_repository_path);
            let (target_status, target_object_id) = match target_entry {
                Some(target) if target.kind == BoundaryGitEntryKind::RegularBlob => (
                    HistoricalV2NodePackageTargetStatus::TrackedRegularFile,
                    Some(target.object_id.clone()),
                ),
                Some(_) => (HistoricalV2NodePackageTargetStatus::NotRegularFile, None),
                None => (
                    HistoricalV2NodePackageTargetStatus::MissingFromInventory,
                    None,
                ),
            };
            let conditions = parsed_exposure
                .conditions
                .into_iter()
                .map(|condition| HistoricalV2NodePackageCondition {
                    name: condition.name,
                    ordinal: condition.ordinal,
                    location: span_range(&entry.repository_path, source, condition.span),
                })
                .collect::<Vec<_>>();
            let mut exposure = HistoricalV2NodePackageExposure {
                exposure_id: String::new(),
                surface_slot_id: node_package_surface_slot_id(
                    parsed.package_name.as_deref(),
                    &entry.repository_path,
                    map_entry_kind(parsed_exposure.entry_kind),
                    &parsed_exposure.public_subpath,
                    &conditions,
                    &parsed_exposure.fallback_indices,
                )?,
                manifest_repository_path: entry.repository_path.clone(),
                manifest_object_id: entry.object_id.clone(),
                package_name: parsed.package_name.clone(),
                entry_kind: map_entry_kind(parsed_exposure.entry_kind),
                public_subpath: parsed_exposure.public_subpath,
                public_subpath_location: span_range(
                    &entry.repository_path,
                    source,
                    parsed_exposure.public_subpath_span,
                ),
                conditions,
                fallback_indices: parsed_exposure.fallback_indices,
                target_repository_path,
                target_location: span_range(
                    &entry.repository_path,
                    source,
                    parsed_exposure.target_span,
                ),
                target_status,
                target_object_id,
            };
            exposure.exposure_id = exposure_id(&exposure)?;
            exposures.push(exposure);
        }
        documents.push(HistoricalV2NodePackageDocument {
            manifest_repository_path: entry.repository_path.clone(),
            manifest_object_id: entry.object_id.clone(),
            source_sha256: sha256(&bytes),
            package_name: parsed.package_name,
            private: parsed.private,
            has_exports: parsed.has_exports,
            exposure_count: exposures.len() - exposure_start,
        });
    }
    documents.sort();
    exposures.sort();
    if documents
        .windows(2)
        .any(|pair| pair[0].manifest_repository_path == pair[1].manifest_repository_path)
        || exposures
            .windows(2)
            .any(|pair| pair[0].exposure_id == pair[1].exposure_id)
    {
        return Err("historical-v2 Node package surface census is non-unique".to_string());
    }
    let exposure_count_by_entry_kind =
        exposures
            .iter()
            .fold(BTreeMap::new(), |mut counts, exposure| {
                *counts.entry(exposure.entry_kind).or_insert(0) += 1;
                counts
            });
    let mut census = HistoricalV2NodePackageSurfaceCensus {
        schema_version: HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION,
        contract: NODE_PACKAGE_SURFACE_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        documents,
        exposures,
        exposure_count_by_entry_kind,
        census_sha256: String::new(),
    };
    census.census_sha256 = node_package_surface_census_sha256(&census)?;
    Ok(census)
}

pub(super) fn validate_historical_v2_node_package_surface_census_commitment(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &HistoricalV2NodePackageSurfaceCensus,
) -> Result<(), String> {
    if census.schema_version != HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION
        || census.contract != NODE_PACKAGE_SURFACE_CONTRACT
        || census.repository != inventory.repository
        || census.revision != inventory.revision
        || census.inventory_sha256 != inventory.inventory_sha256
        || census.census_sha256 != node_package_surface_census_sha256(census)?
    {
        return Err("historical-v2 Node package surface commitment changed".to_string());
    }
    let counts = census
        .exposures
        .iter()
        .fold(BTreeMap::new(), |mut counts, exposure| {
            *counts.entry(exposure.entry_kind).or_insert(0) += 1;
            counts
        });
    if counts != census.exposure_count_by_entry_kind
        || census.documents.windows(2).any(|pair| pair[0] >= pair[1])
        || census.exposures.windows(2).any(|pair| pair[0] >= pair[1])
        || census.documents.iter().any(|document| {
            document.exposure_count
                != census
                    .exposures
                    .iter()
                    .filter(|exposure| {
                        exposure.manifest_repository_path == document.manifest_repository_path
                            && exposure.manifest_object_id == document.manifest_object_id
                    })
                    .count()
        })
    {
        return Err("historical-v2 Node package surface commitment changed".to_string());
    }
    for exposure in &census.exposures {
        if exposure.exposure_id != exposure_id(exposure)?
            || matches!(
                exposure.target_status,
                HistoricalV2NodePackageTargetStatus::TrackedRegularFile
            ) != exposure.target_object_id.is_some()
        {
            return Err("historical-v2 Node package surface commitment changed".to_string());
        }
    }
    let expected = census_historical_v2_node_package_surfaces(
        &inventory.repository,
        &inventory.revision,
        root,
        inventory,
    )?;
    if census != &expected {
        return Err("historical-v2 Node package surface census changed".to_string());
    }
    Ok(())
}

fn map_entry_kind(kind: ParsedNodePackageEntryKind) -> HistoricalV2NodePackageEntryKind {
    match kind {
        ParsedNodePackageEntryKind::Exports => HistoricalV2NodePackageEntryKind::Exports,
        ParsedNodePackageEntryKind::Main => HistoricalV2NodePackageEntryKind::Main,
        ParsedNodePackageEntryKind::Module => HistoricalV2NodePackageEntryKind::Module,
        ParsedNodePackageEntryKind::Types => HistoricalV2NodePackageEntryKind::Types,
        ParsedNodePackageEntryKind::Typings => HistoricalV2NodePackageEntryKind::Typings,
    }
}

fn validate_target_within_package(
    manifest_repository_path: &str,
    target_repository_path: &str,
) -> Result<(), String> {
    let package_directory = manifest_repository_path
        .strip_suffix("package.json")
        .unwrap_or_default();
    if !target_repository_path.starts_with(package_directory) {
        return Err(format!(
            "historical-v2 Node package target escapes its package: {target_repository_path}"
        ));
    }
    Ok(())
}

fn exposure_id(exposure: &HistoricalV2NodePackageExposure) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-node-package-exposure-v1",
        &exposure.manifest_repository_path,
        &exposure.manifest_object_id,
        &exposure.surface_slot_id,
        &exposure.package_name,
        exposure.entry_kind,
        &exposure.public_subpath,
        &exposure.public_subpath_location,
        &exposure.conditions,
        &exposure.fallback_indices,
        &exposure.target_repository_path,
        &exposure.target_location,
        exposure.target_status,
        &exposure.target_object_id,
    ))
    .map(|hash| format!("h2ne-v1:{hash}"))
}

fn node_package_surface_slot_id(
    package_name: Option<&str>,
    manifest_repository_path: &str,
    entry_kind: HistoricalV2NodePackageEntryKind,
    public_subpath: &str,
    conditions: &[HistoricalV2NodePackageCondition],
    fallback_indices: &[usize],
) -> Result<String, String> {
    let package_identity = package_name.map_or_else(
        || ("manifest_path", manifest_repository_path),
        |name| ("package_name", name),
    );
    let condition_identity = conditions
        .iter()
        .map(|condition| (condition.name.as_str(), condition.ordinal))
        .collect::<Vec<_>>();
    hash_json(&(
        "sniffbench-historical-v2-node-package-surface-slot-v1",
        package_identity,
        entry_kind,
        public_subpath,
        condition_identity,
        fallback_indices,
    ))
    .map(|hash| format!("h2nes-v1:{hash}"))
}

fn node_package_surface_census_sha256(
    census: &HistoricalV2NodePackageSurfaceCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.documents,
        &census.exposures,
        &census.exposure_count_by_entry_kind,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 Node package surfaces: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v2_node_package_surface_tests.rs"]
mod tests;
