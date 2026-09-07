use super::{
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelProvider,
    IntentionalBoundaryProjectModelTargetStatus,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const GO_PACKAGE_SURFACE_SLOT_CONTRACT: &str =
    "sniffbench-historical-v2-go-package-surface-slot-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HistoricalV2GoPackageExposure {
    pub(super) target_id: String,
    pub(super) surface_slot_id: String,
    pub(super) module_path: String,
    pub(super) import_path: String,
    pub(super) source_repository_paths: Vec<String>,
    pub(super) externally_reachable: bool,
}

pub(super) fn go_package_exposures(
    model: &IntentionalBoundaryProjectModelCensus,
) -> Result<Vec<HistoricalV2GoPackageExposure>, String> {
    let mut exposures = Vec::with_capacity(model.targets.len());
    let mut target_ids = BTreeSet::new();
    let mut source_owners = BTreeMap::new();
    for target in &model.targets {
        if target.provider != IntentionalBoundaryProjectModelProvider::GoList {
            return Err("historical-v2 Go project model mixed providers".to_string());
        }
        if !target_ids.insert(target.target_id.as_str()) {
            return Err("historical-v2 Go project model repeated a target identity".to_string());
        }
        let (provider_kind, expected_declaration, externally_reachable) =
            match target.provider_kinds.as_slice() {
                [kind] if kind == "package" => (
                    "package",
                    IntentionalBoundaryManifestDeclarationKind::PublishedModule,
                    !go_import_path_is_internal(&target.target_name),
                ),
                [kind] if kind == "main" => (
                    "main",
                    IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
                    false,
                ),
                _ => {
                    return Err(format!(
                        "historical-v2 Go target {} has an unsupported package kind",
                        target.target_name
                    ));
                }
            };
        let expected_output = if provider_kind == "package" {
            "package_archive"
        } else {
            "executable"
        };
        if target.provider_output_types.as_slice() != [expected_output]
            || target.package_name.trim().is_empty()
            || target.target_name.trim().is_empty()
            || (target.target_name != target.package_name
                && !target
                    .target_name
                    .strip_prefix(&target.package_name)
                    .is_some_and(|suffix| suffix.starts_with('/')))
        {
            return Err(format!(
                "historical-v2 Go target {} changed compiler package identity",
                target.target_name
            ));
        }
        let IntentionalBoundaryProjectModelTargetStatus::Boundary {
            declaration_kind,
            target: IntentionalBoundaryManifestTarget::RepositoryPaths { repository_paths },
        } = &target.target_status
        else {
            return Err(format!(
                "historical-v2 Go target {} has unresolved public exposure",
                target.target_name
            ));
        };
        if *declaration_kind != expected_declaration
            || repository_paths != &target.source_repository_paths
            || repository_paths.is_empty()
        {
            return Err(format!(
                "historical-v2 Go target {} changed its compiler source boundary",
                target.target_name
            ));
        }
        for source in repository_paths {
            if source_owners
                .insert(source.as_str(), target.target_name.as_str())
                .is_some()
            {
                return Err(format!(
                    "historical-v2 Go source {source} belongs to more than one compiler package"
                ));
            }
        }
        exposures.push(HistoricalV2GoPackageExposure {
            target_id: target.target_id.clone(),
            surface_slot_id: go_package_surface_slot_id(&target.package_name, &target.target_name)?,
            module_path: target.package_name.clone(),
            import_path: target.target_name.clone(),
            source_repository_paths: repository_paths.clone(),
            externally_reachable,
        });
    }
    exposures.sort_by(|left, right| {
        left.import_path
            .cmp(&right.import_path)
            .then_with(|| left.target_id.cmp(&right.target_id))
    });
    Ok(exposures)
}

pub(super) fn go_package_source_map<'a>(
    exposures: &'a [HistoricalV2GoPackageExposure],
) -> Result<BTreeMap<&'a str, &'a HistoricalV2GoPackageExposure>, String> {
    let mut sources = BTreeMap::new();
    for exposure in exposures {
        for source in &exposure.source_repository_paths {
            if sources.insert(source.as_str(), exposure).is_some() {
                return Err(format!(
                    "historical-v2 Go source {source} belongs to more than one package exposure"
                ));
            }
        }
    }
    Ok(sources)
}

pub(super) fn go_package_surface_slot_id(
    module_path: &str,
    import_path: &str,
) -> Result<String, String> {
    hash_json(&(GO_PACKAGE_SURFACE_SLOT_CONTRACT, module_path, import_path))
        .map(|hash| format!("h2gops-v1:{hash}"))
}

fn go_import_path_is_internal(import_path: &str) -> bool {
    import_path.split('/').any(|segment| segment == "internal")
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 Go package exposure: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v2_go_package_surface_tests.rs"]
mod tests;
