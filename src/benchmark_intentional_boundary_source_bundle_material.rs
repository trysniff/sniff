use super::*;

pub(super) fn validate_materials<'a>(
    materials: &'a [IntentionalBoundarySourceMaterial<'a>],
    required: &BTreeSet<(&str, &str)>,
    frame: &IntentionalBoundaryCandidateFrame,
) -> Result<BTreeMap<(&'a str, &'a str), &'a IntentionalBoundarySourceMaterial<'a>>, String> {
    let mut material_map = BTreeMap::new();
    for material in materials {
        let identity = (
            material.inventory.repository.as_str(),
            material.inventory.revision.as_str(),
        );
        if !required.contains(&identity) {
            return Err(format!(
                "intentional-boundary source material is not selected: {}@{}",
                identity.0, identity.1
            ));
        }
        if material_map.insert(identity, material).is_some() {
            return Err(format!(
                "intentional-boundary source material is repeated: {}@{}",
                identity.0, identity.1
            ));
        }
        validate_intentional_boundary_repository_inventory(
            identity.0,
            identity.1,
            material.root,
            material.inventory,
        )?;
        validate_intentional_boundary_source_census(
            identity.0,
            identity.1,
            material.root,
            material.inventory,
            material.source_census,
        )?;
        let frame_census = frame
            .rank_records
            .iter()
            .find_map(|record| match &record.outcome {
                IntentionalBoundaryFrameRankOutcome::Analyzed {
                    inventory_sha256,
                    candidate_census,
                } if candidate_census.repository == identity.0
                    && candidate_census.revision == identity.1 =>
                {
                    Some((inventory_sha256, candidate_census.as_ref()))
                }
                _ => None,
            });
        let Some((inventory_sha256, candidate_census)) = frame_census else {
            return Err(format!(
                "intentional-boundary frame has no analyzed source for {}@{}",
                identity.0, identity.1
            ));
        };
        if inventory_sha256 != &material.inventory.inventory_sha256
            || candidate_census.source_census_sha256 != material.source_census.census_sha256
        {
            return Err(format!(
                "intentional-boundary source material changed its frame commitments: {}@{}",
                identity.0, identity.1
            ));
        }
    }
    if material_map.len() != required.len() {
        return Err(
            "intentional-boundary source material is missing a selected repository".to_string(),
        );
    }
    Ok(material_map)
}

pub(super) fn source_repository(
    selection: &IntentionalBoundarySlotSelection,
    material: &IntentionalBoundarySourceMaterial<'_>,
) -> Result<IntentionalBoundarySourceRepository, String> {
    let source_repository_id = format!(
        "ibr-v1:{}",
        hash_json(&(
            SOURCE_REPOSITORY_CONTRACT,
            &selection.selection_sha256,
            &material.inventory.repository,
            &material.inventory.revision,
        ))?
    );
    let repository_directory = source_repository_id
        .strip_prefix("ibr-v1:")
        .expect("source repository ID prefix");
    let artifacts = material
        .inventory
        .tracked_entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let (artifact_path, content_sha256) = match entry.byte_length {
                Some(expected_length) => {
                    let bytes = read_intentional_boundary_git_blob(
                        material.root,
                        &entry.object_id,
                        expected_length,
                    )?;
                    (
                        Some(format!("artifacts/{repository_directory}/{index:08}.blob")),
                        Some(sha256(&bytes)),
                    )
                }
                None if entry.kind == BoundaryGitEntryKind::Gitlink => (None, None),
                None => {
                    return Err(format!(
                        "intentional-boundary Git blob has no committed length: {}",
                        entry.repository_path
                    ));
                }
            };
            Ok(IntentionalBoundarySourceArtifact {
                repository_path: entry.repository_path.clone(),
                mode: entry.mode.clone(),
                kind: entry.kind,
                object_id: entry.object_id.clone(),
                byte_length: entry.byte_length,
                artifact_path,
                content_sha256,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(IntentionalBoundarySourceRepository {
        source_repository_id,
        repository: material.inventory.repository.clone(),
        revision: material.inventory.revision.clone(),
        inventory_sha256: material.inventory.inventory_sha256.clone(),
        source_census_sha256: material.source_census.census_sha256.clone(),
        tracked_entry_count: artifacts.len(),
        artifacts,
    })
}
