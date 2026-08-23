use super::intentional_boundary_inventory::{
    INVENTORY_CONTRACT, compute_inventory_sha256, require_object_id, validate_git_path,
};
use super::source_selection::normalize_repository;
use super::{
    BoundaryGitEntryKind, INTENTIONAL_BOUNDARY_INVENTORY_SCHEMA_VERSION,
    IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryRepositoryInventory,
};

pub fn validate_intentional_boundary_repository_inventory_commitment_typed(
    repository: &str,
    revision: &str,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<(), IntentionalBoundaryInventoryError> {
    let repository = normalize_repository(repository).map_err(invalid)?;
    require_object_id(
        "intentional-boundary revision",
        revision,
        inventory.git_object_format,
    )
    .map_err(invalid)?;
    if inventory.schema_version != INTENTIONAL_BOUNDARY_INVENTORY_SCHEMA_VERSION
        || inventory.inventory_contract != INVENTORY_CONTRACT
        || inventory.repository != repository
        || inventory.revision != revision.to_ascii_lowercase()
        || inventory
            .tracked_entries
            .windows(2)
            .any(|pair| pair[0].repository_path >= pair[1].repository_path)
    {
        return Err(invalid(
            "intentional-boundary Git inventory commitment identity changed",
        ));
    }
    for entry in &inventory.tracked_entries {
        validate_git_path(&entry.repository_path).map_err(invalid)?;
        require_object_id(
            "intentional-boundary Git object",
            &entry.object_id,
            inventory.git_object_format,
        )
        .map_err(invalid)?;
        let valid_shape = match entry.kind {
            BoundaryGitEntryKind::RegularBlob => {
                entry.mode == "100644" && entry.byte_length.is_some()
            }
            BoundaryGitEntryKind::ExecutableBlob => {
                entry.mode == "100755" && entry.byte_length.is_some()
            }
            BoundaryGitEntryKind::SymbolicLink => {
                entry.mode == "120000" && entry.byte_length.is_some()
            }
            BoundaryGitEntryKind::Gitlink => entry.mode == "160000" && entry.byte_length.is_none(),
        };
        if !valid_shape {
            return Err(invalid(
                "intentional-boundary Git inventory entry shape changed",
            ));
        }
    }
    if inventory.inventory_sha256 != compute_inventory_sha256(inventory).map_err(invalid)? {
        return Err(invalid(
            "intentional-boundary Git inventory commitment changed",
        ));
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryInventoryError {
    IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
