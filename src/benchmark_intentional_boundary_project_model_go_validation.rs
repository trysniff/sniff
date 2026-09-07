use super::*;

pub fn validate_intentional_boundary_go_list(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_manifest_repository_path: &str,
    toolchain_identity_sha256: &str,
    variant: IntentionalBoundaryProjectModelVariant,
    stdout: &[u8],
    census: &IntentionalBoundaryProjectModelCensus,
) -> Result<(), String> {
    let expected = parse_intentional_boundary_go_list(
        root,
        inventory,
        invocation_manifest_repository_path,
        toolchain_identity_sha256,
        variant,
        stdout,
    )?;
    if census != &expected {
        return Err("intentional-boundary Go project model changed".to_string());
    }
    Ok(())
}
