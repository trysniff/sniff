use super::*;

pub fn validate_intentional_boundary_gradle_tooling_model(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_settings_repository_path: &str,
    toolchain_identity_sha256: &str,
    stdout: &[u8],
    census: &IntentionalBoundaryProjectModelCensus,
) -> Result<(), String> {
    let expected = parse_intentional_boundary_gradle_tooling_model(
        root,
        inventory,
        invocation_settings_repository_path,
        toolchain_identity_sha256,
        stdout,
    )?;
    if census != &expected {
        return Err("intentional-boundary Gradle project model changed".to_string());
    }
    Ok(())
}
