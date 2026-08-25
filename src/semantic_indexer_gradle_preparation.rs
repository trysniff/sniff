#[path = "semantic_indexer_gradle_cache.rs"]
mod cache;
#[path = "semantic_indexer_gradle_control_plane.rs"]
mod control_plane;
#[path = "semantic_indexer_gradle_fs_safety.rs"]
mod fs_safety;
#[path = "semantic_indexer_gradle_settings.rs"]
mod settings;

pub(super) use control_plane::KotlinDependencyPreparationError;

pub(super) fn stage_control_plane(
    repository: &std::path::Path,
    target: &std::path::Path,
) -> Result<(), KotlinDependencyPreparationError> {
    control_plane::stage_control_plane(repository, target)
}

pub(super) fn transfer_cache(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), String> {
    cache::transfer_cache(source, destination)
}

#[cfg(test)]
#[path = "tests/semantic_indexer_gradle_preparation.rs"]
mod tests;
