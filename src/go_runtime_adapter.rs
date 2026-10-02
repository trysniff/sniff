use crate::go_tool_stdio::strip_windows_verbatim_prefix;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[path = "go_runtime_adapter_build.rs"]
mod build;
#[path = "go_runtime_adapter_cache.rs"]
mod cache;
#[path = "go_runtime_adapter_security.rs"]
mod security;

const CONTRACT: &str = "sniff-windows-go-sdk-adapter-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    contract: String,
    platform: String,
    original_driver_sha256: String,
    sdk_sha256: String,
    recipe_sha256: String,
}

pub(crate) struct AdaptedGo {
    pub(crate) root: PathBuf,
    pub(crate) executable: PathBuf,
    pub(crate) record: PathBuf,
    pub(crate) guard: Vec<fs::File>,
}

pub(crate) fn discover_goroot(go: &Path, repository: &Path) -> Result<PathBuf, String> {
    let go = canonical(go)?;
    if go.starts_with(canonical(repository)?) {
        return Err(
            "selected Go driver must be outside the repository before SDK discovery".to_string(),
        );
    }
    let parent = go.parent().ok_or("selected Go executable has no parent")?;
    let mut command = Command::new(&go);
    command.current_dir(parent).args(["env", "GOROOT"]);
    build::control_environment(&mut command);
    if let Some(root) = std::env::var_os("GOROOT") {
        command.env("GOROOT", root);
    }
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        Duration::from_secs(30),
        64 * 1024,
    )
    .map_err(|error| format!("failed to discover selected Go SDK: {error}"))?;
    if output.timed_out
        || output.stdout_truncated
        || output.stderr_truncated
        || !output.status.success()
    {
        return Err(
            "selected Go SDK discovery did not return bounded successful output".to_string(),
        );
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("selected Go SDK path is not UTF-8: {error}"))?;
    let lines = text.lines().collect::<Vec<_>>();
    let [root] = lines.as_slice() else {
        return Err("selected Go SDK discovery must return one path".to_string());
    };
    if !Path::new(root).is_absolute() {
        return Err("selected Go SDK path must be absolute".to_string());
    }
    canonical(Path::new(root))
}

pub(crate) fn prepare(go: &Path, goroot: &Path, repository: &Path) -> Result<AdaptedGo, String> {
    prepare_at(
        go,
        goroot,
        repository,
        &crate::semantic_cache::cache_base_directory()?,
    )
}

fn prepare_at(
    go: &Path,
    goroot: &Path,
    repository: &Path,
    cache_base: &Path,
) -> Result<AdaptedGo, String> {
    let go = canonical(go)?;
    let goroot = canonical(goroot)?;
    let repository = canonical(repository)?;
    if go != canonical(&goroot.join("bin/go.exe"))?
        || goroot.starts_with(&repository)
        || repository.starts_with(&goroot)
        || goroot.parent().is_none()
    {
        return Err(
            "Go adapter requires the selected SDK's own driver outside the repository".to_string(),
        );
    }
    let namespace = cache::prepare_parent(cache_base, &repository, &goroot)?;
    let parent = &namespace.path;
    let binding = binding(&go, &goroot)?;
    let key = digest(&serde_json::to_vec(&binding).map_err(|error| error.to_string())?);
    let root = parent.join(key);
    match fs::symlink_metadata(&root) {
        Ok(_) => return cache::verify(&root, &binding),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to inspect Go adapter cache: {error}")),
    }
    let stage = tempfile::Builder::new()
        .prefix(".go-adapter-stage-")
        .tempdir_in(parent)
        .map_err(|error| format!("failed to create owned Go adapter stage: {error}"))?;
    let bin = stage.path().join("bin");
    fs::create_dir(&bin).map_err(|error| error.to_string())?;
    let output = build::driver(&go, &goroot, &bin.join("go.exe"), parent)?;
    if binding != self::binding(&go, &goroot)? {
        return Err("selected Go SDK changed during adapter production".to_string());
    }
    cache::seal(stage.path(), &binding, &output)?;
    match fs::rename(stage.path(), &root) {
        Ok(()) => {}
        // Another producer may atomically publish the same bound SDK while we build.
        Err(_) if root.exists() => return cache::verify(&root, &binding),
        Err(error) => return Err(format!("failed to publish Go adapter: {error}")),
    }
    cache::verify(&root, &binding)
}

fn binding(go: &Path, goroot: &Path) -> Result<Binding, String> {
    let recipe = concat!(
        include_str!("go_tool_stdio.rs"),
        include_str!("go_runtime_adapter.rs"),
        include_str!("go_runtime_adapter_build.rs"),
        include_str!("go_runtime_adapter_cache.rs"),
        include_str!("go_runtime_adapter_security.rs"),
    );
    Ok(Binding {
        contract: CONTRACT.to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        original_driver_sha256: cache::file_digest(go, 64 * 1024 * 1024)?,
        sdk_sha256: crate::semantic_indexer_runner::go_sdk_input_tree_sha256(goroot)?,
        recipe_sha256: digest(recipe.as_bytes()),
    })
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map(strip_windows_verbatim_prefix)
        .map_err(|error| {
            format!(
                "failed to resolve Go adapter path {}: {error}",
                path.display()
            )
        })
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "tests/go_runtime_adapter.rs"]
mod tests;
