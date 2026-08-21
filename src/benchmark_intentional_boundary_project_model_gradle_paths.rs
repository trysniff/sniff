use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) fn valid_gradle_project_path(path: &str) -> bool {
    path == ":"
        || path
            .strip_prefix(':')
            .is_some_and(|value| !value.is_empty() && value.split(':').all(valid_gradle_name))
}

fn valid_gradle_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| !character.is_control() && !matches!(character, ':' | '/' | '\\'))
}

pub(super) fn canonical_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map(strip_windows_verbatim_prefix)
        .map_err(|error| format!("failed to resolve {label}: {error}"))
}

pub(super) fn emitted_repository_root(
    settings_directory: &str,
    invocation_settings_repository_path: &str,
) -> Result<String, String> {
    let settings_directory = settings_directory.replace('\\', "/");
    let invocation_directory = invocation_settings_repository_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    if invocation_directory.is_empty() {
        let root = settings_directory.trim_end_matches('/');
        return (!root.is_empty())
            .then(|| root.to_string())
            .ok_or_else(|| "Gradle Tooling API emitted an invalid repository root".to_string());
    }
    let suffix = format!("/{invocation_directory}");
    if !path_ends_with(&settings_directory, &suffix) {
        return Err(
            "Gradle settings directory does not match the invocation settings file".to_string(),
        );
    }
    let root = settings_directory[..settings_directory.len() - suffix.len()].trim_end_matches('/');
    if root.is_empty() {
        return Err("Gradle Tooling API emitted an invalid repository root".to_string());
    }
    Ok(root.to_string())
}

pub(super) fn emitted_host_path(
    root: &Path,
    emitted_root: &str,
    raw: &str,
    label: &str,
    allow_root: bool,
) -> Result<PathBuf, String> {
    let raw = raw.replace('\\', "/");
    let emitted_root = emitted_root.trim_end_matches('/');
    let relative = if path_eq(&raw, emitted_root) {
        ""
    } else {
        let prefix = format!("{emitted_root}/");
        if !path_starts_with(&raw, &prefix) {
            return Err(format!("{label} is outside the emitted repository"));
        }
        &raw[prefix.len()..]
    };
    let relative_path = Path::new(relative);
    if (!allow_root && relative.is_empty())
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{label} is not safely repository-relative"));
    }
    let path = canonical_path(&root.join(relative_path), label)?;
    if !path.starts_with(root) {
        return Err(format!("{label} escaped the immutable repository"));
    }
    Ok(path)
}

pub(super) fn emitted_output_repository_path(
    root: &Path,
    emitted_root: &str,
    raw: &str,
    label: &str,
) -> Result<String, String> {
    let raw = raw.replace('\\', "/");
    let emitted_root = emitted_root.trim_end_matches('/');
    let prefix = format!("{emitted_root}/");
    let relative = if path_eq(&raw, emitted_root) {
        ""
    } else if path_starts_with(&raw, &prefix) {
        &raw[prefix.len()..]
    } else {
        return Err(format!("{label} is outside the emitted repository"));
    };
    let relative_path = Path::new(relative);
    if relative.is_empty()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{label} is not safely repository-relative"));
    }
    let mut existing = root.join(relative_path);
    let mut missing = Vec::new();
    while !existing.exists() {
        let name = existing
            .file_name()
            .ok_or_else(|| format!("{label} has no existing repository ancestor"))?;
        missing.push(name.to_os_string());
        if !existing.pop() {
            return Err(format!("{label} has no existing repository ancestor"));
        }
    }
    let mut resolved = canonical_path(&existing, label)?;
    if !resolved.starts_with(root) {
        return Err(format!("{label} escaped the immutable repository"));
    }
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    let relative = resolved
        .strip_prefix(root)
        .map_err(|_| format!("{label} is outside repository"))?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn path_eq(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn path_starts_with(path: &str, prefix: &str) -> bool {
    if cfg!(windows) {
        path.get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
    } else {
        path.starts_with(prefix)
    }
}

fn path_ends_with(path: &str, suffix: &str) -> bool {
    if cfg!(windows) {
        path.to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    } else {
        path.ends_with(suffix)
    }
}

pub(super) fn repository_path(root: &Path, raw: &Path) -> Result<String, String> {
    let path = canonical_path(raw, "Gradle project-model path")?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Gradle project-model path is outside repository".to_string())?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("Gradle project-model path is not safely repository-relative".to_string());
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return path;
        };
        match prefix.kind() {
            Prefix::VerbatimDisk(letter) => {
                let mut normalized = PathBuf::from(format!("{}:\\", letter as char));
                normalized.extend(
                    components.filter(|component| !matches!(component, Component::RootDir)),
                );
                normalized
            }
            _ => path,
        }
    }
    #[cfg(not(windows))]
    {
        path
    }
}
