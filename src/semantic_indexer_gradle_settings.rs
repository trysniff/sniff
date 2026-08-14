use super::fs_safety::{reject_link_or_reparse, reject_linked_path};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) fn discover_build_roots(repository: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let mut roots = BTreeSet::from([PathBuf::new()]);
    let mut pending = vec![PathBuf::new()];
    while let Some(relative_root) = pending.pop() {
        let absolute_root = repository.join(&relative_root);
        let settings = unique_settings_file(&absolute_root)?;
        let Some(settings) = settings else {
            continue;
        };
        let source = fs::read_to_string(&settings).map_err(|error| {
            format!(
                "failed to read Gradle settings file {}: {error}",
                settings.display()
            )
        })?;
        for literal in include_build_literals(&source, &settings)? {
            let child = safe_relative_build_path(&literal, &settings)?;
            let relative = relative_root.join(child);
            let absolute = repository.join(&relative);
            reject_linked_path(repository, &relative)?;
            let canonical = fs::canonicalize(&absolute).map_err(|error| {
                format!(
                    "Gradle includeBuild target {} is unavailable: {error}",
                    absolute.display()
                )
            })?;
            if !canonical.is_dir() || !canonical.starts_with(repository) {
                return Err(format!(
                    "Gradle includeBuild target must be a repository-local directory: {}",
                    absolute.display()
                ));
            }
            let canonical_relative = canonical.strip_prefix(repository).map_err(|_| {
                format!(
                    "Gradle includeBuild target escaped the repository: {}",
                    canonical.display()
                )
            })?;
            if roots.insert(canonical_relative.to_path_buf()) {
                pending.push(canonical_relative.to_path_buf());
            }
        }
    }
    Ok(roots)
}

fn unique_settings_file(root: &Path) -> Result<Option<PathBuf>, String> {
    let candidates = [
        root.join("settings.gradle.kts"),
        root.join("settings.gradle"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect::<Vec<_>>();
    match candidates.as_slice() {
        [] => Ok(None),
        [path] => {
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "failed to inspect Gradle settings {}: {error}",
                    path.display()
                )
            })?;
            reject_link_or_reparse(path, &metadata)?;
            if !metadata.is_file() {
                return Err(format!("Gradle settings is not a file: {}", path.display()));
            }
            Ok(Some(path.clone()))
        }
        _ => Err(format!(
            "Gradle build root {} contains both settings.gradle and settings.gradle.kts; refusing ambiguous dependency preparation",
            root.display()
        )),
    }
}

pub(super) fn include_build_literals(source: &str, path: &Path) -> Result<Vec<String>, String> {
    let bytes = source.as_bytes();
    let mut index = 0usize;
    let mut paths = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start = index;
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                if index + 1 >= bytes.len() {
                    return Err(format!(
                        "unterminated block comment in Gradle settings {} at byte {start}",
                        path.display()
                    ));
                }
                index += 2;
            }
            b'\'' | b'"' => skip_quoted(bytes, &mut index, path)?,
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if &source[start..index] != "includeBuild" {
                    continue;
                }
                skip_ascii_whitespace(bytes, &mut index);
                if bytes.get(index) == Some(&b'(') {
                    index += 1;
                    skip_ascii_whitespace(bytes, &mut index);
                }
                let quote = bytes
                    .get(index)
                    .copied()
                    .ok_or_else(|| format!("incomplete includeBuild call in {}", path.display()))?;
                if quote != b'\'' && quote != b'"' {
                    return Err(format!(
                        "dynamic includeBuild call in {} cannot be source-minimized safely",
                        path.display()
                    ));
                }
                index += 1;
                let literal_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    if bytes[index] == b'\\' || bytes[index] == b'$' {
                        return Err(format!(
                            "escaped or interpolated includeBuild path in {} cannot be verified",
                            path.display()
                        ));
                    }
                    index += 1;
                }
                if index >= bytes.len() {
                    return Err(format!(
                        "unterminated includeBuild path in {}",
                        path.display()
                    ));
                }
                paths.push(source[literal_start..index].to_string());
                index += 1;
            }
            _ => index += 1,
        }
    }
    Ok(paths)
}

fn skip_quoted(bytes: &[u8], index: &mut usize, path: &Path) -> Result<(), String> {
    let quote = bytes[*index];
    *index += 1;
    while *index < bytes.len() {
        if bytes[*index] == b'\\' {
            *index = (*index).saturating_add(2);
        } else if bytes[*index] == quote {
            *index += 1;
            return Ok(());
        } else {
            *index += 1;
        }
    }
    Err(format!(
        "unterminated string in Gradle settings {}",
        path.display()
    ))
}

fn skip_ascii_whitespace(bytes: &[u8], index: &mut usize) {
    while bytes.get(*index).is_some_and(u8::is_ascii_whitespace) {
        *index += 1;
    }
}

fn safe_relative_build_path(value: &str, settings: &Path) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "includeBuild path in {} must be a non-empty repository-relative child path: {value:?}",
            settings.display()
        ));
    }
    Ok(path.to_path_buf())
}
