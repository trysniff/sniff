use super::{SandboxCommand, SandboxError, normalize_windows_path};
use std::path::{Path, PathBuf};

struct FileAlias {
    original: String,
    canonical: PathBuf,
    replacement: String,
}

pub(super) fn canonicalize_file_aliases(spec: &mut SandboxCommand) -> Result<(), SandboxError> {
    let mut aliases = Vec::new();
    for path in &spec.executable_paths {
        let canonical = canonicalize(path)?;
        let metadata = std::fs::metadata(&canonical).map_err(|error| {
            SandboxError::Invalid(format!(
                "inspect executable {} failed: {error}",
                path.display()
            ))
        })?;
        // This file-token rewrite does not alter directory-grant mapping semantics.
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            return Err(SandboxError::Invalid(format!(
                "sandbox executable is not a regular file: {}",
                path.display()
            )));
        }
        let original = path.to_str().ok_or_else(|| {
            SandboxError::Invalid("executable alias is not valid Unicode".to_string())
        })?;
        let replacement = canonical
            .to_str()
            .ok_or_else(|| {
                SandboxError::Invalid("canonical executable is not valid Unicode".to_string())
            })?
            .to_string();
        aliases.push(FileAlias {
            original: fold_path(original),
            canonical,
            replacement,
        });
    }
    aliases.sort_by_key(|alias| std::cmp::Reverse(alias.original.len()));
    spec.program = rewrite(&spec.program, &aliases, true)?;
    for argument in &mut spec.args {
        *argument = rewrite(argument, &aliases, false)?;
    }
    for (name, value) in &mut spec.env {
        if !name.eq_ignore_ascii_case("LOCALAPPDATA") {
            *value = rewrite(value, &aliases, false)?;
        }
    }
    Ok(())
}

fn canonicalize(path: &Path) -> Result<PathBuf, SandboxError> {
    std::fs::canonicalize(path)
        .map(normalize_windows_path)
        .map_err(|error| {
            SandboxError::Invalid(format!(
                "resolve executable alias {} failed: {error}",
                path.display()
            ))
        })
}

fn fold_path(value: &str) -> String {
    value.to_ascii_lowercase().replace('/', "\\")
}

fn delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'\"' | b'\'' | b';' | b'=' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
        )
}

fn rewrite(
    value: &str,
    aliases: &[FileAlias],
    structured_program: bool,
) -> Result<String, SandboxError> {
    let folded = fold_path(value);
    let mut result = String::with_capacity(value.len());
    let mut cursor = 0;
    let mut copied = 0;
    // Only consume the original input. A replacement must never become another alias.
    while cursor < value.len() {
        let alias = aliases.iter().find(|alias| {
            (!structured_program || (cursor == 0 && alias.original.len() == value.len()))
                && folded[cursor..].starts_with(&alias.original)
                && (cursor == 0 || delimiter(value.as_bytes()[cursor - 1]))
                && value
                    .as_bytes()
                    .get(cursor + alias.original.len())
                    .is_none_or(|byte| delimiter(*byte))
        });
        if let Some(alias) = alias {
            let end = cursor + alias.original.len();
            let spelling = &value[cursor..end];
            // Args/env can be consumed by a shell even when the whole value is a path.
            // Reject ambiguous escaping before profile/ACL creation, not after launch.
            if !structured_program
                && fold_path(spelling) != fold_path(&alias.replacement)
                && !alias.replacement.chars().all(|character| {
                    character.is_alphanumeric()
                        || matches!(character, ':' | '\\' | '/' | '_' | '-' | '.')
                })
            {
                return Err(SandboxError::Invalid(format!(
                    "executable alias requires unsupported command-string escaping: {spelling}"
                )));
            }
            if canonicalize(Path::new(spelling))? != alias.canonical {
                return Err(SandboxError::Invalid(format!(
                    "executable alias changed its physical target: {spelling}"
                )));
            }
            result.push_str(&value[copied..cursor]);
            result.push_str(&alias.replacement);
            cursor = end;
            copied = end;
        } else {
            cursor += value[cursor..]
                .chars()
                .next()
                .expect("nonempty suffix")
                .len_utf8();
        }
    }
    result.push_str(&value[copied..]);
    Ok(result)
}

#[cfg(test)]
#[path = "sandbox_windows_executable_aliases_tests.rs"]
mod tests;
