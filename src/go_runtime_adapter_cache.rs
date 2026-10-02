use super::{AdaptedGo, Binding, canonical, digest};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const RECORD: &str = "adapter.json";

pub(super) struct Namespace {
    pub(super) path: std::path::PathBuf,
    pub(super) _guard: Vec<fs::File>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    input: Binding,
    executable_sha256: String,
    build_stdout_sha256: String,
    build_stderr_sha256: String,
}

pub(super) fn prepare_parent(
    base: &Path,
    repository: &Path,
    sdk: &Path,
) -> Result<Namespace, String> {
    if !base.is_absolute() {
        return Err("Go adapter cache must be absolute".to_string());
    }
    let base = destination(base)?;
    let parent = base.join("go-runtime-adapters-v1");
    if base.starts_with(repository)
        || base.starts_with(sdk)
        || repository.starts_with(&parent)
        || sdk.starts_with(&parent)
    {
        return Err("Go adapter cache must be outside repository and selected SDK".to_string());
    }
    let mut guard = super::security::lock_base(&base, true)?;
    super::security::create_namespace(&parent)?;
    guard.push(super::security::hold_trusted(&parent, true, true)?);
    Ok(Namespace {
        path: parent,
        _guard: guard,
    })
}

pub(super) fn seal(
    root: &Path,
    binding: &Binding,
    output: &crate::bounded_process::BoundedOutput,
) -> Result<(), String> {
    let record = Record {
        schema_version: 1,
        input: binding.clone(),
        executable_sha256: file_digest(&root.join("bin/go.exe"), 64 * 1024 * 1024)?,
        build_stdout_sha256: output.stdout_sha256.clone(),
        build_stderr_sha256: output.stderr_sha256.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join(RECORD))
        .map_err(|error| format!("failed to create Go adapter record: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to commit Go adapter record: {error}"))
}

pub(super) fn verify(root: &Path, expected: &Binding) -> Result<AdaptedGo, String> {
    let namespace = root.parent().ok_or("Go adapter cache has no namespace")?;
    let base = namespace
        .parent()
        .ok_or("Go adapter namespace has no cache base")?;
    let mut guard = super::security::lock_base(base, false)?;
    guard.push(super::security::hold_trusted(namespace, true, true)?);
    guard.push(super::security::hold_trusted(root, true, false)?);
    guard.push(super::security::hold_trusted(
        &root.join("bin"),
        true,
        false,
    )?);
    exact_entries(root, &["adapter.json", "bin"])?;
    exact_entries(&root.join("bin"), &["go.exe"])?;
    let record_path = root.join(RECORD);
    guard.push(super::security::hold_trusted(&record_path, false, false)?);
    let record: Record = serde_json::from_slice(&read_plain(&record_path, 64 * 1024)?)
        .map_err(|error| format!("invalid Go adapter record: {error}"))?;
    let executable = root.join("bin/go.exe");
    guard.push(super::security::hold_trusted(&executable, false, false)?);
    if record.schema_version != 1
        || &record.input != expected
        || !valid_digest(&record.build_stdout_sha256)
        || !valid_digest(&record.build_stderr_sha256)
        || record.executable_sha256 != file_digest(&executable, 64 * 1024 * 1024)?
    {
        return Err("Go adapter cache binding or executable checksum mismatch; remove corrupt adapter explicitly".to_string());
    }
    Ok(AdaptedGo {
        root: root.to_path_buf(),
        executable,
        record: record_path,
        guard,
    })
}

pub(super) fn file_digest(path: &Path, limit: u64) -> Result<String, String> {
    Ok(digest(&read_plain(path, limit)?))
}

fn read_plain(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
        .map_err(|error| {
            format!(
                "failed to open Go adapter input {}: {error}",
                path.display()
            )
        })?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 || metadata.len() > limit {
        return Err("Go adapter input is not a plain bounded file".to_string());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Go adapter input exceeds its read limit".to_string());
    }
    Ok(bytes)
}

fn exact_entries(root: &Path, expected: &[&str]) -> Result<(), String> {
    plain(root, true)?;
    let entries = fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .take(expected.len() + 1)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(|error| error.to_string())?;
    let expected = expected
        .iter()
        .map(|name| std::ffi::OsString::from(*name))
        .collect();
    if entries != expected {
        return Err("Go adapter cache contains missing or unexpected entries".to_string());
    }
    Ok(())
}

fn destination(path: &Path) -> Result<std::path::PathBuf, String> {
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("Go adapter cache path must not contain parent traversal".to_string());
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    ancestor
                        .file_name()
                        .ok_or("Go adapter cache has no existing ancestor")?,
                );
                ancestor = ancestor
                    .parent()
                    .ok_or("Go adapter cache has no existing ancestor")?;
            }
            Err(error) => {
                return Err(format!(
                    "failed to inspect Go adapter cache ancestor: {error}"
                ));
            }
        }
    }
    let mut resolved = canonical(ancestor)?;
    for name in suffix.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn plain(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x400 != 0
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err("Go adapter cache requires plain files/directories".to_string());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
