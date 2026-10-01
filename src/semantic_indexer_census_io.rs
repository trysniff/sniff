use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    sha256: String,
    value: T,
}

pub(super) fn hash<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit compiler census receipt: {error}"))
}

pub(super) fn ensure_plain_directory(path: &Path) -> Result<(), String> {
    let created = !path.exists();
    if created {
        fs::create_dir(path)
            .map_err(|error| format!("failed to create compiler census directory: {error}"))?;
    }
    require_plain(path, true)?;
    let expected = super::super::strip_windows_verbatim_prefix(path.to_path_buf());
    let actual = super::super::strip_windows_verbatim_prefix(
        fs::canonicalize(path).map_err(|error| error.to_string())?,
    );
    if actual != expected {
        return Err("compiler census directory has redirected ancestry".to_string());
    }
    if created {
        sync_directory(path)?;
        sync_directory(
            path.parent()
                .ok_or("compiler census directory has no parent")?,
        )?;
    }
    Ok(())
}

fn require_plain(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect compiler census path: {error}"))?;
    let redirected = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let redirected = {
        use std::os::windows::fs::MetadataExt;
        redirected || metadata.file_attributes() & 0x400 != 0
    };
    if redirected
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.len() > MAX_BYTES))
    {
        return Err("compiler census path is not a bounded plain entry".to_string());
    }
    Ok(())
}

pub(super) fn write<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<String, String> {
    ensure_plain_directory(root)?;
    let sha256 = hash(value)?;
    let bytes = serde_json::to_vec(&Envelope {
        sha256: sha256.clone(),
        value,
    })
    .map_err(|error| format!("failed to serialize compiler census receipt: {error}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("compiler census receipt exceeds its bounded file limit".to_string());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(root)
        .map_err(|error| format!("failed to stage compiler census receipt: {error}"))?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("failed to persist compiler census receipt: {error}"))?;
    temporary
        .persist_noclobber(root.join(name))
        .map_err(|error| {
            format!("failed to publish compiler census receipt without replacement: {error}")
        })?;
    sync_directory(root)?;
    Ok(sha256)
}

pub(super) fn read<T: for<'de> Deserialize<'de> + Serialize>(
    path: &Path,
    expected: &str,
) -> Result<T, String> {
    require_plain(path, false)?;
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("compiler census receipt grew beyond its file limit".to_string());
    }
    let envelope: Envelope<T> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid compiler census receipt: {error}"))?;
    if envelope.sha256 != expected || hash(&envelope.value)? != expected {
        return Err("compiler census receipt commitment changed".to_string());
    }
    Ok(envelope.value)
}

pub(super) fn open_attempt(
    root: &Path,
    repository_sha256: &str,
    family: &str,
) -> Result<PathBuf, String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let root = super::super::strip_windows_verbatim_prefix(root);
    let mut parent = root;
    for component in [".sniff", "compiler-census", repository_sha256, family] {
        parent = parent.join(component);
        ensure_plain_directory(&parent)?;
    }
    let attempt = tempfile::Builder::new()
        .prefix("attempt-")
        .tempdir_in(&parent)
        .map_err(|error| format!("failed to create compiler census attempt: {error}"))?
        .keep();
    ensure_plain_directory(&attempt)?;
    sync_directory(&attempt)?;
    sync_directory(&parent)?;
    Ok(attempt)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to synchronize compiler census directory: {error}"))
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to synchronize compiler census directory: {error}"))
}
