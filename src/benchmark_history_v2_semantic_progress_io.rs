use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;

const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn ensure_plain_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "historical-v2 semantic progress path is not a plain directory: {}",
                path.display()
            ));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect historical-v2 semantic progress directory: {error}"
            ));
        }
    }
    fs::create_dir(path).map_err(|error| {
        format!(
            "failed to create historical-v2 semantic progress directory {}: {error}",
            path.display()
        )
    })
}

pub(super) fn remove_incomplete_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "historical-v2 semantic progress temporary entry is not a plain file: {}",
            path.display()
        )),
        Ok(_) => fs::remove_file(path).map_err(|error| {
            format!(
                "failed to remove interrupted historical-v2 semantic progress {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect historical-v2 semantic progress temporary entry: {error}"
        )),
    }
}

pub(super) fn read_checkpoint<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect historical-v2 {label}: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CHECKPOINT_BYTES
    {
        return Err(format!("historical-v2 {label} is not a bounded plain file"));
    }
    let file = File::open(path)
        .map_err(|error| format!("failed to read historical-v2 {label}: {error}"))?;
    serde_json::from_reader(BufReader::new(file))
        .map_err(|error| format!("invalid historical-v2 {label}: {error}"))
}

pub(super) fn write_json_atomic_new<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let temp = std::path::PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
    remove_incomplete_file(&temp)?;
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| {
            format!("failed to create historical-v2 semantic snapshot transaction: {error}")
        })?;
    let mut writer = BoundedWriter::new(BufWriter::new(file), MAX_CHECKPOINT_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        format!("failed to serialize historical-v2 semantic snapshot transaction: {error}")
    })?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .and_then(|()| writer.inner.get_ref().sync_all())
        .map_err(|error| {
            format!("failed to persist historical-v2 semantic snapshot transaction: {error}")
        })?;
    require_absent(path, "historical-v2 semantic snapshot destination")?;
    fs::rename(&temp, path).map_err(|error| {
        format!("failed to publish historical-v2 semantic snapshot checkpoint: {error}")
    })?;
    sync_directory(
        path.parent().ok_or_else(|| {
            "historical-v2 semantic snapshot checkpoint has no parent".to_string()
        })?,
    )
}

struct BoundedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
}

impl<W: Write> BoundedWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("semantic checkpoint length overflowed"))?;
        if self
            .written
            .checked_add(length)
            .is_none_or(|next| next > self.limit)
        {
            return Err(io::Error::other(
                "semantic checkpoint exceeds the size limit",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{label} already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to inspect {label}: {error}")),
    }
}

pub(super) fn require_entries(root: &Path, expected: &[&str], label: &str) -> Result<(), String> {
    let actual = entry_names(root, label)?;
    let expected = expected.iter().map(|value| value.to_string()).collect();
    if actual != expected {
        return Err(format!("{label} contains unexpected or missing entries"));
    }
    Ok(())
}

pub(super) fn require_allowed_entries(
    root: &Path,
    allowed: &[&str],
    label: &str,
) -> Result<(), String> {
    let actual = entry_names(root, label)?;
    let allowed = allowed
        .iter()
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>();
    if let Some(unexpected) = actual.difference(&allowed).next() {
        return Err(format!("{label} contains unexpected entry {unexpected}"));
    }
    Ok(())
}

fn entry_names(root: &Path, label: &str) -> Result<BTreeSet<String>, String> {
    fs::read_dir(root)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("failed to inspect {label}: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("failed to inspect {label} entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} contains a symlink"));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| format!("{label} contains a non-UTF-8 entry"))
        })
        .collect()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!("failed to synchronize historical-v2 semantic progress directory: {error}")
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_refuses_bytes_past_its_limit() {
        let mut writer = BoundedWriter::new(Vec::new(), 3);
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        assert_eq!(writer.inner, b"abc");
    }
}
