use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

pub(super) fn write_json_new<T: Serialize>(
    path: &Path,
    value: &T,
    limit: u64,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize historical-v2 transaction: {error}"))?;
    write_json_bytes_new(path, bytes, limit)
}

pub(super) fn write_compact_json_new<T: Serialize>(
    path: &Path,
    value: &T,
    limit: u64,
) -> Result<(), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create historical-v2 artifact file: {error}"))?;
    let mut writer = BoundedJsonWriter::new(file, limit);
    let result = serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("failed to serialize historical-v2 artifact: {error}"))
        .and_then(|_| {
            writer
                .write_all(b"\n")
                .map_err(|error| format!("failed to persist historical-v2 artifact file: {error}"))
        })
        .and_then(|_| writer.finish(path));
    if result.is_err() {
        drop(writer);
        let _ = fs::remove_file(path);
    }
    result
}

struct BoundedJsonWriter<W> {
    inner: W,
    limit: u64,
    observed: u64,
    exceeded: bool,
}

impl<W> BoundedJsonWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            observed: 0,
            exceeded: false,
        }
    }
}

impl BoundedJsonWriter<File> {
    fn finish(&mut self, path: &Path) -> Result<(), String> {
        if self.exceeded {
            return Err(format!(
                "historical-v2 artifact file exceeds its limit: {} bytes observed, {} bytes allowed: {}",
                self.observed,
                self.limit,
                path.display(),
            ));
        }
        self.inner
            .flush()
            .and_then(|_| self.inner.sync_all())
            .map_err(|error| format!("failed to persist historical-v2 artifact file: {error}"))
    }
}

impl Write for BoundedJsonWriter<File> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.observed = self.observed.saturating_add(byte_count);
        if self.exceeded || self.observed > self.limit {
            self.exceeded = true;
            return Ok(bytes.len());
        }
        self.inner.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn write_json_bytes_new(path: &Path, mut bytes: Vec<u8>, limit: u64) -> Result<(), String> {
    bytes.push(b'\n');
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed > limit {
        return Err(format!(
            "historical-v2 transaction file exceeds its limit: {} bytes observed, {} bytes allowed: {}",
            observed,
            limit,
            path.display(),
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create historical-v2 transaction file: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 transaction file: {error}"))
}

pub(super) fn read_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let (file, length) = open_limited_file(path, limit, label)?;
    let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read historical-v2 {label}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("historical-v2 {label} exceeds its size limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn read_json_limited<T: DeserializeOwned>(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<T, String> {
    let (file, _) = open_limited_file(path, limit, label)?;
    serde_json::from_reader(BufReader::new(file))
        .map_err(|error| format!("invalid historical-v2 {label}: {error}"))
}

pub(super) fn read_committed_json_limited<T: DeserializeOwned>(
    path: &Path,
    limit: u64,
    label: &str,
    expected_byte_count: u64,
    expected_sha256: &str,
) -> Result<T, String> {
    let (file, length) = open_limited_file(path, limit, label)?;
    if length != expected_byte_count {
        return Err(format!("historical-v2 {label} commitment changed"));
    }
    let mut reader = BufReader::new(HashingReader::new(file));
    let value = serde_json::from_reader(&mut reader)
        .map_err(|error| format!("invalid historical-v2 {label}: {error}"))?;
    let reader = reader.into_inner();
    if reader.byte_count != expected_byte_count
        || format!("{:x}", reader.hasher.finalize()) != expected_sha256
    {
        return Err(format!("historical-v2 {label} commitment changed"));
    }
    Ok(value)
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    byte_count: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            byte_count: 0,
        }
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.byte_count = self
            .byte_count
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

fn open_limited_file(path: &Path, limit: u64, label: &str) -> Result<(File, u64), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect historical-v2 {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "historical-v2 {label} is unsafe or exceeds its size limit"
        ));
    }
    let file = File::open(path)
        .map_err(|error| format!("failed to read historical-v2 {label}: {error}"))?;
    Ok((file, metadata.len()))
}

pub(super) fn require_plain_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(format!("{label} is not a plain directory"))
    }
}

pub(super) fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path =
        fs::canonicalize(path).map_err(|error| format!("failed to resolve {label}: {error}"))?;
    require_plain_directory(&path, label)?;
    Ok(path)
}

pub(super) fn validate_slot_path(language: &str, slot_number: usize) -> Result<(), String> {
    if slot_number == 0
        || language.is_empty()
        || !language
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        Err("historical-v2 checkpoint slot path is invalid".to_string())
    } else {
        Ok(())
    }
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_json_can_fit_without_removing_the_hard_bound() {
        let root = tempfile::tempdir().unwrap();
        let value = json!([
            {"method": "first", "status": "resolved"},
            {"method": "second", "status": "resolved"}
        ]);
        let compact_len = serde_json::to_vec(&value).unwrap().len() as u64 + 1;
        let pretty_len = serde_json::to_vec_pretty(&value).unwrap().len() as u64 + 1;
        assert!(compact_len < pretty_len);

        let compact = root.path().join("compact.json");
        write_compact_json_new(&compact, &value, compact_len).unwrap();
        let mut expected = serde_json::to_vec(&value).unwrap();
        expected.push(b'\n');
        assert_eq!(fs::read(compact).unwrap(), expected);

        let pretty = root.path().join("pretty.json");
        let error = write_json_new(&pretty, &value, compact_len).unwrap_err();
        assert!(error.contains(&format!("{pretty_len} bytes observed")));
        assert!(error.contains(&format!("{compact_len} bytes allowed")));
        assert!(!pretty.exists());
    }

    #[test]
    fn compact_json_stream_removes_partial_file_after_crossing_bound() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("bounded.json");
        let value = json!({"payload": "x".repeat(256)});
        let observed = serde_json::to_vec(&value).unwrap().len() as u64 + 1;

        let error = write_compact_json_new(&path, &value, 32).unwrap_err();

        assert!(error.contains(&format!("{observed} bytes observed")));
        assert!(error.contains("32 bytes allowed"));
        assert!(!path.exists());
    }

    #[test]
    fn bounded_json_reader_rejects_invalid_json_without_materializing_a_value() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("invalid.json");
        fs::write(&path, b"{\"unfinished\":\n").unwrap();

        let error = read_json_limited::<serde::de::IgnoredAny>(&path, 1024, "fixture").unwrap_err();

        assert!(error.contains("invalid historical-v2 fixture"));
    }

    #[test]
    fn committed_json_reader_hashes_the_bytes_it_deserializes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("committed.json");
        let bytes = b"{\"value\":1}\n";
        fs::write(&path, bytes).unwrap();

        let value = read_committed_json_limited::<serde_json::Value>(
            &path,
            1024,
            "fixture",
            bytes.len() as u64,
            &sha256(bytes),
        )
        .unwrap();
        assert_eq!(value, json!({"value": 1}));

        fs::write(&path, b"{\"value\":2}\n").unwrap();
        let error = read_committed_json_limited::<serde_json::Value>(
            &path,
            1024,
            "fixture",
            bytes.len() as u64,
            &sha256(bytes),
        )
        .unwrap_err();
        assert!(error.contains("commitment changed"));
    }
}

#[derive(Debug)]
pub(super) struct SlotFileLock {
    file: File,
}

impl SlotFileLock {
    pub(super) fn acquire(path: &Path) -> Result<Self, String> {
        if path.exists() {
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| format!("failed to inspect historical-v2 slot lock: {error}"))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("historical-v2 slot lock is not a plain file".to_string());
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|error| format!("failed to open historical-v2 slot lock: {error}"))?;
        lock_file(&file)?;
        Ok(Self { file })
    }
}

impl Drop for SlotFileLock {
    fn drop(&mut self) {
        unlock_file(&self.file);
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "historical-v2 slot is already active or cannot be locked: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) {
    use std::os::fd::AsRawFd;
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

#[cfg(windows)]
fn lock_file(file: &File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    let locked = unsafe {
        windows_sys::Win32::Storage::FileSystem::LockFile(file.as_raw_handle() as _, 0, 0, 1, 0)
    };
    if locked != 0 {
        Ok(())
    } else {
        Err(format!(
            "historical-v2 slot is already active or cannot be locked: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        windows_sys::Win32::Storage::FileSystem::UnlockFile(file.as_raw_handle() as _, 0, 0, 1, 0);
    }
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("failed to sync historical-v2 transaction directory: {error}"))
}

#[cfg(windows)]
pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("failed to sync historical-v2 transaction directory: {error}"))
}
