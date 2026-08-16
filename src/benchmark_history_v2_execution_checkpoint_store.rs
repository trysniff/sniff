use super::{
    HistoricalV2ExecutionCheckpoint, HistoricalV2IdenticalTestExecution,
    HistoricalV2IdenticalTestPlan,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_CONTRACT: &str = "sniffbench-historical-v2-execution-transaction-v1";
const TRANSACTION_FILE: &str = "_transaction.json";
const PLAN_FILE: &str = "plan.json";
const EXECUTION_FILE: &str = "execution.json";
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PLAN_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EXECUTION_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedFile {
    name: String,
    sha256: String,
    byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionTransaction {
    schema_version: u32,
    transaction_contract: String,
    checkpoint: HistoricalV2ExecutionCheckpoint,
    files: Vec<CommittedFile>,
}

pub(super) struct StoredExecution {
    pub(super) checkpoint: HistoricalV2ExecutionCheckpoint,
    pub(super) plan: HistoricalV2IdenticalTestPlan,
    pub(super) execution: HistoricalV2IdenticalTestExecution,
}

pub(super) struct ExecutionSlotStore {
    language_root: PathBuf,
    staging_root: PathBuf,
    final_root: PathBuf,
    _lock: SlotFileLock,
}

impl ExecutionSlotStore {
    pub(super) fn open(root: &Path, language: &str, slot_number: usize) -> Result<Self, String> {
        validate_slot_path(language, slot_number)?;
        fs::create_dir_all(root)
            .map_err(|error| format!("failed to create historical-v2 state root: {error}"))?;
        let root = canonical_directory(root, "historical-v2 state root")?;
        let language_root = root.join(language);
        fs::create_dir_all(&language_root)
            .map_err(|error| format!("failed to create historical-v2 language state: {error}"))?;
        require_plain_directory(&language_root, "historical-v2 language state")?;
        let language_root = canonical_directory(&language_root, "historical-v2 language state")?;
        if language_root.parent() != Some(root.as_path()) {
            return Err("historical-v2 language state escaped its root".to_string());
        }
        let name = format!("slot-{slot_number:04}");
        let lock = SlotFileLock::acquire(&language_root.join(format!("{name}.lock")))?;
        let store = Self {
            staging_root: language_root.join(format!(".{name}.incomplete")),
            final_root: language_root.join(&name),
            language_root,
            _lock: lock,
        };
        store.remove_incomplete_transaction()?;
        Ok(store)
    }

    pub(super) fn load(&self) -> Result<Option<StoredExecution>, String> {
        if !self.final_root.exists() {
            return Ok(None);
        }
        require_plain_directory(&self.final_root, "historical-v2 execution transaction")?;
        let names = directory_names(&self.final_root)?;
        if names != [TRANSACTION_FILE, EXECUTION_FILE, PLAN_FILE] {
            return Err("historical-v2 execution transaction file set changed".to_string());
        }
        let transaction_bytes = read_limited(
            &self.final_root.join(TRANSACTION_FILE),
            MAX_TRANSACTION_BYTES,
            "execution transaction",
        )?;
        let transaction = serde_json::from_slice::<ExecutionTransaction>(&transaction_bytes)
            .map_err(|error| format!("invalid historical-v2 execution transaction: {error}"))?;
        if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
            || transaction.transaction_contract != TRANSACTION_CONTRACT
        {
            return Err("historical-v2 execution transaction contract changed".to_string());
        }
        let actual = committed_files(&self.final_root)?;
        if actual != transaction.files {
            return Err("historical-v2 execution transaction inventory changed".to_string());
        }
        let plan = serde_json::from_slice::<HistoricalV2IdenticalTestPlan>(&read_limited(
            &self.final_root.join(PLAN_FILE),
            MAX_PLAN_BYTES,
            "execution plan",
        )?)
        .map_err(|error| format!("invalid historical-v2 checkpoint plan: {error}"))?;
        let execution =
            serde_json::from_slice::<HistoricalV2IdenticalTestExecution>(&read_limited(
                &self.final_root.join(EXECUTION_FILE),
                MAX_EXECUTION_BYTES,
                "execution evidence",
            )?)
            .map_err(|error| format!("invalid historical-v2 checkpoint execution: {error}"))?;
        Ok(Some(StoredExecution {
            checkpoint: transaction.checkpoint,
            plan,
            execution,
        }))
    }

    pub(super) fn publish(
        &self,
        checkpoint: &HistoricalV2ExecutionCheckpoint,
        plan: &HistoricalV2IdenticalTestPlan,
        execution: &HistoricalV2IdenticalTestExecution,
    ) -> Result<(), String> {
        if self.final_root.exists() || self.staging_root.exists() {
            return Err("historical-v2 execution transaction already exists".to_string());
        }
        fs::create_dir(&self.staging_root).map_err(|error| {
            format!("failed to create historical-v2 execution staging directory: {error}")
        })?;
        write_json_new(&self.staging_root.join(PLAN_FILE), plan, MAX_PLAN_BYTES)?;
        write_json_new(
            &self.staging_root.join(EXECUTION_FILE),
            execution,
            MAX_EXECUTION_BYTES,
        )?;
        let files = committed_files(&self.staging_root)?;
        let transaction = ExecutionTransaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            transaction_contract: TRANSACTION_CONTRACT.to_string(),
            checkpoint: checkpoint.clone(),
            files,
        };
        write_json_new(
            &self.staging_root.join(TRANSACTION_FILE),
            &transaction,
            MAX_TRANSACTION_BYTES,
        )?;
        sync_directory(&self.staging_root)?;
        fs::rename(&self.staging_root, &self.final_root).map_err(|error| {
            format!("failed to publish historical-v2 execution transaction: {error}")
        })?;
        sync_directory(&self.language_root)?;
        Ok(())
    }

    fn remove_incomplete_transaction(&self) -> Result<(), String> {
        if !self.staging_root.exists() {
            return Ok(());
        }
        require_plain_directory(
            &self.staging_root,
            "incomplete historical-v2 execution transaction",
        )?;
        fs::remove_dir_all(&self.staging_root).map_err(|error| {
            format!("failed to remove incomplete historical-v2 transaction: {error}")
        })?;
        sync_directory(&self.language_root)
    }
}

fn committed_files(root: &Path) -> Result<Vec<CommittedFile>, String> {
    let mut files = Vec::new();
    for (name, limit) in [
        (PLAN_FILE, MAX_PLAN_BYTES),
        (EXECUTION_FILE, MAX_EXECUTION_BYTES),
    ] {
        let path = root.join(name);
        let bytes = read_limited(&path, limit, name)?;
        files.push(CommittedFile {
            name: name.to_string(),
            sha256: sha256(&bytes),
            byte_count: u64::try_from(bytes.len())
                .map_err(|_| "historical-v2 artifact size overflowed".to_string())?,
        });
    }
    Ok(files)
}

fn directory_names(root: &Path) -> Result<Vec<&'static str>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v2 transaction: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("failed to inspect historical-v2 transaction: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("failed to inspect historical-v2 transaction: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("historical-v2 execution transaction contains a non-file".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "historical-v2 transaction filename is not UTF-8".to_string())?;
        let known = match name.as_str() {
            PLAN_FILE => PLAN_FILE,
            EXECUTION_FILE => EXECUTION_FILE,
            TRANSACTION_FILE => TRANSACTION_FILE,
            _ => return Err(format!("unexpected historical-v2 transaction file: {name}")),
        };
        names.push(known);
    }
    names.sort_unstable();
    Ok(names)
}

fn write_json_new<T: Serialize>(path: &Path, value: &T, limit: u64) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize historical-v2 transaction: {error}"))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!(
            "historical-v2 transaction file exceeds its limit: {}",
            path.display()
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

fn read_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect historical-v2 {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "historical-v2 {label} is unsafe or exceeds its size limit"
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("failed to read historical-v2 {label}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("historical-v2 {label} exceeds its size limit"));
    }
    Ok(bytes)
}

fn require_plain_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(format!("{label} is not a plain directory"))
    }
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path =
        fs::canonicalize(path).map_err(|error| format!("failed to resolve {label}: {error}"))?;
    require_plain_directory(&path, label)?;
    Ok(path)
}

fn validate_slot_path(language: &str, slot_number: usize) -> Result<(), String> {
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

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct SlotFileLock {
    file: File,
}

impl SlotFileLock {
    fn acquire(path: &Path) -> Result<Self, String> {
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
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("failed to sync historical-v2 transaction directory: {error}"))
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), String> {
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
