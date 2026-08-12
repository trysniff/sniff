use super::{SandboxError, drive, revoke_acl, wide_null};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;

const LEDGER_FILE: &str = "sandbox-recovery.jsonl";
const HRESULT_FILE_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;
const HRESULT_NOT_FOUND: i32 = 0x8007_0490_u32 as i32;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum RecoveryEvent {
    Begin { profile_name: String },
    Sid { sid: String },
    Acl { path: PathBuf },
    Mapping { drive: String, root: PathBuf },
}

#[derive(Default)]
struct RecoveryState {
    profile_name: Option<String>,
    sid: Option<String>,
    acl_paths: Vec<PathBuf>,
    mappings: Vec<(String, PathBuf)>,
}

pub(super) struct RecoveryLedger {
    path: PathBuf,
}

impl RecoveryLedger {
    pub(super) fn recover_and_begin(profile_name: &str) -> Result<Self, SandboxError> {
        let path = ledger_path()?;
        recover(&path)?;
        let ledger = Self { path };
        ledger.append(&RecoveryEvent::Begin {
            profile_name: profile_name.to_string(),
        })?;
        Ok(ledger)
    }

    pub(super) fn record_sid(&self, sid: &str) -> Result<(), SandboxError> {
        self.append(&RecoveryEvent::Sid {
            sid: sid.to_string(),
        })
    }

    pub(super) fn record_acl(&self, path: &Path) -> Result<(), SandboxError> {
        self.append(&RecoveryEvent::Acl {
            path: path.to_path_buf(),
        })
    }

    pub(super) fn record_mapping(&self, drive: &str, root: &Path) -> Result<(), SandboxError> {
        self.append(&RecoveryEvent::Mapping {
            drive: drive.to_string(),
            root: root.to_path_buf(),
        })
    }

    pub(super) fn clear(self) -> Result<(), SandboxError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(SandboxError::Failed(format!(
                "remove Windows sandbox recovery ledger {} failed: {error}",
                self.path.display()
            ))),
        }
    }

    fn append(&self, event: &RecoveryEvent) -> Result<(), SandboxError> {
        let parent = self.path.parent().ok_or_else(|| {
            SandboxError::Failed("Windows sandbox recovery ledger has no parent".to_string())
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            SandboxError::Failed(format!(
                "create Windows sandbox recovery directory {} failed: {error}",
                parent.display()
            ))
        })?;
        let mut bytes = serde_json::to_vec(event).map_err(|error| {
            SandboxError::Failed(format!(
                "serialize Windows sandbox recovery event failed: {error}"
            ))
        })?;
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| {
                SandboxError::Failed(format!(
                    "open Windows sandbox recovery ledger {} failed: {error}",
                    self.path.display()
                ))
            })?;
        file.write_all(&bytes).map_err(|error| {
            SandboxError::Failed(format!(
                "write Windows sandbox recovery ledger {} failed: {error}",
                self.path.display()
            ))
        })?;
        file.sync_data().map_err(|error| {
            SandboxError::Failed(format!(
                "flush Windows sandbox recovery ledger {} failed: {error}",
                self.path.display()
            ))
        })
    }
}

fn recover(path: &Path) -> Result<(), SandboxError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(SandboxError::Failed(format!(
                "read Windows sandbox recovery ledger {} failed: {error}",
                path.display()
            )));
        }
    };
    let mut state = RecoveryState::default();
    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if complete_len == 0 {
        fs::remove_file(path).map_err(|error| {
            SandboxError::Failed(format!(
                "remove incomplete Windows sandbox recovery ledger {} failed: {error}",
                path.display()
            ))
        })?;
        return Ok(());
    }
    for (index, line) in bytes[..complete_len]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let event: RecoveryEvent = serde_json::from_slice(line).map_err(|error| {
            SandboxError::Failed(format!(
                "parse Windows sandbox recovery ledger {} line {} failed: {error}",
                path.display(),
                index + 1
            ))
        })?;
        match event {
            RecoveryEvent::Begin { profile_name } => {
                if state.profile_name.is_some() {
                    return Err(SandboxError::Failed(format!(
                        "Windows sandbox recovery ledger {} contains multiple runs",
                        path.display()
                    )));
                }
                state.profile_name = Some(profile_name);
            }
            RecoveryEvent::Sid { sid } => state.sid = Some(sid),
            RecoveryEvent::Acl { path } => state.acl_paths.push(path),
            RecoveryEvent::Mapping { drive, root } => state.mappings.push((drive, root)),
        }
    }
    if state.profile_name.is_none() {
        return Err(SandboxError::Failed(format!(
            "Windows sandbox recovery ledger {} is missing its run header",
            path.display()
        )));
    }
    for (drive_name, root) in state.mappings.iter().rev() {
        drive::recover_recorded_mapping(drive_name, root)?;
    }
    if !state.acl_paths.is_empty() && state.sid.is_none() {
        return Err(SandboxError::Failed(format!(
            "Windows sandbox recovery ledger {} records ACLs without a SID",
            path.display()
        )));
    }
    if let Some(sid) = state.sid {
        for acl_path in state.acl_paths.iter().rev() {
            if !acl_path.exists() {
                continue;
            }
            revoke_acl(acl_path, &sid).map_err(|error| {
                SandboxError::Failed(format!(
                    "recover Windows sandbox ACL for {} failed: {error}",
                    acl_path.display()
                ))
            })?;
        }
    }
    if let Some(profile_name) = state.profile_name {
        let deleted = unsafe { DeleteAppContainerProfile(wide_null(&profile_name).as_ptr()) };
        if deleted < 0 && !matches!(deleted, HRESULT_FILE_NOT_FOUND | HRESULT_NOT_FOUND) {
            return Err(SandboxError::Failed(format!(
                "recover Windows AppContainer profile {profile_name} failed with HRESULT 0x{:08x}",
                deleted as u32
            )));
        }
    }
    fs::remove_file(path).map_err(|error| {
        SandboxError::Failed(format!(
            "remove recovered Windows sandbox ledger {} failed: {error}",
            path.display()
        ))
    })
}

fn ledger_path() -> Result<PathBuf, SandboxError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        SandboxError::Unavailable(
            "Windows sandbox recovery requires LOCALAPPDATA to be defined".to_string(),
        )
    })?;
    Ok(PathBuf::from(local_app_data)
        .join("Sniff")
        .join(LEDGER_FILE))
}

#[cfg(test)]
mod tests {
    use super::{RecoveryEvent, recover};
    use std::io::Write;

    #[test]
    fn recovery_tolerates_only_a_truncated_final_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        serde_json::to_writer(
            &mut file,
            &RecoveryEvent::Begin {
                profile_name: "SniffSandbox-recovery-test".to_string(),
            },
        )
        .unwrap();
        file.write_all(b"\n{\"event\":\"acl\",\"path\":").unwrap();
        drop(file);

        recover(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn recovery_discards_a_truncated_header_before_any_host_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.jsonl");
        std::fs::write(&path, b"{\"event\":\"begin\"").unwrap();

        recover(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn recovery_rejects_a_malformed_complete_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.jsonl");
        std::fs::write(&path, b"{not-json}\n").unwrap();

        let error = recover(&path).unwrap_err();

        assert!(error.to_string().contains("line 1"));
        assert!(path.exists());
    }
}
