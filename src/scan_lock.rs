#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

#[cfg(unix)]
use std::fs::File;

pub(crate) struct RepositoryScanLock {
    _locks: Vec<NamedLock>,
    _reservation: InProcessReservation,
}

struct InProcessReservation {
    identities: Vec<String>,
}

struct NamedLock {
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

impl RepositoryScanLock {
    pub(crate) fn acquire(repository_root: &Path, report_path: &Path) -> Result<Self, String> {
        let repository = fs::canonicalize(repository_root)
            .map_err(|error| format!("failed to resolve scan repository: {error}"))?;
        if !repository.is_dir() {
            return Err("scan repository root is not a directory".to_string());
        }
        let report_parent = report_path
            .parent()
            .ok_or_else(|| "scan report has no parent directory".to_string())?;
        let report_parent = fs::canonicalize(report_parent)
            .map_err(|error| format!("failed to resolve scan report directory: {error}"))?;
        let report_name = report_path
            .file_name()
            .ok_or_else(|| "scan report has no filename".to_string())?;
        let report = report_parent.join(report_name);

        let mut resources = [
            (resource_identity("repository", &repository)?, repository),
            (resource_identity("report", &report)?, report_parent),
        ];
        resources.sort_by(|left, right| left.0.cmp(&right.0));
        let identities = resources
            .iter()
            .map(|(identity, _)| identity.clone())
            .collect::<Vec<_>>();
        let reservation = InProcessReservation::acquire(&identities)?;
        let mut locks = Vec::with_capacity(resources.len());
        #[cfg(unix)]
        let mut locked_directories = HashSet::new();
        for (identity, lock_dir) in resources {
            #[cfg(unix)]
            let _ = identity;
            #[cfg(unix)]
            if locked_directories.insert(lock_dir.clone()) {
                locks.push(NamedLock::acquire(&lock_dir)?);
            }
            #[cfg(windows)]
            {
                let _ = lock_dir;
                let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
                locks.push(NamedLock::acquire(&digest)?);
            }
        }
        Ok(Self {
            _locks: locks,
            _reservation: reservation,
        })
    }
}

fn active_identities() -> &'static Mutex<HashSet<String>> {
    static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashSet::new()))
}

impl InProcessReservation {
    fn acquire(identities: &[String]) -> Result<Self, String> {
        let mut active = active_identities()
            .lock()
            .map_err(|_| "Sniff scan lock state is poisoned".to_string())?;
        if identities.iter().any(|identity| active.contains(identity)) {
            return Err("another Sniff scan is active for this repository or report".to_string());
        }
        for identity in identities {
            active.insert(identity.clone());
        }
        Ok(Self {
            identities: identities.to_vec(),
        })
    }
}

impl Drop for InProcessReservation {
    fn drop(&mut self) {
        if let Ok(mut active) = active_identities().lock() {
            for identity in &self.identities {
                active.remove(identity);
            }
        }
    }
}

fn resource_identity(kind: &str, path: &Path) -> Result<String, String> {
    let path = path
        .to_str()
        .ok_or_else(|| "scan lock path is not valid Unicode".to_string())?
        .replace('\\', "/");
    #[cfg(windows)]
    let path = path.to_lowercase();
    Ok(format!("{kind}:{path}"))
}

#[cfg(unix)]
impl NamedLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let file = File::open(path)
            .map_err(|error| format!("failed to open Sniff scan lock directory: {error}"))?;
        if !file
            .metadata()
            .map_err(|error| format!("failed to inspect Sniff scan lock directory: {error}"))?
            .is_dir()
        {
            return Err("Sniff scan lock target is not a directory".to_string());
        }
        lock_file(&file)?;
        Ok(Self { file })
    }
}

#[cfg(windows)]
impl NamedLock {
    fn acquire(digest: &str) -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{
            CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let name = format!("Global\\SniffScan-{digest}\0")
            .encode_utf16()
            .collect::<Vec<_>>();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "failed to create Sniff scan mutex: {}",
                std::io::Error::last_os_error()
            ));
        }
        let outcome = unsafe { WaitForSingleObject(handle, 0) };
        if outcome == WAIT_OBJECT_0 || outcome == WAIT_ABANDONED {
            return Ok(Self { handle });
        }
        unsafe {
            CloseHandle(handle);
        }
        if outcome == WAIT_TIMEOUT {
            Err("another Sniff scan is active for this repository or report".to_string())
        } else {
            Err(format!(
                "failed to wait for Sniff scan mutex: {}",
                std::io::Error::last_os_error()
            ))
        }
    }
}

impl Drop for NamedLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unlock_file(&self.file);
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::ReleaseMutex;
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "another Sniff scan is active for this repository or report: {}",
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

#[cfg(test)]
mod tests {
    use super::RepositoryScanLock;
    use std::fs;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn rejects_another_scan_of_the_same_repository() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        let report = repository.join("sniff-report.md");
        let first = RepositoryScanLock::acquire(&repository, &report).unwrap();
        assert!(RepositoryScanLock::acquire(&repository, &report).is_err());
        drop(first);
        RepositoryScanLock::acquire(&repository, &report).unwrap();
        #[cfg(unix)]
        assert!(!repository.join(".sniff").exists());
    }

    #[test]
    fn sibling_repositories_cannot_share_a_report_concurrently() {
        let root = tempfile::tempdir().unwrap();
        let first_repository = root.path().join("first");
        let second_repository = root.path().join("second");
        fs::create_dir(&first_repository).unwrap();
        fs::create_dir(&second_repository).unwrap();
        let report = root.path().join("sniff-report.md");
        let first = RepositoryScanLock::acquire(&first_repository, &report).unwrap();
        assert!(RepositoryScanLock::acquire(&second_repository, &report).is_err());
        drop(first);
        RepositoryScanLock::acquire(&second_repository, &report).unwrap();
    }

    #[test]
    fn lock_holder_child() {
        let Some(root) = std::env::var_os("SNIFF_TEST_SCAN_LOCK_CHILD_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let repository = root.join("repository");
        let _lock =
            RepositoryScanLock::acquire(&repository, &root.join("sniff-report.md")).unwrap();
        fs::write(root.join("lock-ready"), b"ready").unwrap();
        thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn changed_environment_child_cannot_take_a_held_scan_lock() {
        let Some(root) = std::env::var_os("SNIFF_TEST_SCAN_LOCK_CHANGED_ENV_ROOT") else {
            return;
        };
        let repository = std::path::PathBuf::from(root).join("repository");
        assert!(
            RepositoryScanLock::acquire(&repository, &repository.join("sniff-report.md")).is_err()
        );
    }

    #[test]
    fn environment_overrides_do_not_split_the_lock_namespace() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        let _lock =
            RepositoryScanLock::acquire(&repository, &repository.join("sniff-report.md")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scan_lock::tests::changed_environment_child_cannot_take_a_held_scan_lock",
                "--nocapture",
            ])
            .env("SNIFF_TEST_SCAN_LOCK_CHANGED_ENV_ROOT", root.path())
            .env("HOME", root.path().join("alternate-home"))
            .env("LOCALAPPDATA", root.path().join("alternate-appdata"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn process_termination_releases_both_scan_locks() {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repository");
        fs::create_dir(&repository).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scan_lock::tests::lock_holder_child",
                "--nocapture",
            ])
            .env("SNIFF_TEST_SCAN_LOCK_CHILD_ROOT", root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.path().join("lock-ready").exists() && Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "lock holder exited early: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
        if !root.path().join("lock-ready").exists() {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("lock holder did not become ready");
        }
        let report = root.path().join("sniff-report.md");
        assert!(RepositoryScanLock::acquire(&repository, &report).is_err());
        let sibling = root.path().join("sibling");
        fs::create_dir(&sibling).unwrap();
        assert!(RepositoryScanLock::acquire(&sibling, &report).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        RepositoryScanLock::acquire(&repository, &report).unwrap();
    }
}
