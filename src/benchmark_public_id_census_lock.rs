use std::fs::{self, File, OpenOptions};
use std::path::Path;

pub(super) struct CensusLock(File);

impl CensusLock {
    pub(super) fn acquire(path: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err("public-ID census lock is not a plain file".to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("failed to inspect public-ID census lock: {error}")),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(path)
            .map_err(|error| format!("failed to open public-ID census lock: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect opened public-ID census lock: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("public-ID census lock is not a plain file".to_string());
        }
        lock_file(&file)?;
        Ok(Self(file))
    }
}

impl Drop for CensusLock {
    fn drop(&mut self) {
        unlock_file(&self.0);
    }
}

#[cfg(unix)]
fn lock_file(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "public-ID census is already active or cannot be locked: {}",
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
            "public-ID census is already active or cannot be locked: {}",
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
