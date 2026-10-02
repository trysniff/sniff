use crate::windows_runtime_lease;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub(super) struct Tree {
    pub(super) sha256: String,
    pub(super) files: Vec<PathBuf>,
    pub(super) directories: Vec<PathBuf>,
    pub(super) guard: Vec<File>,
}

pub(super) fn lease(root: &Path) -> Result<Tree, String> {
    const MAX_ENTRIES: usize = 8192;
    const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    let mut guard = windows_runtime_lease::lock_base(root, false)?;
    let mut directories = vec![root.to_path_buf()];
    let mut records = Vec::new();
    let mut files = Vec::new();
    let mut directory_paths = Vec::new();
    let mut bytes = 0u64;
    while let Some(directory) = directories.pop() {
        guard.push(windows_runtime_lease::hold_trusted(
            &directory, true, false,
        )?);
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| error.to_string())?
            .take(MAX_ENTRIES.saturating_sub(records.len()) + 1)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if entries.len() > MAX_ENTRIES.saturating_sub(records.len()) {
            return Err("selected Gradle/JDK tree exceeds its entry bound".to_string());
        }
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if records.len() >= MAX_ENTRIES {
                return Err("selected Gradle/JDK tree exceeds its entry bound".to_string());
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            let relative = relative.to_str().ok_or("runtime tree path is not UTF-8")?;
            if metadata.is_dir() {
                // hold_trusted rejects reparse points, including directory junctions.
                guard.push(windows_runtime_lease::hold_trusted(&path, true, false)?);
                records.push((relative.replace('\\', "/"), "directory".to_string()));
                directories.push(path);
                directory_paths.push(entry.path());
            } else {
                let mut file = windows_runtime_lease::hold_trusted(&path, false, false)?;
                let mut digest = Sha256::new();
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
                    if read == 0 {
                        break;
                    }
                    bytes = bytes
                        .checked_add(read as u64)
                        .ok_or("runtime byte overflow")?;
                    if bytes > MAX_BYTES {
                        return Err("selected Gradle/JDK tree exceeds its byte bound".to_string());
                    }
                    digest.update(&buffer[..read]);
                }
                records.push((
                    relative.replace('\\', "/"),
                    format!("{:x}", digest.finalize()),
                ));
                files.push(path);
                guard.push(file);
            }
        }
    }
    records.sort();
    let committed = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
    Ok(Tree {
        sha256: format!("{:x}", Sha256::digest(committed)),
        files,
        directories: directory_paths,
        guard,
    })
}

pub(super) fn copy_distribution(
    tree: &Tree,
    source: &Path,
    destination: &Path,
) -> Result<(), String> {
    fs::create_dir(destination).map_err(|error| error.to_string())?;
    for path in &tree.directories {
        let relative = path
            .strip_prefix(source)
            .map_err(|error| error.to_string())?;
        fs::create_dir_all(destination.join(relative)).map_err(|error| error.to_string())?;
    }
    for path in &tree.files {
        let relative = path
            .strip_prefix(source)
            .map_err(|error| error.to_string())?;
        if relative == Path::new("lib/gradle-file-temp-8.8.jar") {
            continue;
        }
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().ok_or("distribution file has no parent")?)
            .map_err(|error| error.to_string())?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| error.to_string())?;
        let mut input = File::open(path).map_err(|error| error.to_string())?;
        std::io::copy(&mut input, &mut output).map_err(|error| error.to_string())?;
        output.sync_all().map_err(|error| error.to_string())?;
    }
    Ok(())
}
