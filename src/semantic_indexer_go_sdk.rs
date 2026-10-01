use super::*;

const SDK_TREE_CONTRACT: &[u8] = b"sniff-go-sdk-input-tree-v1";
const MAX_ENTRIES: usize = 1_000_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 128;

pub(super) fn identity_sha256(
    spec: PinnedIndexer,
    execution_root: &Path,
    installed: &InstalledIndexer,
) -> Result<String, String> {
    let prepared =
        build_indexer_sandbox_command(spec, execution_root, installed, Vec::new(), None)?;
    let roots = prepared
        .command
        .env
        .iter()
        .filter(|(name, _)| name == "GOROOT")
        .map(|(_, value)| PathBuf::from(value))
        .collect::<Vec<_>>();
    let [root] = roots.as_slice() else {
        return Err("Go sandbox omitted or repeated its SDK input root".to_string());
    };
    tree_sha256(root)
}

// Unlike a repository snapshot, SDK inputs have no ignored paths or generated outputs.
fn tree_sha256(root: &Path) -> Result<String, String> {
    require_plain(root, true)?;
    let mut tree = TreeDigest {
        digest: Sha256::new(),
        entries: 0,
        bytes: 0,
    };
    tree.digest.update(SDK_TREE_CONTRACT);
    tree.directory(root, root)?;
    Ok(format!("{:x}", tree.digest.finalize()))
}

struct TreeDigest {
    digest: Sha256,
    entries: usize,
    bytes: u64,
}

impl TreeDigest {
    fn directory(&mut self, root: &Path, directory: &Path) -> Result<(), String> {
        if directory
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .components()
            .count()
            > MAX_DEPTH
        {
            return Err("Go SDK input tree exceeds its strict depth limit".to_string());
        }
        let names = entry_names(directory)?;
        for name in &names {
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err("Go SDK input tree exceeds its strict entry limit".to_string());
            }
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("failed to inspect Go SDK input: {error}"))?;
            if is_link(&metadata) {
                return Err(format!(
                    "Go SDK input contains a symbolic link or reparse point: {}",
                    path.display()
                ));
            }
            let relative = relative_identity(root, &path)?;
            self.digest.update((relative.len() as u64).to_le_bytes());
            self.digest.update(relative.as_bytes());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                self.digest
                    .update(metadata.permissions().mode().to_le_bytes());
            }
            if metadata.is_dir() {
                self.digest.update(b"d");
                self.directory(root, &path)?;
            } else if metadata.is_file() {
                self.digest.update(b"f");
                self.file(&path, metadata.len())?;
            } else {
                return Err(format!(
                    "Go SDK input is not a regular file/directory: {}",
                    path.display()
                ));
            }
        }
        if entry_names(directory)? != names {
            return Err("Go SDK input directory changed while hashing".to_string());
        }
        require_plain(directory, true)
    }

    fn file(&mut self, path: &Path, expected_length: u64) -> Result<(), String> {
        self.bytes = self
            .bytes
            .checked_add(expected_length)
            .filter(|bytes| *bytes <= MAX_BYTES)
            .ok_or_else(|| "Go SDK input tree exceeds its strict byte limit".to_string())?;
        self.digest.update(expected_length.to_le_bytes());
        let mut file = fs::File::open(path)
            .map_err(|error| format!("failed to open Go SDK input: {error}"))?;
        let mut buffer = [0_u8; 64 * 1024];
        let mut observed = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("failed to read Go SDK input: {error}"))?;
            if read == 0 {
                break;
            }
            observed += read as u64;
            if observed > expected_length {
                return Err("Go SDK input grew while hashing".to_string());
            }
            self.digest.update(&buffer[..read]);
        }
        require_plain(path, false)?;
        if observed != expected_length
            || fs::metadata(path).map_err(|error| error.to_string())?.len() != expected_length
        {
            return Err("Go SDK input length changed while hashing".to_string());
        }
        Ok(())
    }
}

fn entry_names(directory: &Path) -> Result<Vec<std::ffi::OsString>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("failed to enumerate Go SDK inputs: {error}"))?
    {
        if names.len() >= MAX_ENTRIES {
            return Err("Go SDK input directory exceeds its strict entry limit".to_string());
        }
        names.push(entry.map_err(|error| error.to_string())?.file_name());
    }
    names.sort();
    Ok(names)
}

fn relative_identity(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Go SDK input escaped its root".to_string())?
        .to_str()
        .ok_or_else(|| "Go SDK input path is not UTF-8".to_string())?;
    #[cfg(unix)]
    if relative.contains('\\') {
        return Err("Go SDK input path has an ambiguous separator".to_string());
    }
    Ok(relative.replace('\\', "/"))
}

fn require_plain(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect Go SDK input {}: {error}", path.display()))?;
    if is_link(&metadata)
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err(format!(
            "Go SDK input is not a plain {}: {}",
            if directory { "directory" } else { "file" },
            path.display()
        ));
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    let linked = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let linked = {
        use std::os::windows::fs::MetadataExt;
        linked || metadata.file_attributes() & 0x400 != 0
    };
    linked
}

#[cfg(test)]
#[path = "tests/semantic_indexer_go_sdk.rs"]
mod tests;
