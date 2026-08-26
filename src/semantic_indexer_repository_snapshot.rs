use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

const PRIVATE_COMPONENTS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".sniff",
    ".sniff-indexer-cache",
    ".sniff-indexer-recovery.json",
    ".sniff-indexer-tmp",
];

pub(super) fn repository_content_digest(root: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        format!(
            "failed to inspect semantic repository snapshot root {}: {error}",
            root.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "semantic repository snapshot root is not a plain directory: {}",
            root.display()
        ));
    }

    let mut digest = Sha256::new();
    digest_directory(root, root, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn stage_repository_snapshot(source: &Path, target: &Path) -> Result<(), String> {
    let expected = repository_content_digest(source)?;
    match fs::symlink_metadata(target) {
        Ok(_) => {
            return Err(format!(
                "private semantic repository snapshot already exists: {}",
                target.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect private semantic repository snapshot {}: {error}",
                target.display()
            ));
        }
    }
    fs::create_dir(target).map_err(|error| {
        format!(
            "failed to create private semantic repository snapshot {}: {error}",
            target.display()
        )
    })?;
    copy_directory(source, target, source)?;
    let observed = repository_content_digest(target)?;
    if observed != expected {
        return Err(format!(
            "repository content changed while staging private semantic snapshot {}; expected {expected}, observed {observed}",
            target.display()
        ));
    }
    Ok(())
}

fn digest_directory(root: &Path, directory: &Path, digest: &mut Sha256) -> Result<(), String> {
    for entry in sorted_entries(directory)? {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| {
            format!(
                "semantic repository snapshot path escaped {}: {} ({error})",
                root.display(),
                path.display()
            )
        })?;
        if is_private_path(relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect semantic repository snapshot entry {}: {error}",
                path.display()
            )
        })?;
        update_path(digest, relative)?;
        if metadata.file_type().is_symlink() {
            digest.update([b'l']);
            let target = fs::read_link(&path).map_err(|error| {
                format!(
                    "failed to read semantic repository snapshot symlink {}: {error}",
                    path.display()
                )
            })?;
            update_link_target(digest, &target);
        } else if metadata.is_dir() {
            digest.update([b'd']);
            digest_directory(root, &path, digest)?;
        } else if metadata.is_file() {
            digest.update([b'f']);
            digest.update(metadata.len().to_le_bytes());
            let mut file = fs::File::open(&path).map_err(|error| {
                format!(
                    "failed to open semantic repository snapshot file {}: {error}",
                    path.display()
                )
            })?;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|error| {
                    format!(
                        "failed to hash semantic repository snapshot file {}: {error}",
                        path.display()
                    )
                })?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
        } else {
            return Err(format!(
                "semantic repository snapshot contains an unsupported filesystem entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn copy_directory(source: &Path, target: &Path, root: &Path) -> Result<(), String> {
    for entry in sorted_entries(source)? {
        let source_path = entry.path();
        let relative = source_path.strip_prefix(root).map_err(|error| {
            format!(
                "semantic repository copy path escaped {}: {} ({error})",
                root.display(),
                source_path.display()
            )
        })?;
        if is_private_path(relative) {
            continue;
        }
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            format!(
                "failed to inspect semantic repository copy source {}: {error}",
                source_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            copy_symlink(&source_path, &target_path)?;
        } else if metadata.is_dir() {
            fs::create_dir(&target_path).map_err(|error| {
                format!(
                    "failed to create semantic repository copy directory {}: {error}",
                    target_path.display()
                )
            })?;
            copy_directory(&source_path, &target_path, root)?;
            fs::set_permissions(&target_path, metadata.permissions()).map_err(|error| {
                format!(
                    "failed to preserve semantic repository directory permissions {}: {error}",
                    target_path.display()
                )
            })?;
        } else if metadata.is_file() {
            let copied = fs::copy(&source_path, &target_path).map_err(|error| {
                format!(
                    "failed to copy semantic repository file {} to {}: {error}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
            if copied != metadata.len() {
                return Err(format!(
                    "semantic repository file changed while copying {}",
                    source_path.display()
                ));
            }
        } else {
            return Err(format!(
                "semantic repository copy contains an unsupported filesystem entry: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn sorted_entries(directory: &Path) -> Result<Vec<fs::DirEntry>, String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| {
            format!(
                "failed to read semantic repository directory {}: {error}",
                directory.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "failed to enumerate semantic repository directory {}: {error}",
                directory.display()
            )
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn is_private_path(path: &Path) -> bool {
    path.components().any(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        PRIVATE_COMPONENTS
            .iter()
            .any(|private| value == OsStr::new(private))
    })
}

fn update_path(digest: &mut Sha256, path: &Path) -> Result<(), String> {
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(format!(
                "semantic repository snapshot contains a non-normal path: {}",
                path.display()
            ));
        };
        update_os_string(digest, value);
    }
    digest.update([0xff]);
    Ok(())
}

fn update_link_target(digest: &mut Sha256, target: &Path) {
    digest.update([0xfe]);
    update_os_string(digest, target.as_os_str());
}

#[cfg(unix)]
fn update_os_string(digest: &mut Sha256, value: &OsStr) {
    use std::os::unix::ffi::OsStrExt;
    let bytes = value.as_bytes();
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

#[cfg(windows)]
fn update_os_string(digest: &mut Sha256, value: &OsStr) {
    use std::os::windows::ffi::OsStrExt;
    let units = value.encode_wide().collect::<Vec<_>>();
    digest.update((units.len() as u64).to_le_bytes());
    for unit in units {
        digest.update(unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn update_os_string(digest: &mut Sha256, value: &OsStr) {
    let text = value.to_string_lossy();
    digest.update((text.len() as u64).to_le_bytes());
    digest.update(text.as_bytes());
}

#[cfg(unix)]
fn copy_symlink(source: &Path, target: &Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    let link = fs::read_link(source).map_err(|error| {
        format!(
            "failed to read semantic repository symlink {}: {error}",
            source.display()
        )
    })?;
    symlink(&link, target).map_err(|error| {
        format!(
            "failed to copy semantic repository symlink {} to {}: {error}",
            source.display(),
            target.display()
        )
    })
}

#[cfg(windows)]
fn copy_symlink(source: &Path, target: &Path) -> Result<(), String> {
    use std::os::windows::fs::{FileTypeExt, symlink_dir, symlink_file};
    let link = fs::read_link(source).map_err(|error| {
        format!(
            "failed to read semantic repository symlink {}: {error}",
            source.display()
        )
    })?;
    let file_type = fs::symlink_metadata(source)
        .map_err(|error| {
            format!(
                "failed to inspect semantic repository symlink {}: {error}",
                source.display()
            )
        })?
        .file_type();
    let result = if file_type.is_symlink_dir() {
        symlink_dir(&link, target)
    } else if file_type.is_symlink_file() {
        symlink_file(&link, target)
    } else {
        return Err(format!(
            "semantic repository link has an unsupported Windows reparse type: {}",
            source.display()
        ));
    };
    result.map_err(|error| {
        format!(
            "failed to copy semantic repository symlink {} to {}: {error}",
            source.display(),
            target.display()
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn copy_symlink(source: &Path, _target: &Path) -> Result<(), String> {
    Err(format!(
        "semantic repository symlink copying is unsupported on this platform: {}",
        source.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::{repository_content_digest, stage_repository_snapshot};

    #[test]
    fn private_snapshot_copies_repository_content_without_sniff_or_vcs_state() {
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join("src")).unwrap();
        std::fs::write(repository.path().join("src/main.go"), "package main\n").unwrap();
        std::fs::write(repository.path().join("go.sum"), "original\n").unwrap();
        for private in [
            ".git",
            ".sniff",
            ".sniff-indexer-cache",
            ".sniff-indexer-recovery.json",
        ] {
            if private.ends_with(".json") {
                std::fs::write(repository.path().join(private), "private\n").unwrap();
                continue;
            }
            std::fs::create_dir(repository.path().join(private)).unwrap();
            std::fs::write(repository.path().join(private).join("state"), "private\n").unwrap();
        }
        let private_runtime = repository.path().join(".sniff-indexer-tmp");
        std::fs::create_dir(&private_runtime).unwrap();
        std::fs::write(private_runtime.join("prior-state"), "private\n").unwrap();
        let staged = private_runtime.join("go-index-workspace");

        stage_repository_snapshot(repository.path(), &staged).unwrap();

        assert_eq!(
            std::fs::read_to_string(staged.join("src/main.go")).unwrap(),
            "package main\n"
        );
        assert_eq!(
            std::fs::read_to_string(staged.join("go.sum")).unwrap(),
            "original\n"
        );
        for private in [
            ".git",
            ".sniff",
            ".sniff-indexer-cache",
            ".sniff-indexer-recovery.json",
            ".sniff-indexer-tmp",
        ] {
            assert!(!staged.join(private).exists());
        }

        std::fs::write(staged.join("go.sum"), "indexer mutation\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(repository.path().join("go.sum")).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn repository_digest_covers_non_source_content_and_new_paths() {
        let repository = tempfile::tempdir().unwrap();
        std::fs::write(repository.path().join("go.sum"), "first\n").unwrap();
        let before = repository_content_digest(repository.path()).unwrap();

        std::fs::write(repository.path().join("go.sum"), "second\n").unwrap();
        let changed_manifest = repository_content_digest(repository.path()).unwrap();
        assert_ne!(before, changed_manifest);

        std::fs::write(repository.path().join("generated.json"), "{}\n").unwrap();
        let added_path = repository_content_digest(repository.path()).unwrap();
        assert_ne!(changed_manifest, added_path);
    }

    #[test]
    fn repository_digest_ignores_only_owned_runtime_and_vcs_state() {
        let repository = tempfile::tempdir().unwrap();
        std::fs::write(repository.path().join("go.mod"), "module example.test/x\n").unwrap();
        let before = repository_content_digest(repository.path()).unwrap();

        for private in [".git", ".sniff", ".sniff-indexer-tmp"] {
            std::fs::create_dir(repository.path().join(private)).unwrap();
            std::fs::write(repository.path().join(private).join("state"), "changed\n").unwrap();
        }
        std::fs::write(
            repository.path().join(".sniff-indexer-recovery.json"),
            "changed\n",
        )
        .unwrap();
        let after = repository_content_digest(repository.path()).unwrap();

        assert_eq!(before, after);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_preserves_parent_relative_symlink_targets() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join("shared")).unwrap();
        std::fs::write(repository.path().join("shared/value.txt"), "value\n").unwrap();
        std::fs::create_dir(repository.path().join("src")).unwrap();
        symlink(
            "../shared/value.txt",
            repository.path().join("src/value.txt"),
        )
        .unwrap();
        let private_runtime = repository.path().join(".sniff-indexer-tmp");
        std::fs::create_dir(&private_runtime).unwrap();
        let staged = private_runtime.join("go-index-workspace");

        stage_repository_snapshot(repository.path(), &staged).unwrap();

        assert_eq!(
            std::fs::read_link(staged.join("src/value.txt")).unwrap(),
            std::path::PathBuf::from("../shared/value.txt")
        );
        assert_eq!(
            repository_content_digest(repository.path()).unwrap(),
            repository_content_digest(&staged).unwrap()
        );
    }
}
