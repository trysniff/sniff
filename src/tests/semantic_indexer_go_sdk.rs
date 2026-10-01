use super::*;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for directory in ["bin", "pkg/tool", "src/runtime", ".git", ".sniff"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    for (path, content) in [
        ("bin/go", "compiler-driver"),
        ("pkg/tool/compile", "compiler-backend"),
        ("src/runtime/runtime.go", "package runtime"),
        ("go.env", "GOTOOLCHAIN=local"),
        (".git/input", "not-ignored"),
        (".sniff/input", "also-not-ignored"),
    ] {
        fs::write(root.path().join(path), content).unwrap();
    }
    root
}

#[test]
fn sdk_binding_covers_backends_standard_library_environment_and_every_path() {
    for path in [
        "bin/go",
        "pkg/tool/compile",
        "src/runtime/runtime.go",
        "go.env",
        ".git/input",
        ".sniff/input",
    ] {
        let root = fixture();
        let before = tree_sha256(root.path()).unwrap();
        let mut content = fs::read(root.path().join(path)).unwrap();
        content[0] ^= 1;
        fs::write(root.path().join(path), content).unwrap();
        assert_ne!(before, tree_sha256(root.path()).unwrap(), "{path}");
    }
}

#[test]
fn sdk_binding_tracks_empty_directories_additions_removals_and_renames() {
    let root = fixture();
    let before = tree_sha256(root.path()).unwrap();
    fs::create_dir(root.path().join("empty")).unwrap();
    let empty = tree_sha256(root.path()).unwrap();
    assert_ne!(before, empty);
    fs::write(root.path().join("empty/input"), "").unwrap();
    let added = tree_sha256(root.path()).unwrap();
    assert_ne!(empty, added);
    fs::rename(
        root.path().join("empty/input"),
        root.path().join("empty/renamed"),
    )
    .unwrap();
    assert_ne!(added, tree_sha256(root.path()).unwrap());
    fs::remove_file(root.path().join("empty/renamed")).unwrap();
    assert_eq!(empty, tree_sha256(root.path()).unwrap());
}

#[test]
fn sdk_binding_is_location_independent_and_keeps_file_boundaries() {
    let left = fixture();
    let right = fixture();
    assert_eq!(
        tree_sha256(left.path()).unwrap(),
        tree_sha256(right.path()).unwrap()
    );
    fs::write(left.path().join("one"), "ab").unwrap();
    fs::write(left.path().join("two"), "c").unwrap();
    fs::write(right.path().join("one"), "a").unwrap();
    fs::write(right.path().join("two"), "bc").unwrap();
    assert_ne!(
        tree_sha256(left.path()).unwrap(),
        tree_sha256(right.path()).unwrap()
    );
}

#[test]
fn sdk_binding_rejects_missing_non_directory_and_unbounded_inputs() {
    let root = fixture();
    assert!(tree_sha256(&root.path().join("missing")).is_err());
    assert!(tree_sha256(&root.path().join("go.env")).is_err());
    let mut tree = TreeDigest {
        digest: Sha256::new(),
        entries: MAX_ENTRIES,
        bytes: 0,
    };
    assert!(
        tree.directory(root.path(), root.path())
            .unwrap_err()
            .contains("entry limit")
    );
    let mut tree = TreeDigest {
        digest: Sha256::new(),
        entries: 0,
        bytes: MAX_BYTES,
    };
    assert!(
        tree.file(&root.path().join("go.env"), 1)
            .unwrap_err()
            .contains("byte limit")
    );
}

#[cfg(windows)]
#[test]
fn sdk_binding_rejects_actual_windows_directory_junctions() {
    let root = fixture();
    let external = tempfile::tempdir().unwrap();
    let link = root.path().join("linked");
    let output = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(external.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        tree_sha256(root.path())
            .unwrap_err()
            .contains("reparse point")
    );
    assert!(tree_sha256(&link).unwrap_err().contains("plain directory"));
    fs::remove_dir(&link).unwrap();
    assert!(external.path().is_dir());
}

#[cfg(unix)]
#[test]
fn sdk_binding_rejects_linked_roots_files_directories_and_dangling_links() {
    use std::os::unix::fs::symlink;
    for target in ["bin", "go.env", "missing"] {
        let root = fixture();
        symlink(root.path().join(target), root.path().join("linked")).unwrap();
        assert!(
            tree_sha256(root.path())
                .unwrap_err()
                .contains("symbolic link")
        );
    }
    let root = fixture();
    let parent = tempfile::tempdir().unwrap();
    symlink(root.path(), parent.path().join("sdk")).unwrap();
    assert!(
        tree_sha256(&parent.path().join("sdk"))
            .unwrap_err()
            .contains("plain directory")
    );
}

#[cfg(unix)]
#[test]
fn sdk_binding_tracks_tool_execute_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = fixture();
    let path = root.path().join("bin/go");
    let before = tree_sha256(root.path()).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
    assert_ne!(before, tree_sha256(root.path()).unwrap());
}

#[cfg(unix)]
#[test]
fn sdk_binding_rejects_non_utf8_and_ambiguous_path_encodings() {
    use std::os::unix::ffi::OsStringExt;
    for name in [
        std::ffi::OsString::from_vec(vec![0xff]),
        std::ffi::OsString::from("a\\b"),
    ] {
        let root = fixture();
        assert!(relative_identity(root.path(), &root.path().join(name)).is_err());
    }
}
