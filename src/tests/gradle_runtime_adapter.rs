use super::*;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().join("private");
    windows_runtime_lease::create_namespace(&root).unwrap();
    (owner, canonical(&root).unwrap())
}

#[test]
fn selected_runtime_requires_the_installations_own_native_executable() {
    for (path, name) in [
        ("C:/sdk/bin/java.bat", "java.exe"),
        ("C:/sdk/java.exe", "java.exe"),
        ("C:/sdk/bin/gradle.cmd", "gradle.bat"),
    ] {
        assert!(installation_home(Path::new(path), name).is_err());
    }
    assert_eq!(
        installation_home(Path::new("C:/sdk/bin/java.exe"), "java.exe").unwrap(),
        Path::new("C:/sdk")
    );
}

#[test]
fn runtime_tree_binding_covers_companion_bytes_and_empty_directories() {
    let (_owner, root) = fixture();
    fs::write(root.join("a.jar"), b"original").unwrap();
    let before = tree::lease(&root).unwrap().sha256;
    fs::write(root.join("a.jar"), b"changed").unwrap();
    let changed = tree::lease(&root).unwrap().sha256;
    assert_ne!(before, changed);
    fs::create_dir(root.join("empty")).unwrap();
    assert_ne!(changed, tree::lease(&root).unwrap().sha256);
}

#[test]
fn leased_runtime_files_cannot_be_written_or_replaced() {
    let (_owner, root) = fixture();
    let file = root.join("runtime.jar");
    fs::write(&file, b"fixed").unwrap();
    let lease = tree::lease(&root).unwrap();
    assert!(fs::write(&file, b"corrupt").is_err());
    assert!(fs::remove_file(&file).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"fixed");
    drop(lease);
    fs::write(&file, b"after lease").unwrap();
}

#[test]
fn private_distribution_copy_preserves_every_non_patch_file() {
    let (_owner, root) = fixture();
    let source = root.join("sdk");
    fs::create_dir_all(source.join("lib/plugins")).unwrap();
    fs::create_dir_all(source.join("empty/directory")).unwrap();
    fs::write(source.join("lib/gradle-file-temp-8.8.jar"), b"patch target").unwrap();
    fs::write(source.join("lib/plugins/a.jar"), b"unchanged").unwrap();
    let lease = tree::lease(&source).unwrap();
    let destination = root.join("overlay");
    tree::copy_distribution(&lease, &source, &destination).unwrap();
    assert!(destination.join("empty/directory").is_dir());
    assert!(!destination.join("lib/gradle-file-temp-8.8.jar").exists());
    assert_eq!(
        fs::read(destination.join("lib/plugins/a.jar")).unwrap(),
        b"unchanged"
    );
    assert_eq!(
        fs::read(source.join("lib/gradle-file-temp-8.8.jar")).unwrap(),
        b"patch target"
    );
}

#[test]
fn ambiguous_or_incomplete_pinned_distribution_is_not_adopted() {
    let (_owner, root) = fixture();
    fs::create_dir_all(root.join("lib/agents")).unwrap();
    assert!(require_pinned_distribution(&root, &tree::lease(&root).unwrap()).is_err());
    for relative in [
        "lib/gradle-file-temp-8.8.jar",
        "lib/gradle-launcher-8.8.jar",
        "lib/gradle-tooling-api-8.8.jar",
        "lib/gradle-installation-beacon-8.8.jar",
        "lib/agents/gradle-instrumentation-agent-8.8.jar",
    ] {
        fs::write(root.join(relative), b"fixture, not native proof").unwrap();
    }
    require_pinned_distribution(&root, &tree::lease(&root).unwrap()).unwrap();
    fs::write(root.join("lib/gradle-file-temp-8.7.jar"), b"ambiguous").unwrap();
    assert!(require_pinned_distribution(&root, &tree::lease(&root).unwrap()).is_err());
}

#[test]
fn owned_stage_releases_immutable_leases_before_cleanup() {
    let (_owner, root) = fixture();
    let stage = tempfile::tempdir_in(&root).unwrap();
    fs::write(stage.path().join("owned.jar"), b"fixture").unwrap();
    let stage_path = stage.path().to_path_buf();
    let lease = tree::lease(&stage_path).unwrap();
    let owned = AdaptedGradle {
        home: stage_path.clone(),
        java_home: root,
        identity_files: Vec::new(),
        _guard: lease.guard,
        _stage: stage,
    };
    drop(owned);
    assert!(!stage_path.exists());
}

#[test]
fn snapshot_owned_jdk_is_rejected_before_any_compiler_runs() {
    let (_owner, root) = fixture();
    let java = root.join("jdk/bin/java.exe");
    let gradle = root.join("gradle/bin/gradle.bat");
    fs::create_dir_all(java.parent().unwrap()).unwrap();
    fs::create_dir_all(gradle.parent().unwrap()).unwrap();
    fs::write(&java, b"not executable").unwrap();
    fs::write(java.with_file_name("javac.exe"), b"not executable").unwrap();
    fs::write(&gradle, b"not executable").unwrap();
    let error = prepare(&java, &gradle, &root).err().unwrap();
    assert!(error.contains("outside the writable snapshot"), "{error}");
}
