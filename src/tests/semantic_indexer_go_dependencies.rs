use super::*;

#[test]
fn dependency_binding_requires_an_explicit_prepared_empty_cache() {
    let root = tempfile::tempdir().unwrap();
    assert!(identity_sha256(root.path()).is_err());
    prepare_root(root.path()).unwrap();
    let empty = identity_sha256(root.path()).unwrap();
    assert_eq!(identity_sha256(root.path()).unwrap(), empty);
    assert_ne!(
        empty,
        super::super::go_input_tree::sha256(
            &go_module_cache_root(root.path()),
            b"sniff-go-sdk-input-tree-v1"
        )
        .unwrap()
    );
    fs::remove_dir(go_module_cache_root(root.path())).unwrap();
    assert!(identity_sha256(root.path()).is_err());
}

#[test]
fn dependency_binding_covers_extracted_source_manifests_archives_and_checksums() {
    for path in [
        "example.test/dep@v1.0.0/dep.go",
        "cache/download/example.test/dep/@v/v1.0.0.mod",
        "cache/download/example.test/dep/@v/v1.0.0.zip",
        "cache/download/example.test/dep/@v/v1.0.0.ziphash",
    ] {
        let root = tempfile::tempdir().unwrap();
        prepare_root(root.path()).unwrap();
        let file = go_module_cache_root(root.path()).join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "original").unwrap();
        let before = identity_sha256(root.path()).unwrap();
        fs::write(file, "mutation").unwrap();
        assert_ne!(identity_sha256(root.path()).unwrap(), before, "{path}");
    }
}

#[test]
fn dependency_binding_uses_the_actual_sandbox_cache_path_and_excludes_build_outputs() {
    let root = tempfile::tempdir().unwrap();
    prepare_root(root.path()).unwrap();
    let environment = go_sandbox_environment(root.path(), Path::new("compiler-sdk"))
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        environment["GOMODCACHE"],
        sandbox_repository_argument(
            root.path(),
            &go_module_cache_root(root.path()).to_string_lossy()
        )
    );
    let before = identity_sha256(root.path()).unwrap();
    fs::create_dir(root.path().join(INDEXER_TEMP_DIR).join("go-build")).unwrap();
    fs::write(
        root.path().join(INDEXER_TEMP_DIR).join("go-build/object"),
        "derived",
    )
    .unwrap();
    assert_eq!(identity_sha256(root.path()).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn dependency_binding_rejects_linked_cache_ancestors_before_creating_children() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    symlink(external.path(), root.path().join(INDEXER_TEMP_DIR)).unwrap();
    assert!(prepare_root(root.path()).is_err());
    assert!(identity_sha256(root.path()).is_err());
    assert_eq!(fs::read_dir(external.path()).unwrap().count(), 0);
}
