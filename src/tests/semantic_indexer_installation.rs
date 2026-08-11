use crate::semantic_indexer_installation::SemanticIndexerStore;
use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct TestTempDir(PathBuf);

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir() -> TestTempDir {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "sniff-semantic-indexer-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    TestTempDir(path)
}

fn prepared_store() -> (TestTempDir, SemanticIndexerStore) {
    let temp = temp_dir();
    let store = SemanticIndexerStore::at(temp.0.join("indexers"));
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let root = store.installation_root(spec);
    let entrypoint = root.join(spec.entrypoint_relative_path());
    fs::create_dir_all(entrypoint.parent().unwrap()).unwrap();
    fs::write(entrypoint, b"trusted test indexer").unwrap();
    (temp, store)
}

#[test]
fn sealed_installation_verifies() {
    let (_temp, store) = prepared_store();
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let installed = store.seal(spec).unwrap();
    assert_eq!(
        installed.entrypoint,
        store
            .installation_root(spec)
            .join(spec.entrypoint_relative_path())
    );
    assert_eq!(store.verify(spec).unwrap(), installed);
}

#[test]
fn changed_content_is_rejected_after_sealing() {
    let (_temp, store) = prepared_store();
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    store.seal(spec).unwrap();
    fs::write(
        store
            .installation_root(spec)
            .join(spec.entrypoint_relative_path()),
        b"changed",
    )
    .unwrap();
    let error = store.verify(spec).unwrap_err();
    assert!(error.contains("checksum mismatch"));
}

#[test]
fn files_added_after_sealing_are_rejected() {
    let (_temp, store) = prepared_store();
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    store.seal(spec).unwrap();
    fs::write(
        store.installation_root(spec).join("unexpected.bin"),
        b"extra",
    )
    .unwrap();
    let error = store.verify(spec).unwrap_err();
    assert!(error.contains("checksum mismatch"));
}

#[test]
fn missing_installation_fails_closed() {
    let temp = temp_dir();
    let store = SemanticIndexerStore::at(temp.0.join("indexers"));
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let error = store.verify(spec).unwrap_err();
    assert!(error.contains("not installed"));
}

#[cfg(windows)]
#[test]
fn windows_rust_installation_requires_the_pinned_cargo_companion() {
    let temp = temp_dir();
    let store = SemanticIndexerStore::at(temp.0.join("indexers"));
    let spec = pinned_indexer(SemanticIndexerKind::Rust).unwrap();
    let root = store.installation_root(spec);
    let entrypoint = root.join(spec.entrypoint_relative_path());
    fs::create_dir_all(entrypoint.parent().unwrap()).unwrap();
    fs::write(entrypoint, b"rust-analyzer").unwrap();

    let error = store.seal(spec).unwrap_err();

    assert!(error.contains("cargo.exe"), "{error}");
    assert!(error.contains("runtime file is missing"), "{error}");
}

#[cfg(unix)]
#[test]
fn symlinked_entrypoint_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let store = SemanticIndexerStore::at(temp.path().join("indexers"));
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let root = store.installation_root(spec);
    let entrypoint = root.join(spec.entrypoint_relative_path());
    fs::create_dir_all(entrypoint.parent().unwrap()).unwrap();
    let target = root.join("real-indexer.js");
    fs::write(&target, b"trusted test indexer").unwrap();
    symlink(target, entrypoint).unwrap();
    let error = store.seal(spec).unwrap_err();
    assert!(error.contains("non-regular") || error.contains("symlink"));
}
