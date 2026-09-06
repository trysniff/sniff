use super::files::{is_sha256, sha256};
use super::*;

fn request() -> PythonBuildToolchainRequest {
    PythonBuildToolchainRequest {
        repository_revision: "abc123".to_string(),
        manifest_repository_path: "pyproject.toml".to_string(),
        manifest_source_sha256: "a".repeat(64),
        build_backend: "hatchling.build".to_string(),
        backend_path: Vec::new(),
        build_requirements: vec!["hatchling==1.27.0".to_string()],
        package_index: super::super::python_build_requirement::PYPI_SIMPLE_INDEX.to_string(),
        python_runtime_identity_sha256: "b".repeat(64),
        pip_runtime_identity_sha256: "c".repeat(64),
        target_platform: "test-platform".to_string(),
    }
}

fn prepared(root: &Path) -> PathBuf {
    let prepared = root.join("prepared");
    fs::create_dir(&prepared).unwrap();
    let wheelhouse = prepared.join(WHEELHOUSE_NAME);
    fs::create_dir(&wheelhouse).unwrap();
    let filename = "hatchling-1.27.0-py3-none-any.whl";
    let wheel_bytes = b"fixture wheel";
    let wheel_sha256 = sha256(wheel_bytes);
    fs::write(wheelhouse.join(filename), wheel_bytes).unwrap();
    fs::write(
        prepared.join(LOCK_NAME),
        format!("hatchling==1.27.0 --hash=sha256:{wheel_sha256}\n"),
    )
    .unwrap();
    fs::write(
        prepared.join(REQUIREMENTS_NAME),
        serde_json::to_vec(&PythonBuildRequirementsContract {
            static_requirements: vec!["hatchling==1.27.0".to_string()],
            dynamic_requirements: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();
    fs::write(
        prepared.join(PROVENANCE_NAME),
        serde_json::to_vec(&PythonWheelhouseProvenance {
            version: 1,
            contract: WHEELHOUSE_CONTRACT.to_string(),
            artifacts: vec![PythonWheelArtifact {
                name: "hatchling".to_string(),
                version: "1.27.0".to_string(),
                filename: filename.to_string(),
                sha256: wheel_sha256,
                size: wheel_bytes.len() as u64,
            }],
        })
        .unwrap(),
    )
    .unwrap();
    prepared
}

fn empty_prepared(root: &Path) -> PathBuf {
    let prepared = root.join("prepared-empty");
    fs::create_dir(&prepared).unwrap();
    fs::create_dir(prepared.join(WHEELHOUSE_NAME)).unwrap();
    fs::write(prepared.join(LOCK_NAME), b"").unwrap();
    fs::write(
        prepared.join(REQUIREMENTS_NAME),
        serde_json::to_vec(&PythonBuildRequirementsContract {
            static_requirements: Vec::new(),
            dynamic_requirements: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();
    fs::write(
        prepared.join(PROVENANCE_NAME),
        serde_json::to_vec(&PythonWheelhouseProvenance {
            version: 1,
            contract: WHEELHOUSE_CONTRACT.to_string(),
            artifacts: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();
    prepared
}

#[test]
fn imported_toolchain_is_content_addressed_and_verified() {
    let root = tempfile::tempdir().unwrap();
    let store = PythonBuildToolchainStore::at(root.path().join("store"));
    let prepared = prepared(root.path());

    let installed = store.import_prepared(&request(), &prepared).unwrap();
    let verified = store.verify(&request()).unwrap();

    assert_eq!(installed, verified);
    assert!(is_sha256(&verified.identity_sha256));
    assert!(verified.lock.is_file());
    assert!(verified.provenance.is_file());
    assert!(verified.wheelhouse.is_dir());
    assert_eq!(verified.root, store.entry_root(&request()).unwrap());

    let materialized = root.path().join("materialized");
    fs::create_dir(&materialized).unwrap();
    verified.materialize_into(&materialized).unwrap();
    assert!(materialized.join(LOCK_NAME).is_file());
    assert!(materialized.join(REQUIREMENTS_NAME).is_file());
    assert!(materialized.join(PROVENANCE_NAME).is_file());
    assert!(materialized.join(WHEELHOUSE_NAME).is_dir());
    assert_eq!(
        verified.requirements().unwrap().static_requirements,
        request().build_requirements
    );
}

#[test]
fn empty_resolved_toolchain_is_content_addressed_and_verified() {
    let root = tempfile::tempdir().unwrap();
    let store = PythonBuildToolchainStore::at(root.path().join("store"));
    let prepared = empty_prepared(root.path());
    let mut request = request();
    request.build_requirements.clear();

    let installed = store.import_prepared(&request, &prepared).unwrap();
    let verified = store.verify(&request).unwrap();

    assert_eq!(installed, verified);
    assert!(is_sha256(&verified.identity_sha256));
    assert_eq!(fs::read(&verified.lock).unwrap(), b"");
    assert!(
        verified
            .requirements()
            .unwrap()
            .static_requirements
            .is_empty()
    );
}

#[test]
fn toolchain_verification_rejects_tree_and_lock_tampering() {
    let root = tempfile::tempdir().unwrap();
    let store = PythonBuildToolchainStore::at(root.path().join("store"));
    let prepared = prepared(root.path());
    let installed = store.import_prepared(&request(), &prepared).unwrap();

    let wheel = installed
        .wheelhouse
        .join("hatchling-1.27.0-py3-none-any.whl");
    fs::write(&wheel, "changed wheel").unwrap();
    let error = store.verify(&request()).unwrap_err();
    assert!(
        error.contains("checksum changed") || error.contains("size or file type changed"),
        "{error}"
    );

    fs::write(&wheel, b"fixture wheel").unwrap();
    fs::write(&installed.lock, "changed\n").unwrap();
    let error = store.verify(&request()).unwrap_err();
    assert!(error.contains("lock does not match"), "{error}");
}

#[test]
fn request_identity_changes_for_runtime_or_source_drift() {
    let request = request();
    let mut changed_runtime = request.clone();
    changed_runtime.python_runtime_identity_sha256 = "d".repeat(64);
    let mut changed_source = request.clone();
    changed_source.manifest_source_sha256 = "e".repeat(64);

    assert_ne!(
        request_sha256(&request).unwrap(),
        request_sha256(&changed_runtime).unwrap()
    );
    assert_ne!(
        request_sha256(&request).unwrap(),
        request_sha256(&changed_source).unwrap()
    );
}

#[test]
fn sha256_identity_requires_canonical_lowercase_hex() {
    assert!(is_sha256(&"a".repeat(64)));
    assert!(!is_sha256(&"A".repeat(64)));
    assert!(!is_sha256(&"g".repeat(64)));
}

#[cfg(unix)]
#[test]
fn import_rejects_symbolic_links() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let store = PythonBuildToolchainStore::at(root.path().join("store"));
    let prepared = prepared(root.path());
    symlink(
        prepared.join(LOCK_NAME),
        prepared.join(WHEELHOUSE_NAME).join("link.whl"),
    )
    .unwrap();

    let error = store.import_prepared(&request(), &prepared).unwrap_err();
    assert!(error.contains("symbolic link"), "{error}");
}
