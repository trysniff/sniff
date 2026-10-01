use super::super::execution::finish_worker;
use super::*;
use crate::semantic_index::{SemanticIndexerCompilerQuery, SemanticVariantId};
use tempfile::TempDir;

fn plan() -> SemanticIndexerVariantPlan {
    SemanticIndexerVariantPlan {
        identity: SemanticVariantId("test-world".into()),
        dimensions: BTreeMap::from([
            (
                "discovery_scope".into(),
                "conventional-config-roots-and-compiler-reference-closure".into(),
            ),
            ("project_model_runtime_sha256".into(), "a".repeat(64)),
            ("source_snapshot_sha256".into(), "b".repeat(64)),
            ("compiler_runtime_sha256".into(), "c".repeat(64)),
            ("compiler_installation_sha256".into(), "d".repeat(64)),
        ]),
        environment: BTreeMap::new(),
        compiler_query: SemanticIndexerCompilerQuery::ProjectPackages,
        compiler_project: Some(RepositoryPath("tsconfig.json".into())),
        selected_documents: BTreeSet::from([RepositoryPath("index.ts".into())]),
        ignored_documents: BTreeSet::new(),
    }
}

#[test]
fn normal_census_requires_all_bindings_and_rejects_malformed_digests() {
    assert!(required(&[plan()]).unwrap().is_some());
    for key in [
        "project_model_runtime_sha256",
        "source_snapshot_sha256",
        "compiler_runtime_sha256",
        "compiler_installation_sha256",
    ] {
        let mut missing = plan();
        missing.dimensions.remove(key);
        assert!(required(&[missing]).unwrap_err().contains(key));
        for value in ["".into(), "A".repeat(64), "e".repeat(63), "z".repeat(64)] {
            let mut invalid = plan();
            invalid.dimensions.insert(key.into(), value);
            assert!(required(&[invalid]).unwrap_err().contains(key));
        }
    }
}

#[test]
fn normal_census_cannot_mix_missing_conflicting_or_unknown_worlds() {
    let mut explicit = plan();
    explicit.dimensions.clear();
    explicit
        .dimensions
        .insert("compiler_version".into(), "fixture".into());
    assert!(required(&[explicit.clone()]).unwrap().is_none());
    assert!(required(&[plan(), explicit]).is_err());
    for key in [
        "compiler_runtime_sha256",
        "compiler_installation_sha256",
        "discovery_scope",
    ] {
        let mut changed = plan();
        changed.dimensions.insert(key.into(), "f".repeat(64));
        assert!(required(&[plan(), changed]).is_err());
    }
}

#[test]
fn observed_execution_identity_tracks_node_and_installation_not_location() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let first_node = first.path().join("node-image");
    let second_node = second.path().join("node-image");
    fs::write(&first_node, b"node image").unwrap();
    fs::write(&second_node, b"node image").unwrap();
    // This is a fingerprint fixture, not a verified executable/provider fixture.
    let mut installed = InstalledIndexer {
        root: first.path().into(),
        entrypoint: first.path().join("unused"),
        tree_sha256: "d".repeat(64),
    };
    let original = runtime_sha256(spec, &installed, std::slice::from_ref(&first_node)).unwrap();
    assert_eq!(
        original,
        runtime_sha256(spec, &installed, std::slice::from_ref(&second_node)).unwrap()
    );
    fs::write(&second_node, b"changed node image").unwrap();
    assert_ne!(
        original,
        runtime_sha256(spec, &installed, std::slice::from_ref(&second_node)).unwrap()
    );
    installed.tree_sha256 = "e".repeat(64);
    assert_ne!(
        original,
        runtime_sha256(spec, &installed, std::slice::from_ref(&first_node)).unwrap()
    );
    assert!(runtime_sha256(spec, &installed, &[]).is_err());
    assert!(runtime_sha256(spec, &installed, &[first_node, second_node]).is_err());
}

#[test]
fn execution_and_installation_drift_fail_before_reusing_any_index() {
    let expected = required(&[plan()]).unwrap().unwrap();
    assert!(verify(Some(&expected), &expected).is_ok());
    for runtime_changed in [false, true] {
        let mut changed = expected.clone();
        if runtime_changed {
            changed.runtime = "e".repeat(64);
        } else {
            changed.installation = "e".repeat(64);
        }
        assert!(
            verify(Some(&expected), &changed)
                .unwrap_err()
                .contains("execution inputs differ")
        );
    }
}

#[test]
fn prepared_worker_must_match_census_even_when_host_observations_match() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let root = TempDir::new().unwrap();
    let host = root.path().join("host-image");
    let worker = root.path().join("worker-image");
    fs::write(&host, b"image A").unwrap();
    fs::write(&worker, b"image B").unwrap();
    let installed = InstalledIndexer {
        root: root.path().into(),
        entrypoint: root.path().join("unused"),
        tree_sha256: "d".repeat(64),
    };
    let host_identity = runtime_file_identities(std::slice::from_ref(&host)).unwrap();
    let mut plan = plan();
    plan.dimensions.insert(
        "compiler_runtime_sha256".into(),
        runtime_commitment(spec, &installed, &host_identity).unwrap(),
    );
    let worker_identity = runtime_file_identities(std::slice::from_ref(&worker)).unwrap();
    assert!(verify_worker(spec, &installed, &plan, &worker, &worker_identity).is_err());
    assert!(verify_worker(spec, &installed, &plan, &host, &host_identity).is_ok());
    assert!(
        verify_worker(spec, &installed, &plan, &worker, &host_identity)
            .unwrap_err()
            .contains("worker program differs")
    );
    assert_eq!(host_identity, runtime_file_identities(&[host]).unwrap());
}

#[test]
fn post_worker_runtime_failure_preserves_output_without_inventing_startup_evidence() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let stdout = "actual output".to_string();
    let stderr = "actual diagnostic".to_string();
    let output = crate::sandbox::SandboxOutput {
        status_code: Some(0),
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stdout,
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    };
    let expected = process_evidence(output.clone());
    let failure = finish_worker(spec, Ok(output), Err("image changed".into())).unwrap_err();
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::IntegrityVerification
    );
    assert_eq!(failure.process.as_deref(), Some(&expected));
    let failure = finish_worker(
        spec,
        Err("startup failed".into()),
        Err("image changed".into()),
    )
    .unwrap_err();
    assert!(failure.process.is_none());
    assert!(failure.detail.contains("startup failed"));
    assert!(failure.detail.contains("image changed"));
}

#[test]
fn census_node_commitment_uses_the_guard_snapshot_not_a_second_file_read() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let root = TempDir::new().unwrap();
    let node = root.path().join("node-image");
    let sidecar = root.path().join("sidecar.js");
    fs::write(&node, b"image A").unwrap();
    fs::write(&sidecar, b"sidecar").unwrap();
    let installed = InstalledIndexer {
        root: root.path().into(),
        entrypoint: root.path().join("unused"),
        tree_sha256: "d".repeat(64),
    };
    let expected = runtime_sha256(spec, &installed, std::slice::from_ref(&node)).unwrap();
    let identities = runtime_file_identities(&[node.clone(), sidecar]).unwrap();
    fs::write(&node, b"image B").unwrap();
    assert_eq!(
        command_runtime_sha256(spec, &installed, &node, &identities).unwrap(),
        expected
    );
    assert_ne!(
        runtime_sha256(spec, &installed, std::slice::from_ref(&node)).unwrap(),
        expected
    );
    let mut duplicates = identities.clone();
    duplicates.extend(identities);
    assert!(command_runtime_sha256(spec, &installed, &node, &duplicates).is_err());
    assert!(command_runtime_sha256(spec, &installed, &node, &[]).is_err());
}
