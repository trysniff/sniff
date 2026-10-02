use super::*;
use crate::semantic_index::{SemanticIndexerCompilerQuery, SemanticVariantId};
use tempfile::TempDir;

fn invalid_neighbor_fixture() -> (TempDir, Vec<FileRecord>) {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/fixture\ngo 1.23\n",
    )
    .unwrap();
    fs::write(
        root.path().join("main.go"),
        "package fixture\nfunc value() int { return 1 }\n",
    )
    .unwrap();
    fs::create_dir(root.path().join("z")).unwrap();
    fs::write(
        root.path().join("z/go.mod"),
        "module example.test/neighbor\ngo invalid-version\n",
    )
    .unwrap();
    fs::write(
        root.path().join("z/neighbor.go"),
        "package neighbor\nfunc value() int { return 2 }\n",
    )
    .unwrap();
    let file =
        crate::parser::parse_file_checked(root.path().join("main.go").to_str().unwrap()).unwrap();
    (root, vec![file])
}

fn assert_preparation_failure(failure: &SemanticIndexerRunFailure) {
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::Preparation,
        "{failure:?}"
    );
    assert_eq!(failure.indexer, Some(SemanticIndexerKind::Go));
    let process = failure
        .process
        .as_ref()
        .expect("lost real Go process evidence");
    assert!(process.status_code.is_some_and(|code| code != 0));
    assert!(!process.timed_out);
    assert!(!process.memory_limit_exceeded);
    assert!(!process.process_limit_exceeded);
    assert!(process.stderr.contains("invalid go version"), "{failure:?}");
    assert_eq!(
        process.stderr_sha256,
        format!("{:x}", Sha256::digest(process.stderr.as_bytes()))
    );
}

fn assert_owned_stage_removed(root: &Path, execution_root: &Path, before: &str) {
    assert!(!execution_root.exists());
    assert!(!execution_root.parent().unwrap().exists());
    assert_eq!(
        repository_snapshot::repository_content_digest(root).unwrap(),
        before
    );
    assert!(!root.join(INDEXER_TEMP_DIR).exists());
    assert!(!root.join(INDEXER_CACHE_DIR).exists());
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn discovery_failure_preserves_source_and_removes_owned_stage() {
    let (root, files) = invalid_neighbor_fixture();
    let before = repository_snapshot::repository_content_digest(root.path()).unwrap();
    // Explicit fixture installation rejects stale caches; it does not repair them.
    crate::semantic_indexer_installer::install_required_indexers(&files, false)
        .await
        .expect("explicit pinned Go fixture installation failed");
    let store = SemanticIndexerStore::for_user().unwrap();
    let recovery = recovery::SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
    let execution_root = recovery.prepare_indexer_run().unwrap();
    let context = RequiredIndexerRunContext {
        root: root.path(),
        files: &files,
        required_documents: &files,
        store: &store,
        recovery: &recovery,
        repository_content_sha256: &before,
        progress_root: None,
    };

    let failure = discover(&context).await.unwrap_err();

    assert_preparation_failure(&failure);
    assert_owned_stage_removed(root.path(), &execution_root, &before);
    super::super::census::assert_native_preparation_failure_terminal(root.path());
    recovery.finish().unwrap();
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn qualified_preparation_checks_unselected_neighbor_and_cleans_up_on_failure() {
    let (root, files) = invalid_neighbor_fixture();
    let before = repository_snapshot::repository_content_digest(root.path()).unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let store = SemanticIndexerStore::for_user().unwrap();
    let installed = store.verify(spec).unwrap();
    let recovery = recovery::SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
    let execution_root = recovery.prepare_indexer_run().unwrap();
    repository_snapshot::stage_repository_snapshot(root.path(), &execution_root).unwrap();
    super::super::go_dependencies::prepare_root(&execution_root).unwrap();
    prepare_go_dependency_cache(spec, &execution_root, &installed, ".")
        .await
        .unwrap();
    let sdk = super::super::go_sdk::identity_sha256(spec, &execution_root, &installed).unwrap();
    let dependencies = super::super::go_dependencies::identity_sha256(&execution_root).unwrap();
    // This is an executor-boundary fixture, not a substitute for full discovery.
    let plan = SemanticIndexerVariantPlan {
        identity: SemanticVariantId("preparation-failure-boundary".to_string()),
        dimensions: BTreeMap::from([
            ("compiler_sdk_sha256".to_string(), sdk),
            ("compiler_dependencies_sha256".to_string(), dependencies),
            (
                "compiler_dependency_projects".to_string(),
                r#"["go.mod","z/go.mod"]"#.to_string(),
            ),
            ("source_snapshot_sha256".to_string(), before.clone()),
        ]),
        environment: BTreeMap::from([
            ("GOOS".to_string(), "linux".to_string()),
            ("GOARCH".to_string(), "amd64".to_string()),
            ("CGO_ENABLED".to_string(), "0".to_string()),
            ("GOFLAGS".to_string(), String::new()),
        ]),
        compiler_query: SemanticIndexerCompilerQuery::ProjectPackages,
        compiler_project: Some(RepositoryPath("go.mod".to_string())),
        selected_documents: BTreeSet::from([RepositoryPath("main.go".to_string())]),
        ignored_documents: BTreeSet::new(),
    };
    let inputs = super::super::go_runner::GoIndexerRunInputs {
        spec,
        root: root.path(),
        installed: &installed,
        files: &files,
        required_documents: &files,
        recovery: &recovery,
        repository_content_sha256: &before,
        progress_root: None,
    };

    let failure = super::super::go_runner::run_required_go_indexer_variants(inputs, &[plan])
        .await
        .unwrap_err();

    assert_preparation_failure(&failure);
    assert_owned_stage_removed(root.path(), &execution_root, &before);
    recovery.finish().unwrap();
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}
