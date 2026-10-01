use super::*;
use crate::semantic_index::{RepositoryPath, SemanticVariantId};
use tempfile::TempDir;

enum StaleClaim {
    Sdk,
    Dependencies,
    MissingSdk,
}

fn change_digest(digest: &mut String) {
    let replacement = if digest.starts_with('0') { "1" } else { "0" };
    digest.replace_range(..1, replacement);
}

async fn reject_stale_claim(claim: StaleClaim) {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/input-boundary\ngo 1.23\n",
    )
    .unwrap();
    fs::write(
        root.path().join("main.go"),
        "package boundary\nfunc value() int { return 1 }\n",
    )
    .unwrap();
    let files = [
        crate::parser::parse_file_checked(root.path().join("main.go").to_str().unwrap()).unwrap(),
    ];
    let before = repository_snapshot::repository_content_digest(root.path()).unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let installed = SemanticIndexerStore::for_user()
        .unwrap()
        .verify(spec)
        .unwrap();
    let recovery = recovery::SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
    let execution_root = recovery.prepare_indexer_run().unwrap();
    repository_snapshot::stage_repository_snapshot(root.path(), &execution_root).unwrap();
    super::super::go_dependencies::prepare_root(&execution_root).unwrap();
    let sdk = super::super::go_sdk::identity_sha256(spec, &execution_root, &installed).unwrap();
    let dependencies = super::super::go_dependencies::identity_sha256(&execution_root).unwrap();
    let runtime = runtime_identity_sha256(spec, &execution_root, &installed).unwrap();
    // This exercises the executor boundary, not a substitute project-model census.
    let mut plan = SemanticIndexerVariantPlan {
        identity: SemanticVariantId("qualified-input-boundary".to_string()),
        dimensions: BTreeMap::from([
            ("compiler_sdk_sha256".to_string(), sdk),
            ("compiler_dependencies_sha256".to_string(), dependencies),
            ("compiler_runtime_sha256".to_string(), runtime),
            (
                "compiler_dependency_projects".to_string(),
                r#"["go.mod"]"#.to_string(),
            ),
            ("source_snapshot_sha256".to_string(), before.clone()),
            ("project_model_census_sha256".to_string(), "a".repeat(64)),
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
    let inputs = GoIndexerRunInputs {
        spec,
        root: root.path(),
        installed: &installed,
        files: &files,
        required_documents: &files,
        recovery: &recovery,
        repository_content_sha256: &before,
        progress_root: None,
    };
    verify_discovered_world_inputs(&inputs, &execution_root, &plan).unwrap();
    verify_discovered_sdk_inputs(&inputs, &execution_root, std::slice::from_ref(&plan)).unwrap();
    verify_discovered_dependency_inputs(&inputs, &execution_root, std::slice::from_ref(&plan))
        .unwrap();
    let expected_diagnostic = match claim {
        StaleClaim::Sdk => {
            change_digest(plan.dimensions.get_mut("compiler_sdk_sha256").unwrap());
            "SDK inputs changed between project discovery"
        }
        StaleClaim::Dependencies => {
            change_digest(
                plan.dimensions
                    .get_mut("compiler_dependencies_sha256")
                    .unwrap(),
            );
            "dependency inputs changed between project discovery"
        }
        StaleClaim::MissingSdk => {
            plan.dimensions.remove("compiler_sdk_sha256");
            "compiler_sdk_sha256 input binding"
        }
    };
    let failure = run_required_go_indexer_variants(inputs, &[plan])
        .await
        .unwrap_err();

    assert_eq!(failure.indexer, Some(SemanticIndexerKind::Go));
    assert_eq!(
        failure.kind,
        SemanticIndexerRunFailureKind::InfrastructureFailed
    );
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::IntegrityVerification
    );
    assert!(failure.detail.contains(expected_diagnostic), "{failure:?}");
    assert!(
        failure.process.is_none(),
        "unexpected failed process: {failure:?}"
    );
    assert!(!execution_root.exists());
    assert!(!execution_root.parent().unwrap().exists());
    assert_eq!(
        repository_snapshot::repository_content_digest(root.path()).unwrap(),
        before
    );
    assert!(!root.path().join(INDEXER_TEMP_DIR).exists());
    assert!(!root.path().join(INDEXER_CACHE_DIR).exists());
    recovery.finish().unwrap();
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn qualified_executor_rejects_stale_sdk_claim_and_removes_owned_stage() {
    reject_stale_claim(StaleClaim::Sdk).await;
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn qualified_executor_rejects_stale_dependency_claim_and_removes_owned_stage() {
    reject_stale_claim(StaleClaim::Dependencies).await;
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn qualified_executor_cannot_downgrade_normal_census_with_missing_sdk_claim() {
    reject_stale_claim(StaleClaim::MissingSdk).await;
}
