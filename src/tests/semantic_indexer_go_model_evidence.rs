use super::*;
use crate::sandbox::SandboxOutput;
use tempfile::TempDir;

fn spec() -> PinnedIndexer {
    pinned_indexer(SemanticIndexerKind::Go).unwrap()
}

fn output(stdout: &str) -> SandboxOutput {
    let stderr = "source census diagnostic\n".to_string();
    SandboxOutput {
        status_code: Some(0),
        stdout: stdout.to_string(),
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    }
}

fn platforms() -> &'static str {
    r#"[{"GOOS":"linux","GOARCH":"amd64","CgoSupported":true,"FirstClass":true}]"#
}

#[test]
fn malformed_platform_domain_keeps_its_own_output_before_any_source_query() {
    for stdout in ["not JSON", "[]", r#"[{"GOOS":"linux"}]"#] {
        let output = output(stdout);
        let expected = process_evidence(output.clone());
        let failure = platform_domain(spec(), output).unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        assert_eq!(failure.process.as_deref(), Some(&expected));
    }
    let output = output(platforms());
    let expected = process_evidence(output.clone());
    let (domain, witness) = platform_domain(spec(), output).unwrap();
    assert_eq!(domain, platforms());
    assert_eq!(witness, expected);
}

#[test]
fn malformed_constraints_and_unbounded_domains_retain_helper_not_platform_output() {
    let sources = vec!["main.go".to_string()];
    let tags = (0..20)
        .map(|i| format!("feature{i:02}"))
        .collect::<Vec<_>>();
    let facts = serde_json::json!({
        "schema_version": 2,
        "files": [{
            "repository_path": "main.go",
            "tags": tags,
            "package_name": "model",
            "go_generate_directives": []
        }]
    });
    for stdout in ["not JSON".to_string(), facts.to_string()] {
        let output = output(&stdout);
        let expected = process_evidence(output.clone());
        let failure = source_contexts(spec(), output, &sources, platforms()).unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        assert_eq!(failure.process.as_deref(), Some(&expected));
        if stdout != "not JSON" {
            assert!(failure.detail.contains("strict limit"), "{failure:?}");
        }
    }
}

#[test]
fn invalid_package_world_keeps_exact_package_command_output() {
    let root = TempDir::new().unwrap();
    let module = super::super::go_model_output::ModuleIdentity {
        path: "example.test/model".to_string(),
        project: RepositoryPath("go.mod".to_string()),
    };
    let context = contexts(
        platforms(),
        &GoConstraintTagDomain {
            custom_build_tags: Vec::new(),
            architecture_feature_tags: Vec::new(),
            standalone_source_repository_paths: Vec::new(),
        },
    )
    .unwrap()
    .remove(0);
    let output = output("not JSON");
    let expected = process_evidence(output.clone());
    let failure = validate_model_output(spec(), output, |stdout| {
        parse_world(
            root.path(),
            module,
            context,
            BTreeMap::new(),
            &BTreeSet::from([RepositoryPath("main.go".to_string())]),
            stdout,
        )
    })
    .unwrap_err();
    assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
    assert_eq!(failure.process.as_deref(), Some(&expected));
}

#[tokio::test]
#[ignore = "requires the checksum-pinned scip-go runtime, Go compiler and native sandbox"]
async fn normal_discovery_validation_keeps_real_constraint_output_and_cleans_stage() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.test/model\ngo 1.23\n",
    )
    .unwrap();
    fs::write(
        root.path().join("main.go"),
        "//go:build race\n\npackage model\nfunc value() int { return 1 }\n",
    )
    .unwrap();
    let file =
        crate::parser::parse_file_checked(root.path().join("main.go").to_str().unwrap()).unwrap();
    let files = [file];
    let before = repository_snapshot::repository_content_digest(root.path()).unwrap();
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
    assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
    assert_eq!(
        failure.kind,
        SemanticIndexerRunFailureKind::IncompleteOutput
    );
    assert!(
        failure
            .detail
            .contains("unsupported compiler build mode tag race")
    );
    let process = failure
        .process
        .as_ref()
        .expect("lost real constraint command");
    assert_eq!(process.status_code, Some(0));
    assert!(!process.timed_out);
    assert!(!process.memory_limit_exceeded);
    assert!(!process.process_limit_exceeded);
    assert!(process.stdout.contains("race"));
    assert_eq!(
        process.stdout_sha256,
        format!("{:x}", Sha256::digest(process.stdout.as_bytes()))
    );
    assert_eq!(
        process.stderr_sha256,
        format!("{:x}", Sha256::digest(process.stderr.as_bytes()))
    );
    assert!(!execution_root.exists());
    assert!(!execution_root.parent().unwrap().exists());
    assert_eq!(
        repository_snapshot::repository_content_digest(root.path()).unwrap(),
        before
    );
    recovery.finish().unwrap();
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}
