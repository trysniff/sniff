use super::*;
use crate::sandbox::SandboxOutput;
use tempfile::TempDir;

fn output(stdout: &str) -> SandboxOutput {
    let stderr = "compiler context diagnostic\n".to_string();
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

fn spec() -> PinnedIndexer {
    pinned_indexer(SemanticIndexerKind::Go).unwrap()
}

#[test]
fn module_validation_retains_actual_record_for_json_and_ownership_errors() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("go.mod"), "module example.test/model\n").unwrap();
    fs::write(root.path().join("other.mod"), "module example.test/other\n").unwrap();
    let project = RepositoryPath("go.mod".to_string());
    let module = GoListModule {
        path: "example.test/model".to_string(),
        version: String::new(),
        dir: root.path().to_str().unwrap().to_string(),
        go_mod: root.path().join("other.mod").to_str().unwrap().to_string(),
        main: true,
    };
    for stdout in [
        "not JSON".to_string(),
        serde_json::to_string(&module).unwrap(),
    ] {
        let output = output(&stdout);
        let expected = process_evidence(output.clone());
        let failure = validate_model_output(spec(), output, |stdout| {
            validate_module(stdout, root.path(), &project)
        })
        .unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::IncompleteOutput
        );
        assert_eq!(failure.indexer, Some(SemanticIndexerKind::Go));
        assert_eq!(failure.process.as_deref(), Some(&expected));
        if stdout != "not JSON" {
            assert!(failure.detail.contains("exact manifest ownership"));
        }
    }
}

#[test]
fn environment_validation_retains_record_for_invalid_missing_extra_and_changed_values() {
    let explicit = BTreeMap::from([("GOOS".to_string(), "linux".to_string())]);
    let names = BTreeSet::from(["GOOS".to_string(), "GOAMD64".to_string()]);
    for stdout in [
        "not JSON",
        r#"{"GOOS":null,"GOAMD64":"v1"}"#,
        r#"{"GOOS":"linux"}"#,
        r#"{"GOOS":"linux","GOAMD64":"v1","unexpected":"extra"}"#,
        r#"{"GOOS":"windows","GOAMD64":"v1"}"#,
    ] {
        let output = output(stdout);
        let expected = process_evidence(output.clone());
        let failure = validate_model_output(spec(), output, |stdout| {
            validate_environment(stdout, &names, &explicit)
        })
        .unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        assert_eq!(failure.process.as_deref(), Some(&expected));
    }
}

#[test]
fn validated_module_and_environment_keep_values_and_witnesses() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("go.mod"), "module example.test/model\n").unwrap();
    let project = RepositoryPath("go.mod".to_string());
    let module = GoListModule {
        path: "example.test/model".to_string(),
        version: String::new(),
        dir: root.path().to_str().unwrap().to_string(),
        go_mod: root.path().join("go.mod").to_str().unwrap().to_string(),
        main: true,
    };
    let output = output(&serde_json::to_string(&module).unwrap());
    let expected = process_evidence(output.clone());
    let (identity, process) = validate_model_output(spec(), output, |stdout| {
        validate_module(stdout, root.path(), &project)
    })
    .unwrap();
    assert_eq!(identity.path, module.path);
    assert_eq!(identity.project, project);
    assert_eq!(process, expected);

    let explicit = BTreeMap::from([("GOOS".to_string(), "linux".to_string())]);
    let names = BTreeSet::from(["GOOS".to_string(), "GOAMD64".to_string()]);
    let output = self::output(r#"{"GOOS":"linux","GOAMD64":"v1"}"#);
    let expected = process_evidence(output.clone());
    let (environment, process) = validate_model_output(spec(), output, |stdout| {
        validate_environment(stdout, &names, &explicit)
    })
    .unwrap();
    assert_eq!(environment["GOOS"], "linux");
    assert_eq!(environment["GOAMD64"], "v1");
    assert_eq!(process, expected);
}
