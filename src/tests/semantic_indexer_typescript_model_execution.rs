use super::*;
use crate::sandbox::SandboxOutput;

fn spec() -> PinnedIndexer {
    pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap()
}

fn output(status_code: Option<i32>) -> SandboxOutput {
    let stdout = "{\"partial\":true}".to_string();
    let stderr = "compiler diagnostic\n".to_string();
    SandboxOutput {
        status_code,
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stdout,
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    }
}

#[test]
fn rejected_compiler_retains_process_through_every_post_execution_guard() {
    for guards in [
        [Err("runtime changed".into()), Ok(()), Ok(())],
        [Ok(()), Err("snapshot changed".into()), Ok(())],
        [Ok(()), Ok(()), Err("installation changed".into())],
        [
            Err("runtime changed".into()),
            Err("snapshot changed".into()),
            Err("installation changed".into()),
        ],
    ] {
        let output = output(Some(2));
        let expected = process_evidence(output.clone());
        let diagnostics = guards
            .iter()
            .filter_map(|guard| guard.as_ref().err().cloned())
            .collect::<Vec<_>>();
        let failure = validate_execution(spec(), Ok(output), guards).unwrap_err();
        assert_eq!(
            failure.phase,
            SemanticIndexerRunPhase::IntegrityVerification
        );
        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::InfrastructureFailed
        );
        assert_eq!(
            failure.indexer,
            Some(SemanticIndexerKind::TypeScriptJavaScript)
        );
        assert_eq!(failure.process.as_deref(), Some(&expected));
        assert!(
            failure
                .detail
                .starts_with("TypeScript compiler project census failed")
        );
        for diagnostic in diagnostics {
            assert!(failure.detail.contains(&diagnostic));
        }
    }
}

#[test]
fn successful_compiler_with_failed_guard_keeps_output_but_never_returns_plans() {
    for guards in [
        [Err("runtime changed".into()), Ok(()), Ok(())],
        [Ok(()), Err("snapshot changed".into()), Ok(())],
        [Ok(()), Ok(()), Err("installation changed".into())],
        [
            Err("runtime changed".into()),
            Err("snapshot changed".into()),
            Err("installation changed".into()),
        ],
    ] {
        let output = output(Some(0));
        let expected = process_evidence(output.clone());
        let failure = validate_execution(spec(), Ok(output), guards).unwrap_err();
        assert_eq!(
            failure.phase,
            SemanticIndexerRunPhase::IntegrityVerification
        );
        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::InfrastructureFailed
        );
        assert_eq!(failure.process.as_deref(), Some(&expected));
    }
}

#[test]
fn resource_limits_and_missing_status_cannot_become_success() {
    for (status, timed_out, memory, processes) in [
        (Some(2), false, false, false),
        (None, false, false, false),
        (Some(0), true, false, false),
        (Some(0), false, true, false),
        (Some(0), false, false, true),
    ] {
        let mut output = output(status);
        output.timed_out = timed_out;
        output.memory_limit_exceeded = memory;
        output.process_limit_exceeded = processes;
        let expected = process_evidence(output.clone());
        let failure = validate_execution(spec(), Ok(output), [Ok(()), Ok(()), Ok(())]).unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::Execution);
        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::RepositoryRejected
        );
        assert_eq!(failure.process.as_deref(), Some(&expected));
    }
}

#[test]
fn failed_worker_and_all_guards_keep_diagnostics_without_inventing_output() {
    let failure = validate_execution(
        spec(),
        Err("sandbox could not start".into()),
        [
            Err("runtime unavailable".into()),
            Err("snapshot unavailable".into()),
            Err("installation unavailable".into()),
        ],
    )
    .unwrap_err();
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::IntegrityVerification
    );
    assert!(failure.process.is_none());
    assert_eq!(
        failure.detail,
        "sandbox could not start; additionally, runtime unavailable; additionally, snapshot unavailable; additionally, installation unavailable"
    );
}

#[test]
fn valid_guards_leave_success_and_startup_failure_unchanged() {
    let expected = output(Some(0));
    let result =
        validate_execution(spec(), Ok(expected.clone()), [Ok(()), Ok(()), Ok(())]).unwrap();
    assert_eq!(result, expected);
    let failure = validate_execution(
        spec(),
        Err("sandbox could not start".into()),
        [Ok(()), Ok(()), Ok(())],
    )
    .unwrap_err();
    assert_eq!(failure.phase, SemanticIndexerRunPhase::Execution);
    assert_eq!(
        failure.kind,
        SemanticIndexerRunFailureKind::InfrastructureFailed
    );
    assert_eq!(failure.detail, "sandbox could not start");
    assert!(failure.process.is_none());
}

#[test]
fn malformed_model_output_keeps_successful_process_evidence() {
    for stdout in ["not JSON", "{\"partial\":true}"] {
        let mut output = output(Some(0));
        output.stdout = stdout.to_string();
        output.stdout_sha256 = format!("{:x}", Sha256::digest(stdout.as_bytes()));
        let expected = process_evidence(output.clone());
        let output = validate_execution(spec(), Ok(output), [Ok(()), Ok(()), Ok(())]).unwrap();
        let failure = validate_output(spec(), output, |stdout| {
            plans_from_output(stdout, &[], &[], &"a".repeat(64), &"b".repeat(64), |_| {
                panic!("empty configuration and source scopes must not request files")
            })
        })
        .unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::InfrastructureFailed
        );
        assert_eq!(failure.process.as_deref(), Some(&expected));
        assert!(!failure.detail.is_empty());
    }
}

#[test]
fn cleanup_failure_after_success_retains_process_and_discards_result() {
    let output = output(Some(0));
    let expected = process_evidence(output.clone());
    let result = validate_output(spec(), output, |_| Ok(42));
    let cleanup = model_failure(spec(), SemanticIndexerRunPhase::Cleanup, "cleanup failed");
    let failure = finish_discovery(result, Err(cleanup)).unwrap_err();
    assert_eq!(failure.phase, SemanticIndexerRunPhase::Cleanup);
    assert_eq!(failure.process.as_deref(), Some(&expected));
    assert_eq!(failure.detail, "cleanup failed");
}

#[test]
fn cleanup_failure_after_rejection_keeps_compiler_and_all_diagnostics() {
    let output = output(Some(2));
    let expected = process_evidence(output.clone());
    let result = validate_execution(
        spec(),
        Ok(output),
        [Err("runtime changed".into()), Ok(()), Ok(())],
    )
    .and_then(|output| validate_output(spec(), output, |_| Ok(42)));
    let cleanup = model_failure(spec(), SemanticIndexerRunPhase::Cleanup, "cleanup failed");
    let failure = finish_discovery(result, Err(cleanup)).unwrap_err();
    assert_eq!(failure.phase, SemanticIndexerRunPhase::Cleanup);
    assert_eq!(failure.process.as_deref(), Some(&expected));
    assert!(failure.detail.contains("compiler project census failed"));
    assert!(failure.detail.contains("runtime changed"));
    assert!(failure.detail.ends_with("cleanup failed"));
}

#[test]
fn completed_discovery_returns_result_only_after_successful_cleanup() {
    let result = validate_output(spec(), output(Some(0)), |_| Ok(42));
    assert_eq!(finish_discovery(result, Ok(())).unwrap(), 42);
}

#[test]
fn cleanup_with_own_process_keeps_its_primary_evidence() {
    let result = validate_output(spec(), output(Some(0)), |_| Ok(42));
    let mut cleanup = model_failure(spec(), SemanticIndexerRunPhase::Cleanup, "cleanup failed");
    let expected = process_evidence(output(Some(3)));
    cleanup.process = Some(Box::new(expected.clone()));
    let failure = finish_discovery(result, Err(cleanup)).unwrap_err();
    assert_eq!(failure.phase, SemanticIndexerRunPhase::Cleanup);
    assert_eq!(failure.process.as_deref(), Some(&expected));
}
