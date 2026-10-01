use super::*;
use sha2::{Digest, Sha256};

fn process(label: &str) -> Box<SemanticIndexerProcessEvidence> {
    let stdout = format!("partial {label}");
    let stderr = format!("failed {label}");
    Box::new(SemanticIndexerProcessEvidence {
        status_code: Some(101),
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stdout,
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    })
}

fn error(
    phase: SemanticIndexerRunPhase,
    process: Option<Box<SemanticIndexerProcessEvidence>>,
    detail: &str,
) -> SemanticIndexerRunFailure {
    SemanticIndexerRunFailure {
        kind: if phase == SemanticIndexerRunPhase::Execution {
            SemanticIndexerRunFailureKind::IncompleteOutput
        } else {
            SemanticIndexerRunFailureKind::InfrastructureFailed
        },
        phase,
        indexer: Some(SemanticIndexerKind::Go),
        detail: detail.to_string(),
        process,
    }
}

#[test]
fn secondary_integrity_failure_retains_failed_process_bytes_hashes_and_limits() {
    for (timed_out, memory_limit_exceeded, process_limit_exceeded) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let mut expected = process("compiler");
        expected.timed_out = timed_out;
        expected.memory_limit_exceeded = memory_limit_exceeded;
        expected.process_limit_exceeded = process_limit_exceeded;
        if timed_out || memory_limit_exceeded || process_limit_exceeded {
            expected.status_code = None;
        }
        let execution = error(
            SemanticIndexerRunPhase::Execution,
            Some(expected.clone()),
            "compiler execution failed",
        );
        let integrity = error(
            SemanticIndexerRunPhase::IntegrityVerification,
            None,
            "SDK inputs changed",
        );
        let result =
            combine_typed_run_and_integrity::<()>(Err(execution), Err(integrity)).unwrap_err();
        assert_eq!(result.phase, SemanticIndexerRunPhase::IntegrityVerification);
        assert_eq!(
            result.kind,
            SemanticIndexerRunFailureKind::InfrastructureFailed
        );
        assert_eq!(result.process, Some(expected));
        assert_eq!(
            result.detail,
            "compiler execution failed; additionally, SDK inputs changed"
        );
    }
}

#[test]
fn successive_integrity_and_cleanup_errors_keep_original_process_evidence() {
    let expected = process("preparation");
    let execution = error(
        SemanticIndexerRunPhase::Preparation,
        Some(expected.clone()),
        "preparation failed",
    );
    let integrity = error(
        SemanticIndexerRunPhase::IntegrityVerification,
        None,
        "dependency inputs changed",
    );
    let result = combine_typed_run_and_integrity::<()>(Err(execution), Err(integrity));
    let cleanup = error(SemanticIndexerRunPhase::Cleanup, None, "cleanup failed");
    let result = combine_typed_run_and_integrity(result, Err(cleanup)).unwrap_err();
    assert_eq!(result.phase, SemanticIndexerRunPhase::Cleanup);
    assert_eq!(result.process, Some(expected));
    assert_eq!(
        result.detail,
        "preparation failed; additionally, dependency inputs changed; additionally, cleanup failed"
    );
}

#[test]
fn integrity_error_with_own_process_keeps_its_primary_process_evidence() {
    let execution = error(
        SemanticIndexerRunPhase::Execution,
        Some(process("compiler")),
        "compiler failed",
    );
    let expected = process("integrity");
    let integrity = error(
        SemanticIndexerRunPhase::IntegrityVerification,
        Some(expected.clone()),
        "integrity process failed",
    );
    let result = combine_typed_run_and_integrity::<()>(Err(execution), Err(integrity)).unwrap_err();
    assert_eq!(result.process, Some(expected));
    assert_eq!(result.phase, SemanticIndexerRunPhase::IntegrityVerification);
}

#[test]
fn single_failure_is_unchanged_and_successful_work_does_not_invent_processes() {
    let execution = error(
        SemanticIndexerRunPhase::Execution,
        Some(process("compiler")),
        "compiler failed",
    );
    assert_eq!(
        combine_typed_run_and_integrity::<()>(Err(execution.clone()), Ok(())).unwrap_err(),
        execution
    );
    let integrity = error(
        SemanticIndexerRunPhase::IntegrityVerification,
        None,
        "changed",
    );
    assert_eq!(
        combine_typed_run_and_integrity(Ok(()), Err(integrity.clone())).unwrap_err(),
        integrity
    );
    assert_eq!(combine_typed_run_and_integrity(Ok(17), Ok(())).unwrap(), 17);
}
