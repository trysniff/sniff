use super::*;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

const TASK: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-frame-task.json");

fn task() -> IntentionalBoundaryFrameTask {
    serde_json::from_slice(TASK).unwrap()
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn committed_repository() -> tempfile::TempDir {
    let repository = tempfile::tempdir().unwrap();
    git(repository.path(), &["init", "--quiet"]);
    git(repository.path(), &["config", "user.name", "SniffBench"]);
    git(
        repository.path(),
        &["config", "user.email", "sniffbench@example.invalid"],
    );
    fs::write(
        repository.path().join("lib.js"),
        "export function value() { return 1; }\n",
    )
    .unwrap();
    git(repository.path(), &["add", "lib.js"]);
    git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
    repository
}

#[test]
fn materializes_a_complete_clean_immutable_checkout() {
    let task = task();
    let source = committed_repository();
    let state = tempfile::tempdir().unwrap();
    let destination = state.path().join("rank-0001");

    let outcome =
        materialize_intentional_boundary_repository_fixture(&task, 1, &destination, source.path())
            .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Completed(completed) = outcome else {
        panic!("committed fixture must materialize");
    };

    assert_eq!(completed.checkout_root, destination);
    assert_eq!(completed.artifact.population_rank, 1);
    assert_eq!(
        completed.artifact.repository,
        task.repositories[0].repository
    );
    assert_eq!(
        completed.artifact.revision,
        git(source.path(), &["rev-parse", "HEAD"])
    );
    assert_eq!(
        git(
            &completed.checkout_root,
            &["rev-parse", "--is-shallow-repository"]
        ),
        "false"
    );
    assert!(
        git(
            &completed.checkout_root,
            &["status", "--porcelain=v1", "--untracked-files=all"]
        )
        .is_empty()
    );
    validate_intentional_boundary_materialization(
        &task,
        &completed.artifact,
        &completed.checkout_root,
    )
    .unwrap();
}

#[test]
fn treats_a_successfully_cloned_repository_without_head_as_empty() {
    let task = task();
    let source = tempfile::tempdir().unwrap();
    git(source.path(), &["init", "--quiet"]);
    let state = tempfile::tempdir().unwrap();
    let destination = state.path().join("rank-0001");

    let outcome =
        materialize_intentional_boundary_repository_fixture(&task, 1, &destination, source.path())
            .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Excluded(exclusion) = outcome else {
        panic!("empty fixture must be excluded");
    };

    assert_eq!(
        exclusion.reason,
        IntentionalBoundaryMaterializationExclusionReason::EmptyRepository
    );
    assert!(!destination.exists());
    assert_eq!(exclusion.exclusion_sha256.len(), 64);
    validate_intentional_boundary_materialization_exclusion(&task, &exclusion).unwrap();

    let mut mismatched = exclusion.clone();
    mismatched.reason = IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible;
    let error =
        validate_intentional_boundary_materialization_exclusion(&task, &mismatched).unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryMaterializationErrorKind::InvalidInput
    );

    let mut tampered = exclusion;
    tampered.exclusion_sha256.push('0');
    let error =
        validate_intentional_boundary_materialization_exclusion(&task, &tampered).unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryMaterializationErrorKind::InvalidInput
    );
}

#[test]
fn refuses_unknown_ranks_existing_destinations_and_checkout_mutation() {
    let task = task();
    let source = committed_repository();
    let state = tempfile::tempdir().unwrap();
    let destination = state.path().join("rank-0001");

    let error =
        materialize_intentional_boundary_repository_fixture(&task, 0, &destination, source.path())
            .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryMaterializationErrorKind::InvalidInput
    );

    fs::create_dir(&destination).unwrap();
    let error =
        materialize_intentional_boundary_repository_fixture(&task, 1, &destination, source.path())
            .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryMaterializationErrorKind::InvalidInput
    );
    fs::remove_dir(&destination).unwrap();

    let outcome =
        materialize_intentional_boundary_repository_fixture(&task, 1, &destination, source.path())
            .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Completed(completed) = outcome else {
        panic!("committed fixture must materialize");
    };
    fs::write(destination.join("untracked.txt"), "tamper\n").unwrap();
    let error = validate_intentional_boundary_materialization(
        &task,
        &completed.artifact,
        &completed.checkout_root,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryMaterializationErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn preserves_a_definitive_not_found_probe_as_typed_status() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let count = stream.read(&mut request).unwrap();
        assert!(String::from_utf8_lossy(&request[..count]).starts_with("GET /repository "));
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });

    let status = probe_repository(&format!("http://{address}/repository"), None)
        .await
        .unwrap();
    server.join().unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);
}
