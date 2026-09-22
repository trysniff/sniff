use super::super::{
    HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION, HistoricalV3CandidateCollectionManifest,
    HistoricalV3CandidateIdentity, HistoricalV3CandidateRepository, HistoricalV3Language,
    HistoricalV3Protocol, prepare_historical_v3_stream_task,
};
use super::runtime::materialize_historical_v3_candidate_from_url;
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct GitFixture {
    _root: tempfile::TempDir,
    repository: PathBuf,
    base: String,
    head: String,
    merge: String,
}

fn fixture() -> GitFixture {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("source");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-b", "main"]);
    git(&repository, &["config", "user.name", "Sniff Test"]);
    git(&repository, &["config", "user.email", "sniff-test@invalid"]);
    fs::create_dir(repository.join("src")).unwrap();
    fs::write(
        repository.join("src/lib.rs"),
        "pub fn total(values: &[i32]) -> i32 {\n    let mut total = 0;\n    for value in values {\n        total += value;\n    }\n    total\n}\n",
    )
    .unwrap();
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "base"]);
    let base = git_text(&repository, &["rev-parse", "HEAD"]);

    git(&repository, &["checkout", "-b", "feature"]);
    fs::write(
        repository.join("src/lib.rs"),
        "pub fn total(values: &[i32]) -> i32 { values.iter().sum() }\n",
    )
    .unwrap();
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "simplify total"]);
    let head = git_text(&repository, &["rev-parse", "HEAD"]);
    git(&repository, &["update-ref", "refs/pull/7/head", &head]);

    git(&repository, &["checkout", "main"]);
    git(
        &repository,
        &["merge", "--no-ff", "feature", "-m", "merge feature"],
    );
    let merge = git_text(&repository, &["rev-parse", "HEAD"]);
    GitFixture {
        _root: root,
        repository,
        base,
        head,
        merge,
    }
}

fn protocol() -> HistoricalV3Protocol {
    use super::super::history_v3_source_binding::tests as source_fixture;

    let fixtures = source_fixture::fixtures();
    let prior = source_fixture::prior_identity_seal();
    source_fixture::protocol(&prior, &fixtures)
}

fn collection(
    protocol: &HistoricalV3Protocol,
    fixture: &GitFixture,
) -> HistoricalV3CandidateCollection {
    collection_with_identity(
        protocol,
        HistoricalV3CandidateIdentity {
            language: HistoricalV3Language::Rust,
            repository_id: 14,
            pull_request_number: 7,
            base_commit: fixture.base.clone(),
            head_commit: fixture.head.clone(),
            merge_commit: fixture.merge.clone(),
        },
    )
}

fn collection_with_identity(
    protocol: &HistoricalV3Protocol,
    identity: HistoricalV3CandidateIdentity,
) -> HistoricalV3CandidateCollection {
    let stream_task = prepare_historical_v3_stream_task(protocol, vec![identity.clone()]).unwrap();
    let manifest =
        super::super::history_v3_candidate_collection::seal_collection_manifest(
            HistoricalV3CandidateCollectionManifest {
                schema_version: HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION,
                manifest_contract: "sniffbench-historical-v3-candidate-manifest-v1".to_string(),
                protocol_sha256: protocol.protocol_sha256.clone(),
                source_binding_audit_sha256: "a".repeat(64),
                query_document_sha256:
                    super::super::history_v3_candidate_collection::historical_v3_candidate_query_sha256_for_tests(),
                repositories: vec![HistoricalV3CandidateRepository {
                    language: HistoricalV3Language::Rust,
                    repository_id: 14,
                    name_with_owner: "fresh/rust".to_string(),
                }],
                partitions: Vec::new(),
                page_checkpoint_sha256s: Vec::new(),
                candidate_count: 1,
                stream_task,
                manifest_sha256: String::new(),
            },
        )
        .unwrap();
    HistoricalV3CandidateCollection {
        manifest,
        candidates: vec![identity],
    }
}

#[test]
fn materializes_exact_revisions_and_replays_patch_identity() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let output = tempfile::tempdir().unwrap();
    let destination = output.path().join("rank-1");
    let outcome = materialize_historical_v3_candidate_from_url(
        &protocol,
        &collection,
        1,
        &destination,
        fixture.repository.to_str().unwrap(),
    )
    .unwrap();
    let HistoricalV3MaterializationOutcome::Completed { artifact, roots } = outcome else {
        panic!("expected completed materialization");
    };
    assert!(artifact.patch_byte_count > 0);
    assert!(artifact.merge_parent_commits.contains(&fixture.base));
    assert!(artifact.merge_parent_commits.contains(&fixture.head));
    validate_historical_v3_materialization(&protocol, &collection, &artifact, &roots).unwrap();

    let mut changed = artifact.clone();
    changed.patch_sha256 = "0".repeat(64);
    assert!(
        validate_historical_v3_materialization_commitment(&protocol, &collection, &changed)
            .unwrap_err()
            .detail
            .contains("commitment changed")
    );

    fs::write(
        roots.reproduced_root.join("src/lib.rs"),
        "pub fn total(_: &[i32]) -> i32 { 999 }\n",
    )
    .unwrap();
    assert!(
        validate_historical_v3_materialization(&protocol, &collection, &artifact, &roots)
            .unwrap_err()
            .detail
            .contains("patch changed")
    );
    git(&roots.reproduced_root, &["checkout", "--", "."]);

    fs::write(&roots.patch_path, b"tampered patch").unwrap();
    assert!(
        validate_historical_v3_materialization(&protocol, &collection, &artifact, &roots)
            .unwrap_err()
            .detail
            .contains("patch changed")
    );
}

#[test]
fn changed_pull_head_is_a_bound_terminal_exclusion() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    git(
        &fixture.repository,
        &["update-ref", "refs/pull/7/head", &fixture.base],
    );
    let output = tempfile::tempdir().unwrap();
    let destination = output.path().join("rank-1");
    let outcome = materialize_historical_v3_candidate_from_url(
        &protocol,
        &collection,
        1,
        &destination,
        fixture.repository.to_str().unwrap(),
    )
    .unwrap();
    let HistoricalV3MaterializationOutcome::Excluded(exclusion) = outcome else {
        panic!("expected terminal exclusion");
    };
    assert_eq!(
        exclusion.reason,
        HistoricalV3MaterializationExclusionReason::PullRequestHeadChanged
    );
    validate_historical_v3_materialization_exclusion(&protocol, &collection, &exclusion).unwrap();
    assert!(!destination.exists());
}

#[test]
fn unavailable_revision_is_excluded_without_retaining_partial_state() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection_with_identity(
        &protocol,
        HistoricalV3CandidateIdentity {
            language: HistoricalV3Language::Rust,
            repository_id: 14,
            pull_request_number: 7,
            base_commit: fixture.base.clone(),
            head_commit: fixture.head.clone(),
            merge_commit: "0".repeat(40),
        },
    );
    let output = tempfile::tempdir().unwrap();
    let destination = output.path().join("rank-1");
    let outcome = materialize_historical_v3_candidate_from_url(
        &protocol,
        &collection,
        1,
        &destination,
        fixture.repository.to_str().unwrap(),
    )
    .unwrap();
    let HistoricalV3MaterializationOutcome::Excluded(exclusion) = outcome else {
        panic!("expected terminal exclusion");
    };
    let HistoricalV3MaterializationExclusionEvidence::RevisionUnavailable { missing } =
        &exclusion.evidence
    else {
        panic!("expected unavailable-revision evidence");
    };
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].kind, HistoricalV3RevisionKind::Merge);
    assert_eq!(missing[0].revision, "0".repeat(40));
    assert_ne!(missing[0].fetch.exit_code, Some(0));
    validate_historical_v3_materialization_exclusion(&protocol, &collection, &exclusion).unwrap();
    assert!(!destination.exists());
}

#[test]
fn forged_candidate_manifest_fails_before_creating_a_destination() {
    let fixture = fixture();
    let protocol = protocol();
    let mut collection = collection(&protocol, &fixture);
    collection.manifest.candidate_count = 2;
    let output = tempfile::tempdir().unwrap();
    let destination = output.path().join("rank-1");
    let error = materialize_historical_v3_candidate_from_url(
        &protocol,
        &collection,
        1,
        &destination,
        fixture.repository.to_str().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV3MaterializationErrorKind::InvalidInput
    );
    assert!(!destination.exists());
}

#[test]
fn detached_candidate_payload_fails_before_creating_a_destination() {
    let fixture = fixture();
    let protocol = protocol();
    let mut collection = collection(&protocol, &fixture);
    collection.candidates[0].head_commit = "f".repeat(40);
    let output = tempfile::tempdir().unwrap();
    let destination = output.path().join("rank-1");
    let error = materialize_historical_v3_candidate_from_url(
        &protocol,
        &collection,
        1,
        &destination,
        fixture.repository.to_str().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV3MaterializationErrorKind::InvalidInput
    );
    assert!(error.detail.contains("collection payload changed"));
    assert!(!destination.exists());
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_text(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
