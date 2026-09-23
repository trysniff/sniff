use super::super::history_v3_materialization::materialize_historical_v3_candidate_from_url;
use super::super::{
    HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION, HistoricalV3CandidateCollectionManifest,
    HistoricalV3CandidateIdentity, HistoricalV3CandidateRepository, HistoricalV3Language,
    HistoricalV3MaterializationError, HistoricalV3MaterializationErrorKind, HistoricalV3Protocol,
    prepare_historical_v3_stream_task,
};
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
        "pub fn total(values: &[i32]) -> i32 { values.iter().copied().sum() }\n",
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
    git(&repository, &["commit", "-m", "simplify"]);
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
    let identity = HistoricalV3CandidateIdentity {
        language: HistoricalV3Language::Rust,
        repository_id: 14,
        pull_request_number: 7,
        base_commit: fixture.base.clone(),
        head_commit: fixture.head.clone(),
        merge_commit: fixture.merge.clone(),
    };
    let stream_task = prepare_historical_v3_stream_task(protocol, vec![identity.clone()]).unwrap();
    let manifest = super::super::history_v3_candidate_collection::seal_collection_manifest(
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
fn committed_materialization_resumes_without_executing_git_again() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let first = run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |destination| {
            materialize_historical_v3_candidate_from_url(
                &protocol,
                &collection,
                1,
                destination,
                fixture.repository.to_str().unwrap(),
            )
        },
    )
    .unwrap();
    assert!(matches!(
        first,
        HistoricalV3MaterializationStageRun::Completed { resumed: false, .. }
    ));
    let HistoricalV3MaterializationStageRun::Completed { roots, .. } = &first else {
        unreachable!();
    };
    fs::rename(
        roots.repository_root.join(".git"),
        roots.repository_root.join(".git-disabled"),
    )
    .unwrap();

    let resumed = run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |_| panic!("committed materialization must not execute again"),
    )
    .unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3MaterializationStageRun::Completed { resumed: true, .. }
    ));
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let journal = HistoricalV3RankJournal::open(state.path(), &identity).unwrap();
    assert_eq!(journal.history().len(), 1);
    assert_eq!(
        journal.next_stage(),
        Some(HistoricalV3RankStage::SourceCensus)
    );
}

#[test]
fn operational_failure_leaves_the_exact_rank_open_for_retry() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let error = run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |_| {
            Err(HistoricalV3MaterializationError {
                kind: HistoricalV3MaterializationErrorKind::InfrastructureUnavailable,
                detail: "network unavailable".to_string(),
            })
        },
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
    );
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let journal = HistoricalV3RankJournal::open(state.path(), &identity).unwrap();
    assert!(journal.history().is_empty());
    assert_eq!(
        journal.next_stage(),
        Some(HistoricalV3RankStage::Materialization)
    );
}

#[test]
fn stale_uncommitted_workspace_is_removed_before_exact_rank_retry() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let destination = rank_workspace(work.path(), &identity).unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("partial"), b"crash residue").unwrap();

    let outcome = run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |retry_destination| {
            assert_eq!(retry_destination, destination);
            assert!(!retry_destination.exists());
            materialize_historical_v3_candidate_from_url(
                &protocol,
                &collection,
                1,
                retry_destination,
                fixture.repository.to_str().unwrap(),
            )
        },
    )
    .unwrap();
    assert!(matches!(
        outcome,
        HistoricalV3MaterializationStageRun::Completed { resumed: false, .. }
    ));
}

#[test]
fn terminal_exclusion_is_committed_and_resumed_without_retry() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    git(
        &fixture.repository,
        &["update-ref", "refs/pull/7/head", &fixture.base],
    );
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let first = run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |destination| {
            materialize_historical_v3_candidate_from_url(
                &protocol,
                &collection,
                1,
                destination,
                fixture.repository.to_str().unwrap(),
            )
        },
    )
    .unwrap();
    assert!(matches!(
        &first,
        HistoricalV3MaterializationStageRun::Excluded { resumed: false, .. }
    ));
    let resumed = run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |_| panic!("terminal exclusion must not execute again"),
    )
    .unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3MaterializationStageRun::Excluded { resumed: true, .. }
    ));
    let proof =
        verify_historical_v3_terminal_exclusion(&protocol, &collection, 1, state.path()).unwrap();
    assert_eq!(proof.stage(), HistoricalV3RankStage::Materialization);
    assert_eq!(proof.rank().stream_rank, 1);
    assert!(matches!(
        super::super::evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            proof.rank().language(),
            &[super::super::HistoricalV3OrderedRankOutcome::Excluded(
                proof.clone()
            )],
        )
        .unwrap(),
        super::super::HistoricalV3OrderedStopStatus::FailedSourceExhausted {
            processed_ranks: 1,
            reviewed: 0,
            ..
        }
    ));
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let HistoricalV3MaterializationStageRun::Excluded { artifact, .. } = first else {
        unreachable!("validated exclusion outcome")
    };
    let forged_state = tempfile::tempdir().unwrap();
    let mut forged = HistoricalV3RankJournal::open(forged_state.path(), &identity).unwrap();
    forged
        .append(
            HistoricalV3RankStage::Materialization,
            HistoricalV3RankStageOutcome::Excluded {
                artifact_kind: HistoricalV3RankArtifactKind::MaterializationExclusion,
                artifact_sha256: "0".repeat(64),
            },
            Some(artifact.as_ref()),
        )
        .unwrap();
    drop(forged);
    let error =
        verify_historical_v3_terminal_exclusion(&protocol, &collection, 1, forged_state.path())
            .unwrap_err();
    assert!(error.detail.contains("artifact hash differs"));
    let journal = HistoricalV3RankJournal::open(state.path(), &identity).unwrap();
    assert_eq!(journal.next_stage(), None);
}

#[test]
fn tampered_artifact_and_cross_rank_identity_fail_closed() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let state = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    run_materialization_stage_with(
        &protocol,
        &collection,
        1,
        state.path(),
        work.path(),
        |destination| {
            materialize_historical_v3_candidate_from_url(
                &protocol,
                &collection,
                1,
                destination,
                fixture.repository.to_str().unwrap(),
            )
        },
    )
    .unwrap();
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let mut wrong = identity.clone();
    wrong.name_with_owner = "other/rust".to_string();
    let error = HistoricalV3RankJournal::open(state.path(), &wrong).unwrap_err();
    assert!(error.detail.contains("different rank identity"));

    let artifact = state
        .path()
        .join(&identity.stream_task_sha256)
        .join("rust")
        .join("rank-00000001")
        .join("01-materialization")
        .join("artifact.json");
    fs::write(&artifact, b"{}\n").unwrap();
    let error = HistoricalV3RankJournal::open(state.path(), &identity).unwrap_err();
    assert!(error.detail.contains("transaction commitment changed"));
}

#[test]
fn incomplete_checkpoint_publication_is_cleaned_on_open() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let state = tempfile::tempdir().unwrap();
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let task = state.path().join(&identity.stream_task_sha256);
    let language = task.join("rust");
    fs::create_dir_all(&language).unwrap();
    let incomplete = language.join(".rank-00000001.incomplete");
    fs::create_dir(&incomplete).unwrap();
    fs::write(incomplete.join("partial"), b"interrupted write").unwrap();

    let journal = HistoricalV3RankJournal::open(state.path(), &identity).unwrap();
    assert!(journal.history().is_empty());
    assert!(!incomplete.exists());
}

#[test]
fn checkpoint_chain_rejects_skips_identity_changes_and_terminal_successors() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let artifact_sha256 = "b".repeat(64);
    let materialization = append_historical_v3_rank_checkpoint(
        &[],
        &identity,
        HistoricalV3RankStage::Materialization,
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::Materialization,
            artifact_sha256: artifact_sha256.clone(),
        },
    )
    .unwrap();
    let history = vec![materialization];
    let error = append_historical_v3_rank_checkpoint(
        &history,
        &identity,
        HistoricalV3RankStage::SemanticCensus,
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::SemanticCensus,
            artifact_sha256: artifact_sha256.clone(),
        },
    )
    .unwrap_err();
    assert!(error.contains("out of order"));

    let mut wrong_identity = identity.clone();
    wrong_identity.name_with_owner = "other/rust".to_string();
    let error = append_historical_v3_rank_checkpoint(
        &history,
        &wrong_identity,
        HistoricalV3RankStage::SourceCensus,
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::SourceCensusExclusion,
            artifact_sha256,
        },
    )
    .unwrap_err();
    assert!(error.contains("identity changed"));

    let exclusion = append_historical_v3_rank_checkpoint(
        &history,
        &identity,
        HistoricalV3RankStage::SourceCensus,
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::SourceCensusExclusion,
            artifact_sha256: "c".repeat(64),
        },
    )
    .unwrap();
    let error = append_historical_v3_rank_checkpoint(
        &[history[0].clone(), exclusion],
        &identity,
        HistoricalV3RankStage::SemanticCensus,
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::SemanticCensus,
            artifact_sha256: "d".repeat(64),
        },
    )
    .unwrap_err();
    assert!(error.contains("terminal rank checkpoint cannot be extended"));
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
