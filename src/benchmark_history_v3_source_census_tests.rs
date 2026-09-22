use super::super::history_v3_materialization::materialize_historical_v3_candidate_from_url;
use super::super::history_v3_rank_journal::run_materialization_stage_with;
use super::super::{
    HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3CandidateCollectionManifest, HistoricalV3CandidateIdentity,
    HistoricalV3CandidateRepository, HistoricalV3Language, HistoricalV3MaterializationStageRun,
    HistoricalV3Protocol, HistoricalV3RankJournal, HistoricalV3SourceSnapshotEvidence,
    IntentionalBoundarySourceCensusFailureEvidence, prepare_historical_v3_stream_task,
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

fn fixture(base_source: Option<&str>, merged_source: &str) -> GitFixture {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("source");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-b", "main"]);
    git(&repository, &["config", "user.name", "Sniff Test"]);
    git(&repository, &["config", "user.email", "sniff-test@invalid"]);
    fs::write(repository.join("README.md"), "fixture\n").unwrap();
    if let Some(source) = base_source {
        fs::create_dir(repository.join("src")).unwrap();
        fs::write(repository.join("src/lib.rs"), source).unwrap();
    }
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "base"]);
    let base = git_text(&repository, &["rev-parse", "HEAD"]);

    git(&repository, &["checkout", "-b", "feature"]);
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(repository.join("src/lib.rs"), merged_source).unwrap();
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "change source"]);
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

fn materialize(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    fixture: &GitFixture,
    journal: &Path,
    workspace: &Path,
) {
    let outcome = run_materialization_stage_with(
        protocol,
        collection,
        1,
        journal,
        workspace,
        |destination| {
            materialize_historical_v3_candidate_from_url(
                protocol,
                collection,
                1,
                destination,
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
fn commits_both_source_snapshots_and_resumes_without_git() {
    let fixture = fixture(
        Some("pub fn total(values: &[i32]) -> i32 { values.iter().copied().sum() }\n"),
        "pub fn total(values: &[i32]) -> i32 { values.iter().sum() }\n",
    );
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    materialize(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );

    let first = run_historical_v3_source_census_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    let HistoricalV3SourceCensusStageRun::Completed {
        artifact,
        resumed: false,
    } = first
    else {
        panic!("supported source snapshots must complete");
    };
    assert_eq!(artifact.base.source_census.source_file_count, 1);
    assert_eq!(artifact.merge.source_census.source_file_count, 1);
    assert_eq!(artifact.base.source_census.method_count, 1);
    assert_eq!(artifact.merge.source_census.method_count, 1);

    let identity = super::super::historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let destination =
        super::super::history_v3_rank_journal::rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed = run_historical_v3_source_census_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3SourceCensusStageRun::Completed { resumed: true, .. }
    ));
}

#[test]
fn inspects_both_sides_before_terminal_source_exclusion() {
    let fixture = fixture(
        None,
        "pub fn added(values: &[i32]) -> i32 { values.iter().sum() }\n",
    );
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    materialize(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );

    let outcome = run_historical_v3_source_census_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    let HistoricalV3SourceCensusStageRun::Excluded { artifact, .. } = outcome else {
        panic!("source-free base must exclude the rank");
    };
    assert!(matches!(
        artifact.sides[0],
        HistoricalV3SourceSnapshotEvidence::Excluded {
            reason: HistoricalV3SourceCensusExclusionReason::NoSupportedSources,
            ..
        }
    ));
    assert!(matches!(
        artifact.sides[1],
        HistoricalV3SourceSnapshotEvidence::Completed {
            ref snapshot,
        } if snapshot.source_census.source_file_count == 1
            && snapshot.source_census.method_count == 1
    ));

    let mut artifact = *artifact;
    let (side, revision, inventory) = match &artifact.sides[0] {
        HistoricalV3SourceSnapshotEvidence::Excluded {
            side,
            revision,
            inventory,
            ..
        } => (*side, revision.clone(), inventory.clone()),
        HistoricalV3SourceSnapshotEvidence::Completed { .. } => unreachable!(),
    };
    let ordinary_entry = &inventory.tracked_entries[0];
    let false_gitlink = IntentionalBoundarySourceCensusFailureEvidence::RepositoryContainsGitlink {
        repository_path: ordinary_entry.repository_path.clone(),
        object_id: ordinary_entry.object_id.clone(),
    };
    artifact.sides[0] = HistoricalV3SourceSnapshotEvidence::Excluded {
        side,
        revision,
        inventory,
        reason: HistoricalV3SourceCensusExclusionReason::UnsupportedProjectShape,
        failures: vec![false_gitlink],
    };
    artifact = super::commitment::seal_source_exclusion(artifact).unwrap();
    let identity = super::super::historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    let materialization = persisted.history()[0]
        .read_artifact::<super::super::HistoricalV3Materialization>()
        .unwrap()
        .unwrap();
    let error = validate_historical_v3_source_census_exclusion(
        &protocol,
        &collection,
        &materialization,
        &artifact,
    )
    .unwrap_err();
    assert!(error.contains("contradicts its inventory"));
}

#[test]
fn source_commitment_rejects_rehashed_payload_tampering() {
    let fixture = fixture(
        Some("pub fn total() -> i32 { 1 }\n"),
        "pub fn total() -> i32 { 2 }\n",
    );
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    materialize(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    let outcome = run_historical_v3_source_census_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    let HistoricalV3SourceCensusStageRun::Completed { artifact, .. } = outcome else {
        panic!("fixture must complete");
    };
    let mut artifact = *artifact;
    artifact.base.source_census.method_count += 1;
    artifact.base = super::commitment::seal_snapshot(artifact.base).unwrap();
    artifact = super::commitment::seal_source_census(artifact).unwrap();
    let identity = super::super::historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    let materialization = persisted.history()[0]
        .read_artifact::<super::super::HistoricalV3Materialization>()
        .unwrap()
        .unwrap();
    let error = validate_historical_v3_source_census_commitment(
        &protocol,
        &collection,
        &materialization,
        &artifact,
    )
    .unwrap_err();
    assert!(error.contains("commitment"));
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
