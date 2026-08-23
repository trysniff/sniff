use super::*;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

fn task() -> IntentionalBoundaryFrameTask {
    prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn empty_candidate_census(
    task: &IntentionalBoundaryFrameTask,
    rank: usize,
) -> IntentionalBoundaryCandidateCensus {
    let mut census = IntentionalBoundaryCandidateCensus {
        schema_version: INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION,
        candidate_contract: "sniffbench-intentional-boundary-candidate-census-v1".to_string(),
        protocol_sha256: task.protocol_sha256.clone(),
        repository: task.repositories[rank - 1].repository.clone(),
        revision: format!("{rank:040x}"),
        source_census_sha256: "1".repeat(64),
        semantic_census_sha256: "2".repeat(64),
        evidence_census_sha256: "3".repeat(64),
        candidates: Vec::new(),
        candidate_count_by_category: BTreeMap::new(),
        candidate_census_sha256: String::new(),
    };
    census.candidate_census_sha256 = candidate_census_sha256(&census).unwrap();
    census
}

fn analyzed(
    task: &IntentionalBoundaryFrameTask,
    rank: usize,
) -> IntentionalBoundaryFrameRankRecord {
    prepare_intentional_boundary_analyzed_rank(
        task,
        rank,
        &"4".repeat(64),
        empty_candidate_census(task, rank),
    )
    .unwrap()
}

fn excluded(
    task: &IntentionalBoundaryFrameTask,
    rank: usize,
) -> IntentionalBoundaryFrameRankRecord {
    prepare_intentional_boundary_excluded_rank(
        task,
        rank,
        IntentionalBoundaryFrameExclusionReason::RepositoryInaccessible,
        &"5".repeat(64),
    )
    .unwrap()
}

#[test]
fn commits_and_idempotently_reconciles_a_contiguous_create_new_prefix() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let first = analyzed(&task, 1);
    let second = excluded(&task, 2);

    commit_intentional_boundary_frame_rank(state.path(), &task, &first).unwrap();
    commit_intentional_boundary_frame_rank(state.path(), &task, &second).unwrap();

    assert_eq!(
        load_intentional_boundary_frame_ranks(state.path(), &task).unwrap(),
        vec![first.clone(), second]
    );
    assert_eq!(
        reconcile_intentional_boundary_frame_rank(state.path(), &task, &first).unwrap(),
        IntentionalBoundaryFrameRankReconciliation::AlreadyCommitted
    );
    assert!(
        commit_intentional_boundary_frame_rank(state.path(), &task, &excluded(&task, 4))
            .unwrap_err()
            .contains("contiguous rank 3")
    );
}

#[test]
fn reconciliation_rejects_a_changed_existing_rank() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let first = analyzed(&task, 1);
    commit_intentional_boundary_frame_rank(state.path(), &task, &first).unwrap();

    let changed = excluded(&task, 1);
    assert!(
        reconcile_intentional_boundary_frame_rank(state.path(), &task, &changed)
            .unwrap_err()
            .contains("conflicts with its committed record")
    );
    assert_eq!(
        load_intentional_boundary_frame_ranks(state.path(), &task).unwrap(),
        vec![first]
    );
}

#[test]
fn recovers_an_artifact_published_before_its_checkpoint() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let artifacts = state.path().join(ARTIFACT_DIRECTORY);
    fs::create_dir_all(&artifacts).unwrap();
    let record = analyzed(&task, 1);
    let bytes = pretty_json(&record, "fixture").unwrap();
    persist_create_new(&rank_path(&artifacts, 1), &bytes, "fixture").unwrap();

    assert_eq!(
        load_intentional_boundary_frame_ranks(state.path(), &task).unwrap(),
        vec![record]
    );
    assert!(rank_path(&state.path().join(CHECKPOINT_DIRECTORY), 1).is_file());
}

#[test]
fn artifact_publication_never_replaces_an_existing_file() {
    let state = tempfile::tempdir().unwrap();
    let path = state.path().join("rank.json");
    persist_create_new(&path, b"first\n", "fixture").unwrap();

    assert!(persist_create_new(&path, b"second\n", "fixture").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"first\n");
}

#[test]
fn rejects_tampered_artifacts_and_noncontiguous_state() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    commit_intentional_boundary_frame_rank(state.path(), &task, &analyzed(&task, 1)).unwrap();
    let artifact = rank_path(&state.path().join(ARTIFACT_DIRECTORY), 1);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&artifact).unwrap()).unwrap();
    value["repository_task"]["repository"] = serde_json::json!("github.com/forged/repository");
    fs::write(&artifact, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    assert!(
        load_intentional_boundary_frame_ranks(state.path(), &task)
            .unwrap_err()
            .contains("commitment changed")
    );

    let state = tempfile::tempdir().unwrap();
    let artifacts = state.path().join(ARTIFACT_DIRECTORY);
    let checkpoints = state.path().join(CHECKPOINT_DIRECTORY);
    fs::create_dir_all(&artifacts).unwrap();
    fs::create_dir_all(&checkpoints).unwrap();
    fs::write(rank_path(&artifacts, 2), "{}\n").unwrap();
    assert!(
        load_intentional_boundary_frame_ranks(state.path(), &task)
            .unwrap_err()
            .contains("contiguous ranked prefix")
    );
}

#[test]
fn incomplete_state_cannot_become_a_candidate_frame() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    commit_intentional_boundary_frame_rank(state.path(), &task, &analyzed(&task, 1)).unwrap();

    assert!(
        complete_intentional_boundary_candidate_frame(state.path(), &task)
            .unwrap_err()
            .contains("1 of 600")
    );
}

#[test]
fn complete_frame_requires_and_commits_every_population_rank() {
    let task = task();
    let records = task
        .repositories
        .iter()
        .map(|repository| excluded(&task, repository.population_rank))
        .collect::<Vec<_>>();

    let frame = finish_candidate_frame(&task, records).unwrap();

    assert_eq!(frame.rank_records.len(), 600);
    assert_eq!(frame.analyzed_repository_count, 0);
    assert_eq!(frame.excluded_repository_count, 600);
    assert!(frame.candidates.is_empty());
    assert_eq!(frame.frame_sha256.len(), 64);
}

#[test]
fn candidate_and_task_tampering_fail_before_persistence() {
    let task = task();
    let mut census = empty_candidate_census(&task, 1);
    census.repository = task.repositories[1].repository.clone();
    census.candidate_census_sha256 = candidate_census_sha256(&census).unwrap();
    assert!(
        prepare_intentional_boundary_analyzed_rank(&task, 1, &"4".repeat(64), census)
            .unwrap_err()
            .contains("candidate commitment changed")
    );

    let mut record = excluded(&task, 1);
    record.frame_task_sha256 = "0".repeat(64);
    let state = tempfile::tempdir().unwrap();
    assert!(
        commit_intentional_boundary_frame_rank(state.path(), &task, &record)
            .unwrap_err()
            .contains("commitment changed")
    );
}

#[test]
fn typed_frame_errors_distinguish_input_corruption_and_infrastructure() {
    let task = task();

    let mut invalid_record = excluded(&task, 1);
    invalid_record.frame_task_sha256 = "0".repeat(64);
    let state = tempfile::tempdir().unwrap();
    let invalid =
        commit_intentional_boundary_frame_rank_typed(state.path(), &task, &invalid_record)
            .unwrap_err();
    assert_eq!(
        invalid.kind,
        IntentionalBoundaryFrameErrorKind::InvalidInput
    );

    let first = analyzed(&task, 1);
    commit_intentional_boundary_frame_rank_typed(state.path(), &task, &first).unwrap();
    let conflict =
        reconcile_intentional_boundary_frame_rank_typed(state.path(), &task, &excluded(&task, 1))
            .unwrap_err();
    assert_eq!(
        conflict.kind,
        IntentionalBoundaryFrameErrorKind::CorruptState
    );

    let malformed = tempfile::tempdir().unwrap();
    let artifacts = malformed.path().join(ARTIFACT_DIRECTORY);
    fs::create_dir_all(&artifacts).unwrap();
    fs::write(rank_path(&artifacts, 2), "{}\n").unwrap();
    let corrupt = load_intentional_boundary_frame_ranks_typed(malformed.path(), &task).unwrap_err();
    assert_eq!(
        corrupt.kind,
        IntentionalBoundaryFrameErrorKind::CorruptState
    );

    let blocked = tempfile::tempdir().unwrap();
    let frame_file = blocked.path().join("frame");
    fs::write(&frame_file, b"not a directory").unwrap();
    let infrastructure =
        load_intentional_boundary_frame_ranks_typed(&frame_file, &task).unwrap_err();
    assert_eq!(
        infrastructure.kind,
        IntentionalBoundaryFrameErrorKind::InfrastructureFailed
    );
}
