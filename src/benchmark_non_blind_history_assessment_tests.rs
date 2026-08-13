use super::*;
use crate::benchmark::{
    AffectedHistoricalMethod, HistoricalChangedPath, HistoricalEvidenceKind,
    HistoricalRevisionSide, HistoricalTestOutcome, HistoricalTestResult, ProvenanceArtifact,
    SourceSnapshot,
};

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const WORKSHEET: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-history-assessment-protocol.json");

#[test]
fn frozen_history_assessment_prepares_all_six_hundred_ranks() {
    let assessment = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();

    assert_eq!(assessment.assessments.len(), 600);
    assert_eq!(assessment.quota_target.len(), 6);
    assert!(assessment.quota_target.values().all(|quota| *quota == 2));
    assert!(assessment.assessments.iter().all(|entry| {
        entry.disposition.is_none()
            && entry.facts.is_none()
            && entry.evidence.is_empty()
            && entry.exclusion_reason.is_none()
            && entry.selected_provenance.is_none()
    }));
    validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment).unwrap();
    assert!(
        complete_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment)
            .unwrap_err()
            .contains("incomplete")
    );
}

#[test]
fn frozen_history_assessment_rejects_protocol_or_task_drift() {
    let assessment = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    let mut changed_protocol = PROTOCOL.to_vec();
    changed_protocol.push(b' ');
    assert!(
        prepare_non_blind_history_assessment(POLICY, WORKSHEET, &changed_protocol)
            .unwrap_err()
            .contains("protocol hash mismatch")
    );

    let mut changed = assessment;
    changed.assessments.swap(0, 1);
    assert!(
        validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &changed)
            .unwrap_err()
            .contains("immutable rank")
    );
}

#[test]
fn commit_ranking_filters_subjects_and_merges_before_hash_ranking() {
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(POLICY).unwrap();
    let commits = vec![
        commit("1", "cleanup redundant branch", &["2"]),
        commit("3", "add feature", &["4"]),
        commit("5", "refactor parser", &["6", "7"]),
        commit("8", "simplify parser", &["9"]),
    ];

    let ranked = rank_historical_commits(&policy, "github.com/example/project", &commits).unwrap();

    assert_eq!(ranked.len(), 2);
    assert!(ranked.iter().all(|entry| entry.rank > 0));
    assert!(
        ranked
            .iter()
            .all(|entry| matches!(entry.commit_sha.as_bytes()[0], b'1' | b'8'))
    );
    assert_ne!(ranked[0].rank_sha256, ranked[1].rank_sha256);
}

#[test]
fn checkpoints_are_create_new_contiguous_and_task_bound() {
    let template = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    let root = tempfile::tempdir().unwrap();
    let first = excluded(template.assessments[0].clone());

    write_non_blind_history_checkpoint(root.path(), &template.task_sha256, &first).unwrap();
    assert!(
        write_non_blind_history_checkpoint(root.path(), &template.task_sha256, &first)
            .unwrap_err()
            .contains("already exists")
    );
    assert_eq!(
        load_non_blind_history_checkpoints(&template, root.path()).unwrap(),
        [first]
    );

    let third = excluded(template.assessments[2].clone());
    write_non_blind_history_checkpoint(root.path(), &template.task_sha256, &third).unwrap();
    assert!(
        load_non_blind_history_checkpoints(&template, root.path())
            .unwrap_err()
            .contains("contiguous ranked prefix")
    );
}

#[test]
fn exclusion_reason_is_derived_from_facts_not_trusted() {
    let mut assessment = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    assessment.assessments[0] = excluded(assessment.assessments[0].clone());
    assessment.assessments[0].exclusion_reason = Some(HistoricalExclusionReason::NoMatchingCommit);

    let error = validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment)
        .unwrap_err();
    assert!(error.contains("evidence derives Inaccessible"));
}

#[test]
fn complete_selected_case_requires_all_label_free_provenance() {
    let mut assessment = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    assessment.assessments[0] = selected(assessment.assessments[0].clone());

    validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment).unwrap();

    assessment.assessments[0]
        .facts
        .as_mut()
        .unwrap()
        .selected_commit
        .as_mut()
        .unwrap()
        .rank_sha256 = "f".repeat(64);
    assert!(
        validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment)
            .unwrap_err()
            .contains("rank commitment changed")
    );
}

#[test]
fn quota_filled_is_derived_only_after_two_earlier_selections() {
    let mut assessment = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    assessment.assessments[0] = selected(assessment.assessments[0].clone());
    assessment.assessments[1] = selected(assessment.assessments[1].clone());
    let mut third = selected(assessment.assessments[2].clone());
    third.disposition = Some(HistoricalAssessmentDisposition::Excluded);
    third.exclusion_reason = Some(HistoricalExclusionReason::QuotaFilled);
    third.selected_provenance = None;
    assessment.assessments[2] = third;

    validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment).unwrap();

    assessment.assessments.swap(0, 1);
    assert!(
        validate_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL, &assessment)
            .unwrap_err()
            .contains("immutable rank")
    );
}

fn commit(commit: &str, subject: &str, parents: &[&str]) -> HistoricalCommitMetadata {
    HistoricalCommitMetadata {
        commit_sha: commit.repeat(40),
        parent_shas: parents.iter().map(|parent| parent.repeat(40)).collect(),
        subject: subject.to_string(),
        changed_paths: vec![HistoricalChangedPath {
            status: "M".to_string(),
            previous_path: None,
            path: "src/main.rs".to_string(),
        }],
    }
}

fn excluded(mut assessment: HistoricalRepositoryAssessment) -> HistoricalRepositoryAssessment {
    assessment.facts = Some(HistoricalRepositoryFacts {
        repository: assessment.candidate.repository.clone(),
        accessible: false,
        repository_empty: false,
        default_branch: None,
        default_branch_head: None,
        complete_history: false,
        matching_commit_count: None,
        selected_commit: None,
        supported_project_shape: None,
        qualifying_production_change: None,
        parent_method_counts: Default::default(),
        parent_method_count: None,
        affected_methods: Vec::new(),
        quota_language: None,
        source_non_whitespace_lines_before: None,
        source_non_whitespace_lines_after: None,
        license_path: None,
        test_recipe: None,
        parent_test: None,
        commit_test: None,
        test_outcome: None,
    });
    assessment.evidence = vec![HistoricalAssessmentEvidence {
        kind: HistoricalEvidenceKind::RepositoryRefs,
        source: format!("https://{}", assessment.candidate.repository),
        observed_at: "fixture".to_string(),
        artifact_path: format!("evidence/rank-{:04}.json", assessment.candidate.rank),
        sha256: "a".repeat(64),
    }];
    assessment.disposition = Some(HistoricalAssessmentDisposition::Excluded);
    assessment.exclusion_reason = Some(HistoricalExclusionReason::Inaccessible);
    assessment
}

fn selected(mut assessment: HistoricalRepositoryAssessment) -> HistoricalRepositoryAssessment {
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(POLICY).unwrap();
    let repository = assessment.candidate.repository.clone();
    let ranked = rank_historical_commits(
        &policy,
        &repository,
        &[commit("1", "simplify parser", &["2"])],
    )
    .unwrap()
    .remove(0);
    let command = vec!["cargo".to_string(), "test".to_string()];
    let parent_test = test_result(&ranked.parent_sha, &command);
    let commit_test = test_result(&ranked.commit_sha, &command);
    assessment.facts = Some(HistoricalRepositoryFacts {
        repository: repository.clone(),
        accessible: true,
        repository_empty: false,
        default_branch: Some("main".to_string()),
        default_branch_head: Some("f".repeat(40)),
        complete_history: true,
        matching_commit_count: Some(1),
        selected_commit: Some(ranked.clone()),
        supported_project_shape: Some(true),
        qualifying_production_change: Some(true),
        parent_method_counts: [("rust".to_string(), 20)].into(),
        parent_method_count: Some(20),
        affected_methods: vec![AffectedHistoricalMethod {
            side: HistoricalRevisionSide::Parent,
            language: "rust".to_string(),
            repository_path: "src/main.rs".to_string(),
            symbol: "simplify".to_string(),
            start_line: 1,
            end_line: 3,
            source_sha256: "3".repeat(64),
        }],
        quota_language: Some("rust".to_string()),
        source_non_whitespace_lines_before: Some(10),
        source_non_whitespace_lines_after: Some(9),
        license_path: Some("LICENSE".to_string()),
        test_recipe: Some(command.clone()),
        parent_test: Some(parent_test),
        commit_test: Some(commit_test),
        test_outcome: Some(HistoricalTestOutcome::Passed),
    });
    assessment.evidence = [
        HistoricalEvidenceKind::RepositoryRefs,
        HistoricalEvidenceKind::CommitMetadata,
        HistoricalEvidenceKind::SourceCensus,
        HistoricalEvidenceKind::SourceDelta,
        HistoricalEvidenceKind::License,
        HistoricalEvidenceKind::TestRecipe,
        HistoricalEvidenceKind::ParentTest,
        HistoricalEvidenceKind::CommitTest,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, kind)| HistoricalAssessmentEvidence {
        kind,
        source: format!("fixture:{kind:?}"),
        observed_at: "fixture".to_string(),
        artifact_path: format!(
            "evidence/rank-{:04}-{index}.json",
            assessment.candidate.rank
        ),
        sha256: format!("{:064x}", index + 1),
    })
    .collect();
    let repository_url = format!("https://{repository}");
    assessment.selected_provenance = Some(HistoricalSelectedProvenance {
        provenance_id: format!("history-rank-{:04}", assessment.candidate.rank),
        upstream_url: repository_url.clone(),
        upstream_revision: ranked.commit_sha.clone(),
        upstream_record_id: ranked.commit_sha.clone(),
        before: vec![SourceSnapshot {
            repository: repository_url.clone(),
            revision: ranked.parent_sha,
            repository_path: "src/main.rs".to_string(),
            artifact_path: format!(
                "sources/rank-{:04}/before/src/main.rs",
                assessment.candidate.rank
            ),
            sha256: "4".repeat(64),
        }],
        after: vec![SourceSnapshot {
            repository: repository_url,
            revision: ranked.commit_sha,
            repository_path: "src/main.rs".to_string(),
            artifact_path: format!(
                "sources/rank-{:04}/after/src/main.rs",
                assessment.candidate.rank
            ),
            sha256: "5".repeat(64),
        }],
        license: ProvenanceArtifact {
            artifact_path: format!("sources/rank-{:04}/LICENSE", assessment.candidate.rank),
            sha256: "6".repeat(64),
            description: "Repository license".to_string(),
        },
        behavioral_evidence: vec![
            ProvenanceArtifact {
                artifact_path: format!("tests/rank-{:04}/parent.json", assessment.candidate.rank),
                sha256: "7".repeat(64),
                description: "Parent test result".to_string(),
            },
            ProvenanceArtifact {
                artifact_path: format!("tests/rank-{:04}/commit.json", assessment.candidate.rank),
                sha256: "8".repeat(64),
                description: "Commit test result".to_string(),
            },
        ],
    });
    assessment.disposition = Some(HistoricalAssessmentDisposition::Selected);
    assessment
}

fn test_result(revision: &str, command: &[String]) -> HistoricalTestResult {
    HistoricalTestResult {
        revision: revision.to_string(),
        command: command.to_vec(),
        runtime_identity: "fixture-runtime".to_string(),
        status_code: Some(0),
        timed_out: false,
        stdout_sha256: "9".repeat(64),
        stderr_sha256: "a".repeat(64),
        raw_result_sha256: "b".repeat(64),
    }
}
