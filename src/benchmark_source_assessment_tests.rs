use super::*;
use crate::benchmark::{
    SOURCE_SAMPLING_POLICY_SCHEMA_VERSION, SourceAssessmentEvidenceKind,
    SourceAssessmentSupportingEvidence, SourceSamplingPolicy, prepare_source_selection,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-source-assessment-{name}-{unique}"));
    fs::create_dir_all(&root).unwrap();
    root
}

fn run_git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn repository(root: &Path) -> String {
    run_git(root, &["init"]);
    run_git(root, &["config", "user.email", "sniff@example.test"]);
    run_git(root, &["config", "user.name", "Sniff Fixture"]);
    fs::write(
        root.join("main.py"),
        "def first():\n    return 1\n\ndef second():\n    return 2\n",
    )
    .unwrap();
    fs::write(
        root.join("main.ts"),
        "export function one() { return 1; }\nexport function two() { return 2; }\n",
    )
    .unwrap();
    fs::write(root.join("LICENSE"), "fixture license\n").unwrap();
    run_git(root, &["add", "."]);
    run_git(root, &["commit", "-m", "fixture"]);
    run_git(root, &["rev-parse", "HEAD"])
}

fn policy(frame: &[u8]) -> SourceSamplingPolicy {
    SourceSamplingPolicy {
        schema_version: SOURCE_SAMPLING_POLICY_SCHEMA_VERSION,
        selection_id: "assessment-test".to_string(),
        selected_at: "2026-08-13T00:00:00Z".to_string(),
        frame_source: "https://example.test/frame.csv".to_string(),
        frame_revision: "1".repeat(40),
        frame_blob_sha: "2".repeat(40),
        frame_sha256: sha256(frame),
        seed: "assessment-test-seed".to_string(),
        assessment_prefix: 1,
        minimum_methods: 1,
        maximum_methods: 10,
        language_quotas: BTreeMap::from([("python".to_string(), 1)]),
        attestation: "fixed before output".to_string(),
    }
}

#[test]
fn census_records_every_language_and_uses_lexicographic_tie_break() {
    let root = temp_root("census");
    repository(&root);

    let census = census_repository(&root).unwrap();

    assert_eq!(census.observed_method_count, Some(4));
    assert_eq!(census.method_counts.get("python"), Some(&2));
    assert_eq!(census.method_counts.get("typescript"), Some(&2));
    assert_eq!(census.dominant_language.as_deref(), Some("python"));
    assert!(census.supported_project_shape);
    assert!(census.parse_failure.is_none());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checkpoints_resume_only_a_contiguous_prefix_with_its_selected_checkout() {
    let frame = b"repo,metadata\ngithub.com/example/repository,fixture\n";
    let worksheet = prepare_source_selection(policy(frame), frame).unwrap();
    let root = temp_root("resume");
    let checkpoint_root = root.join("checkpoints");
    let work_root = root.join("work");
    let checkout_root = root.join("checkouts");
    let checkout = checkout_root.join("example").join("repository");
    fs::create_dir_all(&checkpoint_root).unwrap();
    fs::create_dir_all(&work_root).unwrap();
    fs::create_dir_all(checkout.parent().unwrap()).unwrap();
    fs::create_dir_all(&checkout).unwrap();
    let revision = repository(&checkout);
    let facts = SourceAssessmentFacts {
        repository: "github.com/example/repository".to_string(),
        selection_quota_language: "python".to_string(),
        observed_method_count: Some(4),
        assessed_revision: Some(revision.clone()),
        method_counts: BTreeMap::from([("python".to_string(), 2), ("typescript".to_string(), 2)]),
        method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
        repository_empty: false,
        accessible: true,
        archived: Some(false),
        fork: Some(false),
        license_path: Some("LICENSE".to_string()),
        supported_project_shape: Some(true),
    };
    let mut selected_counts = BTreeMap::from([("python".to_string(), 0)]);
    let assessment = complete_source_candidate_assessment(
        worksheet.candidates[0].candidate.clone(),
        facts,
        "unix:1".to_string(),
        supporting_evidence(&revision),
        Vec::new(),
        &worksheet.policy,
        &mut selected_counts,
    )
    .unwrap();
    write_checkpoint(&checkpoint_root, &worksheet.task_sha256, &assessment).unwrap();
    fs::write(checkpoint_root.join("rank-0002.json.tmp-999"), "partial").unwrap();

    let resumed =
        load_checkpoints(&worksheet, &checkpoint_root, &work_root, &checkout_root).unwrap();
    assert_eq!(resumed, vec![assessment]);
    assert!(!checkpoint_root.join("rank-0002.json.tmp-999").exists());

    fs::write(checkpoint_root.join("rank-0003.json"), "{}\n").unwrap();
    let error =
        load_checkpoints(&worksheet, &checkpoint_root, &work_root, &checkout_root).unwrap_err();
    assert!(error.contains("contiguous ranked prefix"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsupported_parse_shape_is_explicit_instead_of_partially_counted() {
    let root = temp_root("parse-failure");
    fs::write(root.join("valid.py"), "def valid():\n    return 1\n").unwrap();
    fs::write(root.join("broken.ts"), "export function broken( {\n").unwrap();

    let census = census_repository(&root).unwrap();

    assert!(!census.supported_project_shape);
    assert_eq!(census.observed_method_count, None);
    assert!(census.method_counts.is_empty());
    assert!(
        census
            .parse_failure
            .as_deref()
            .unwrap()
            .contains("broken.ts")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_repository_facts_require_no_invented_revision() {
    let frame = b"repo,metadata\ngithub.com/example/empty,fixture\n";
    let worksheet = prepare_source_selection(policy(frame), frame).unwrap();
    let facts = SourceAssessmentFacts {
        repository: "github.com/example/empty".to_string(),
        selection_quota_language: "unsupported".to_string(),
        observed_method_count: Some(0),
        assessed_revision: None,
        method_counts: BTreeMap::new(),
        method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
        repository_empty: true,
        accessible: true,
        archived: Some(false),
        fork: Some(false),
        license_path: None,
        supported_project_shape: Some(true),
    };
    let mut selected_counts = BTreeMap::from([("python".to_string(), 0)]);

    let assessment = complete_source_candidate_assessment(
        worksheet.candidates[0].candidate.clone(),
        facts,
        "unix:1".to_string(),
        vec![
            SourceAssessmentSupportingEvidence {
                kind: SourceAssessmentEvidenceKind::RawSource,
                source: "https://api.github.com/repos/example/empty".to_string(),
                payload: "empty repository".to_string(),
            },
            SourceAssessmentSupportingEvidence {
                kind: SourceAssessmentEvidenceKind::DerivedCensus,
                source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                payload: "empty census".to_string(),
            },
        ],
        Vec::new(),
        &worksheet.policy,
        &mut selected_counts,
    )
    .unwrap();

    assert_eq!(
        assessment.exclusion_reason,
        Some(crate::benchmark::SourceExclusionReason::NoSupportedMethods)
    );
    assert!(assessment.selected_repository.is_none());
}

#[test]
fn resume_finishes_selected_checkout_move_after_checkpoint_flush() {
    let frame = b"repo,metadata\ngithub.com/example/repository,fixture\n";
    let worksheet = prepare_source_selection(policy(frame), frame).unwrap();
    let root = temp_root("move-recovery");
    let checkpoint_root = root.join("checkpoints");
    let work_root = root.join("work");
    let checkout_root = root.join("checkouts");
    let worktree = work_root.join("rank-0001");
    fs::create_dir_all(&checkpoint_root).unwrap();
    fs::create_dir_all(&work_root).unwrap();
    fs::create_dir_all(&checkout_root).unwrap();
    fs::create_dir_all(&worktree).unwrap();
    let revision = repository(&worktree);
    let facts = SourceAssessmentFacts {
        repository: "github.com/example/repository".to_string(),
        selection_quota_language: "python".to_string(),
        observed_method_count: Some(4),
        assessed_revision: Some(revision.clone()),
        method_counts: BTreeMap::from([("python".to_string(), 2), ("typescript".to_string(), 2)]),
        method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
        repository_empty: false,
        accessible: true,
        archived: Some(false),
        fork: Some(false),
        license_path: Some("LICENSE".to_string()),
        supported_project_shape: Some(true),
    };
    let mut selected_counts = BTreeMap::from([("python".to_string(), 0)]);
    let assessment = complete_source_candidate_assessment(
        worksheet.candidates[0].candidate.clone(),
        facts,
        "unix:1".to_string(),
        supporting_evidence(&revision),
        Vec::new(),
        &worksheet.policy,
        &mut selected_counts,
    )
    .unwrap();
    write_checkpoint(&checkpoint_root, &worksheet.task_sha256, &assessment).unwrap();

    let resumed =
        load_checkpoints(&worksheet, &checkpoint_root, &work_root, &checkout_root).unwrap();

    assert_eq!(resumed, vec![assessment]);
    assert!(!worktree.exists());
    assert!(checkout_root.join("example").join("repository").is_dir());
    fs::remove_dir_all(root).unwrap();
}

fn supporting_evidence(revision: &str) -> Vec<SourceAssessmentSupportingEvidence> {
    vec![
        SourceAssessmentSupportingEvidence {
            kind: SourceAssessmentEvidenceKind::RawSource,
            source: "https://api.github.com/repos/example/repository".to_string(),
            payload: "fixture metadata".to_string(),
        },
        SourceAssessmentSupportingEvidence {
            kind: SourceAssessmentEvidenceKind::DerivedCensus,
            source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
            payload: format!("fixture census at {revision}"),
        },
    ]
}

#[test]
fn accessible_assessment_without_derived_census_is_rejected() {
    let frame = b"repo,metadata\ngithub.com/example/repository,fixture\n";
    let worksheet = prepare_source_selection(policy(frame), frame).unwrap();
    let facts = SourceAssessmentFacts {
        repository: "github.com/example/repository".to_string(),
        selection_quota_language: "python".to_string(),
        observed_method_count: Some(2),
        assessed_revision: Some("3".repeat(40)),
        method_counts: BTreeMap::from([("python".to_string(), 2)]),
        method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
        repository_empty: false,
        accessible: true,
        archived: Some(false),
        fork: Some(false),
        license_path: Some("LICENSE".to_string()),
        supported_project_shape: Some(true),
    };
    let mut selected_counts = BTreeMap::from([("python".to_string(), 0)]);

    let error = complete_source_candidate_assessment(
        worksheet.candidates[0].candidate.clone(),
        facts,
        "unix:1".to_string(),
        vec![SourceAssessmentSupportingEvidence {
            kind: SourceAssessmentEvidenceKind::RawSource,
            source: "https://api.github.com/repos/example/repository".to_string(),
            payload: "metadata only".to_string(),
        }],
        Vec::new(),
        &worksheet.policy,
        &mut selected_counts,
    )
    .unwrap_err();

    assert!(error.contains("accessible-source census"));
}

#[test]
fn assessment_requires_safe_disk_headroom_before_clone() {
    let root = temp_root("disk-headroom");

    assessment_state::require_disk_headroom(&root).unwrap();

    fs::remove_dir_all(root).unwrap();
}
