use super::*;

fn frame() -> Vec<u8> {
    let mut text = String::from("repo,metadata\n");
    for language in SUPPORTED_LANGUAGES {
        for index in 0..2 {
            text.push_str(&format!("github.com/example/{language}-{index},fixture\n"));
        }
    }
    text.into_bytes()
}

fn policy(frame: &[u8]) -> SourceSamplingPolicy {
    SourceSamplingPolicy {
        schema_version: SOURCE_SAMPLING_POLICY_SCHEMA_VERSION,
        selection_id: "blind-oss-v1".to_string(),
        selected_at: "2026-08-13T00:00:00Z".to_string(),
        frame_source: "https://github.com/ossf/scorecard/cron/internal/data/projects.csv"
            .to_string(),
        frame_revision: "1".repeat(40),
        frame_blob_sha: "2".repeat(40),
        frame_sha256: sha256(frame),
        seed: "public-precommitted-seed".to_string(),
        assessment_prefix: 12,
        minimum_methods: 10,
        maximum_methods: 500,
        language_quotas: SUPPORTED_LANGUAGES
            .into_iter()
            .map(|language| (language.to_string(), 1))
            .collect(),
        attestation: "The frame, seed, quotas, and limits were fixed before tool output."
            .to_string(),
    }
}

fn completed(frame: &[u8]) -> SourceSelectionWorksheet {
    let mut worksheet = prepare_source_selection(policy(frame), frame).unwrap();
    let mut selected = HashSet::new();
    for assessment in &mut worksheet.candidates {
        let language = SUPPORTED_LANGUAGES
            .iter()
            .find(|language| assessment.candidate.repository.contains(**language))
            .unwrap()
            .to_string();
        assessment.selection_quota_language = language.clone();
        assessment.observed_method_count = Some(100);
        let facts = SourceAssessmentFacts {
            repository: assessment.candidate.repository.clone(),
            selection_quota_language: language.clone(),
            observed_method_count: Some(100),
            accessible: true,
            archived: Some(false),
            fork: Some(false),
            license_path: Some("LICENSE".to_string()),
            supported_project_shape: Some(true),
        };
        let payload = serde_json::to_string(&facts).unwrap();
        assessment.facts = Some(facts);
        let raw_payload = format!("raw metadata for {}", assessment.candidate.repository);
        assessment.evidence = vec![
            SourceAssessmentEvidence {
                kind: SourceAssessmentEvidenceKind::StructuredFacts,
                source: "derived:source-assessment-facts-v1".to_string(),
                observed_at: "2026-08-13T00:00:00Z".to_string(),
                payload_sha256: sha256(payload.as_bytes()),
                payload,
            },
            SourceAssessmentEvidence {
                kind: SourceAssessmentEvidenceKind::RawSource,
                source: "https://example.test/source-selection-metadata".to_string(),
                observed_at: "2026-08-13T00:00:00Z".to_string(),
                payload_sha256: sha256(raw_payload.as_bytes()),
                payload: raw_payload,
            },
        ];
        if selected.insert(language) {
            assessment.disposition = Some(SourceSelectionDisposition::Selected);
            assessment.selected_repository = Some(SourceRepositoryDraft {
                repository: format!("https://{}", assessment.candidate.repository),
                revision: "3".repeat(40),
                license_path: "LICENSE".to_string(),
                selection_language: assessment.selection_quota_language.clone(),
                observed_method_count: 100,
                context_paths: Vec::new(),
            });
        } else {
            assessment.disposition = Some(SourceSelectionDisposition::Excluded);
            assessment.exclusion_reason = Some(SourceExclusionReason::QuotaFilled);
        }
    }
    worksheet
}

#[test]
fn source_selection_is_hash_ranked_and_fills_every_language_quota() {
    let frame = frame();
    let worksheet = completed(&frame);

    let audit = audit_source_selection(policy(&frame), &frame, worksheet).unwrap();

    assert_eq!(audit.selected_repositories.len(), 6);
    assert_eq!(audit.audit_sha256, audit.computed_audit_sha256().unwrap());
    validate_source_selection_audit(&audit).unwrap();
}

#[test]
fn source_selection_rejects_skipped_or_reordered_ranked_candidates() {
    let frame = frame();
    let mut worksheet = completed(&frame);
    worksheet.candidates.swap(0, 1);

    let error = audit_source_selection(policy(&frame), &frame, worksheet).unwrap_err();

    assert!(error.contains("changed ranked candidate"));
}

#[test]
fn source_selection_rejects_untyped_exclusions_and_premature_quota_claims() {
    let frame = frame();
    let mut worksheet = completed(&frame);
    let first = &mut worksheet.candidates[0];
    first.disposition = Some(SourceSelectionDisposition::Excluded);
    first.selected_repository = None;
    first.exclusion_reason = Some(SourceExclusionReason::QuotaFilled);

    let error = audit_source_selection(policy(&frame), &frame, worksheet).unwrap_err();

    assert!(error.contains("contradicts"));
}

#[test]
fn source_selection_rejects_frame_or_task_tampering() {
    let frame = frame();
    let worksheet = completed(&frame);
    let mut changed_frame = frame.clone();
    changed_frame.extend_from_slice(b"github.com/example/extra,fixture\n");

    let error = audit_source_selection(policy(&frame), &changed_frame, worksheet).unwrap_err();

    assert!(error.contains("frame hash mismatch"));
}

#[test]
fn source_selection_commits_malformed_invalid_and_duplicate_frame_rows() {
    let mut frame = frame();
    frame.extend_from_slice(b"not-a-csv-row\n");
    frame.extend_from_slice(b"github.com/invalid+owner/repository,fixture\n");
    frame.extend_from_slice(b"github.com/example/rust-0,duplicate\n");
    let mut policy = policy(&frame);
    policy.assessment_prefix = 12;

    let worksheet = prepare_source_selection(policy, &frame).unwrap();

    assert_eq!(worksheet.frame_eligibility.ineligible_records.len(), 3);
    assert_eq!(
        worksheet.frame_eligibility.ineligible_records[0].reason,
        FrameIneligibilityReason::MalformedRecord
    );
    assert_eq!(
        worksheet.frame_eligibility.ineligible_records[1].reason,
        FrameIneligibilityReason::InvalidRepositoryIdentity
    );
    assert_eq!(
        worksheet.frame_eligibility.ineligible_records[2].reason,
        FrameIneligibilityReason::DuplicateRepositoryIdentity
    );
    let serialized = serde_json::to_string(&worksheet.frame_eligibility).unwrap();
    assert!(!serialized.contains("invalid+owner"));
}

#[test]
fn source_selection_rejects_tampered_frame_eligibility_census() {
    let frame = frame();
    let mut worksheet = completed(&frame);
    worksheet.frame_eligibility.nonempty_records += 1;

    let error = audit_source_selection(policy(&frame), &frame, worksheet).unwrap_err();

    assert!(error.contains("changed its immutable task"));
}

#[test]
fn source_selection_rejects_tampered_or_contradictory_assessment_evidence() {
    let frame = frame();
    let mut tampered = completed(&frame);
    tampered.candidates[0].evidence[0]
        .payload
        .push_str("tampered");

    let error = audit_source_selection(policy(&frame), &frame, tampered).unwrap_err();

    assert!(error.contains("evidence hash mismatch"));

    let mut archived = completed(&frame);
    let assessment = &mut archived.candidates[0];
    let mut facts = assessment.facts.clone().unwrap();
    facts.archived = Some(true);
    let payload = serde_json::to_string(&facts).unwrap();
    assessment.facts = Some(facts);
    assessment.evidence[0].payload_sha256 = sha256(payload.as_bytes());
    assessment.evidence[0].payload = payload;

    let error = audit_source_selection(policy(&frame), &frame, archived).unwrap_err();

    assert!(error.contains("contradicts its assessed repository facts"));
}

#[test]
fn source_selection_rejects_exclusion_reason_that_contradicts_facts() {
    let frame = frame();
    let mut worksheet = completed(&frame);
    let assessment = &mut worksheet.candidates[0];
    assessment.disposition = Some(SourceSelectionDisposition::Excluded);
    assessment.selected_repository = None;
    assessment.exclusion_reason = Some(SourceExclusionReason::MissingLicense);
    let payload = "{\"license\":\"MIT\"}".to_string();
    assessment.evidence.push(SourceAssessmentEvidence {
        kind: SourceAssessmentEvidenceKind::RawSource,
        source: "https://api.github.test/repos/example/repository".to_string(),
        observed_at: "2026-08-13T00:00:00Z".to_string(),
        payload_sha256: sha256(payload.as_bytes()),
        payload,
    });

    let error = audit_source_selection(policy(&frame), &frame, worksheet).unwrap_err();

    assert!(error.contains("contradicts its recorded evidence"));
}

#[test]
fn externally_sourced_exclusions_require_the_raw_source_payload() {
    let frame = frame();
    let mut worksheet = completed(&frame);
    let assessment = &mut worksheet.candidates[0];
    assessment.disposition = Some(SourceSelectionDisposition::Excluded);
    assessment.selected_repository = None;
    assessment.exclusion_reason = Some(SourceExclusionReason::Archived);
    let mut facts = assessment.facts.clone().unwrap();
    facts.archived = Some(true);
    let payload = serde_json::to_string(&facts).unwrap();
    assessment.facts = Some(facts);
    assessment.evidence[0].payload_sha256 = sha256(payload.as_bytes());
    assessment.evidence[0].payload = payload;
    assessment
        .evidence
        .retain(|evidence| evidence.kind == SourceAssessmentEvidenceKind::StructuredFacts);

    let error = audit_source_selection(policy(&frame), &frame, worksheet).unwrap_err();

    assert!(error.contains("at least one raw-source payload"));
}
