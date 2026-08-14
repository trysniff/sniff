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
        continuation: None,
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
            assessed_revision: Some("3".repeat(40)),
            method_counts: BTreeMap::from([(language.clone(), 100)]),
            method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
            repository_empty: false,
            accessible: true,
            archived: Some(false),
            fork: Some(false),
            license_path: Some("LICENSE".to_string()),
            supported_project_shape: Some(true),
        };
        let payload = serde_json::to_string(&facts).unwrap();
        assessment.facts = Some(facts);
        let raw_payload = format!("raw metadata for {}", assessment.candidate.repository);
        let census_payload = format!("census for {}", assessment.candidate.repository);
        assessment.evidence = vec![
            SourceAssessmentEvidence {
                kind: SourceAssessmentEvidenceKind::StructuredFacts,
                source: "derived:source-assessment-facts-v2".to_string(),
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
            SourceAssessmentEvidence {
                kind: SourceAssessmentEvidenceKind::DerivedCensus,
                source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                observed_at: "2026-08-13T00:00:00Z".to_string(),
                payload_sha256: sha256(census_payload.as_bytes()),
                payload: census_payload,
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

fn continuation_policy(frame: &[u8], prior: &SourceSelectionWorksheet) -> SourceSamplingPolicy {
    let mut extended = policy(frame);
    extended.schema_version = SOURCE_SAMPLING_CONTINUATION_POLICY_SCHEMA_VERSION;
    extended.selection_id = "blind-oss-v1-extension-1".to_string();
    extended.assessment_prefix = prior.candidates.len() + 1;
    extended.continuation = Some(SourceSelectionContinuation {
        prior_prefix: prior.candidates.len(),
        prior_policy_sha256: prior.policy_sha256.clone(),
        prior_task_sha256: prior.task_sha256.clone(),
        prior_worksheet_sha256: json_sha256(prior).unwrap(),
        prior_assessments_sha256: json_sha256(&prior.candidates).unwrap(),
    });
    extended
}

fn exclude_language(
    worksheet: &mut SourceSelectionWorksheet,
    language: &str,
    reason: SourceExclusionReason,
) {
    for assessment in &mut worksheet.candidates {
        if assessment.selection_quota_language != language {
            continue;
        }
        let mut facts = assessment.facts.clone().unwrap();
        if reason == SourceExclusionReason::MissingLicense {
            facts.license_path = None;
        }
        let payload = serde_json::to_string(&facts).unwrap();
        assessment.facts = Some(facts);
        assessment.evidence[0].payload_sha256 = sha256(payload.as_bytes());
        assessment.evidence[0].payload = payload;
        assessment.disposition = Some(SourceSelectionDisposition::Excluded);
        assessment.exclusion_reason = Some(reason);
        assessment.selected_repository = None;
    }
}

fn kotlin_component() -> (Vec<u8>, SourceSelectionComponentAudit) {
    let frame = b"repo,metadata\ngithub.com/example/kotlin-supplement,fixture\n".to_vec();
    let policy = SourceSamplingPolicy {
        schema_version: SOURCE_SAMPLING_POLICY_SCHEMA_VERSION,
        selection_id: "blind-oss-v1-kotlin-1".to_string(),
        selected_at: "2026-08-14T00:00:00Z".to_string(),
        frame_source: "https://example.test/frozen-kotlin-frame.csv".to_string(),
        frame_revision: "4".repeat(40),
        frame_blob_sha: "5".repeat(40),
        frame_sha256: sha256(&frame),
        seed: "precommitted-kotlin-seed".to_string(),
        assessment_prefix: 1,
        minimum_methods: 10,
        maximum_methods: 500,
        language_quotas: BTreeMap::from([("kotlin".to_string(), 1)]),
        attestation: "The Kotlin frame and seed were fixed before ranking.".to_string(),
        continuation: None,
    };
    let mut worksheet = prepare_source_selection(policy.clone(), &frame).unwrap();
    let assessment = &mut worksheet.candidates[0];
    assessment.selection_quota_language = "kotlin".to_string();
    assessment.observed_method_count = Some(100);
    let facts = SourceAssessmentFacts {
        repository: assessment.candidate.repository.clone(),
        selection_quota_language: "kotlin".to_string(),
        observed_method_count: Some(100),
        assessed_revision: Some("6".repeat(40)),
        method_counts: BTreeMap::from([("kotlin".to_string(), 100)]),
        method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
        repository_empty: false,
        accessible: true,
        archived: Some(false),
        fork: Some(false),
        license_path: Some("LICENSE".to_string()),
        supported_project_shape: Some(true),
    };
    let payload = serde_json::to_string(&facts).unwrap();
    assessment.facts = Some(facts);
    assessment.evidence = vec![
        SourceAssessmentEvidence {
            kind: SourceAssessmentEvidenceKind::StructuredFacts,
            source: "derived:source-assessment-facts-v2".to_string(),
            observed_at: "2026-08-14T00:00:00Z".to_string(),
            payload_sha256: sha256(payload.as_bytes()),
            payload,
        },
        SourceAssessmentEvidence {
            kind: SourceAssessmentEvidenceKind::RawSource,
            source: "https://example.test/kotlin-metadata".to_string(),
            observed_at: "2026-08-14T00:00:00Z".to_string(),
            payload_sha256: sha256(b"kotlin metadata"),
            payload: "kotlin metadata".to_string(),
        },
        SourceAssessmentEvidence {
            kind: SourceAssessmentEvidenceKind::DerivedCensus,
            source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
            observed_at: "2026-08-14T00:00:00Z".to_string(),
            payload_sha256: sha256(b"kotlin census"),
            payload: "kotlin census".to_string(),
        },
    ];
    assessment.disposition = Some(SourceSelectionDisposition::Selected);
    assessment.selected_repository = Some(SourceRepositoryDraft {
        repository: "https://github.com/example/kotlin-supplement".to_string(),
        revision: "6".repeat(40),
        license_path: "LICENSE".to_string(),
        selection_language: "kotlin".to_string(),
        observed_method_count: 100,
        context_paths: Vec::new(),
    });
    let audit = audit_source_selection_component(policy, &frame, worksheet).unwrap();
    (frame, audit)
}

fn composite_policy(
    base: &SourceSelectionComponentAudit,
    kotlin: &SourceSelectionComponentAudit,
) -> SourceSelectionCompositePolicy {
    SourceSelectionCompositePolicy {
        schema_version: SOURCE_SELECTION_COMPOSITE_POLICY_SCHEMA_VERSION,
        selection_id: "blind-oss-v1-complete".to_string(),
        selected_at: "2026-08-14T00:00:00Z".to_string(),
        language_quotas: SUPPORTED_LANGUAGES
            .into_iter()
            .map(|language| (language.to_string(), 1))
            .collect(),
        components: [&base, &kotlin]
            .into_iter()
            .map(|component| SourceSelectionComponentCommitment {
                selection_id: component.policy.selection_id.clone(),
                policy_sha256: component.policy_sha256.clone(),
                frame_sha256: component.frame_sha256.clone(),
            })
            .collect(),
        attestation: "Both source components were fixed before final source sealing.".to_string(),
    }
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
fn underfilled_selection_remains_auditable_without_passing_the_strict_gate() {
    let frame = frame();
    let mut worksheet = completed(&frame);
    exclude_language(
        &mut worksheet,
        "kotlin",
        SourceExclusionReason::MissingLicense,
    );

    let component =
        audit_source_selection_component(policy(&frame), &frame, worksheet.clone()).unwrap();
    assert_eq!(component.selected_counts["kotlin"], 0);
    validate_source_selection_component_against_frame(&component, &frame).unwrap();

    let error = audit_source_selection(policy(&frame), &frame, worksheet).unwrap_err();
    assert!(error.contains("filled 0 of 1 required kotlin"));
}

#[test]
fn composite_selection_closes_an_underfilled_language_without_changing_components() {
    let base_frame = frame();
    let mut worksheet = completed(&base_frame);
    exclude_language(
        &mut worksheet,
        "kotlin",
        SourceExclusionReason::MissingLicense,
    );
    let base =
        audit_source_selection_component(policy(&base_frame), &base_frame, worksheet).unwrap();
    let (kotlin_frame, kotlin) = kotlin_component();
    let composite =
        combine_source_selections(composite_policy(&base, &kotlin), vec![base, kotlin]).unwrap();

    assert_eq!(composite.selected_repositories.len(), 6);
    assert!(composite.selected_counts.values().all(|count| *count == 1));
    validate_source_selection_composite_audit(&composite).unwrap();
    validate_source_selection_component_against_frame(&composite.components[0], &base_frame)
        .unwrap();
    validate_source_selection_component_against_frame(&composite.components[1], &kotlin_frame)
        .unwrap();
}

#[test]
fn composite_selection_rejects_missing_tampered_or_duplicate_components() {
    let base_frame = frame();
    let mut worksheet = completed(&base_frame);
    exclude_language(
        &mut worksheet,
        "kotlin",
        SourceExclusionReason::MissingLicense,
    );
    let base =
        audit_source_selection_component(policy(&base_frame), &base_frame, worksheet).unwrap();
    let (_, kotlin) = kotlin_component();
    let policy = composite_policy(&base, &kotlin);

    let error = combine_source_selections(policy.clone(), vec![base.clone()]).unwrap_err();
    assert!(error.contains("every precommitted component"));

    let mut tampered = kotlin.clone();
    tampered.policy_sha256 = "0".repeat(64);
    let error =
        combine_source_selections(policy.clone(), vec![base.clone(), tampered]).unwrap_err();
    assert!(error.contains("policy or frame commitment changed"));

    let mut duplicate = kotlin;
    duplicate.selected_repositories[0] = base.selected_repositories[0].clone();
    duplicate.selected_repositories[0].selection_language = "kotlin".to_string();
    duplicate.selected_repositories[0].observed_method_count = 100;
    duplicate.component_audit_sha256 = duplicate.computed_component_audit_sha256().unwrap();
    let error = combine_source_selections(policy, vec![base, duplicate]).unwrap_err();
    assert!(error.contains("repository ledger changed"));
}

#[test]
fn source_selection_extension_preserves_completed_prior_round_exactly() {
    let mut frame = frame();
    frame.extend_from_slice(b"github.com/example/go-extension,fixture\n");
    let prior = completed(&frame);

    let extended =
        extend_source_selection(continuation_policy(&frame, &prior), &frame, prior.clone())
            .unwrap();

    assert_eq!(&extended.candidates[..12], prior.candidates.as_slice());
    assert_eq!(extended.candidates.len(), 13);
    assert!(extended.candidates[12].facts.is_none());
    validate_source_selection_worksheet(&extended.policy, &frame, &extended).unwrap();
}

#[test]
fn source_selection_extension_policy_is_derived_from_the_completed_prior_round() {
    let mut frame = frame();
    frame.extend_from_slice(b"github.com/example/go-extension,fixture\n");
    let prior = completed(&frame);
    let mut draft = continuation_policy(&frame, &prior);
    draft.continuation = None;

    let finalized = prepare_source_selection_extension(draft, &frame, &prior).unwrap();
    let commitment = finalized.continuation.as_ref().unwrap();

    assert_eq!(commitment.prior_prefix, 12);
    assert_eq!(commitment.prior_policy_sha256, prior.policy_sha256);
    assert_eq!(commitment.prior_task_sha256, prior.task_sha256);
    assert_eq!(
        commitment.prior_worksheet_sha256,
        json_sha256(&prior).unwrap()
    );
    assert_eq!(
        commitment.prior_assessments_sha256,
        json_sha256(&prior.candidates).unwrap()
    );
    extend_source_selection(finalized, &frame, prior).unwrap();
}

#[test]
fn source_selection_extension_rejects_retrofit_and_fresh_preparation() {
    let mut frame = frame();
    frame.extend_from_slice(b"github.com/example/go-extension,fixture\n");
    let prior = completed(&frame);

    let mut changed_contract = continuation_policy(&frame, &prior);
    changed_contract.minimum_methods += 1;
    let error = extend_source_selection(changed_contract, &frame, prior.clone()).unwrap_err();
    assert!(error.contains("frame, seed, limits, or quotas"));

    let continuation = continuation_policy(&frame, &prior);
    let error = prepare_source_selection(continuation, &frame).unwrap_err();
    assert!(error.contains("require extend-selection"));

    let mut tampered_commitment = continuation_policy(&frame, &prior);
    tampered_commitment
        .continuation
        .as_mut()
        .unwrap()
        .prior_assessments_sha256 = "0".repeat(64);
    let error = extend_source_selection(tampered_commitment, &frame, prior).unwrap_err();
    assert!(error.contains("completed prior round"));
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
fn source_selection_rejects_forged_revision_or_method_census() {
    let frame = frame();
    let mut revision_mismatch = completed(&frame);
    let assessment = &mut revision_mismatch.candidates[0];
    let mut facts = assessment.facts.clone().unwrap();
    facts.assessed_revision = Some("4".repeat(40));
    let payload = serde_json::to_string(&facts).unwrap();
    assessment.facts = Some(facts);
    assessment.evidence[0].payload_sha256 = sha256(payload.as_bytes());
    assessment.evidence[0].payload = payload;

    let error = audit_source_selection(policy(&frame), &frame, revision_mismatch).unwrap_err();
    assert!(error.contains("does not match its assessed language or method count"));

    let mut forged_count = completed(&frame);
    let assessment = &mut forged_count.candidates[0];
    let mut facts = assessment.facts.clone().unwrap();
    facts.method_counts.insert("python".to_string(), 1);
    let payload = serde_json::to_string(&facts).unwrap();
    assessment.facts = Some(facts);
    assessment.evidence[0].payload_sha256 = sha256(payload.as_bytes());
    assessment.evidence[0].payload = payload;

    let error = audit_source_selection(policy(&frame), &frame, forged_count).unwrap_err();
    assert!(error.contains("does not sum"));
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
