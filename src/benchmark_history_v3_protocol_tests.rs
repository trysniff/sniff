use super::*;

fn sha(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn protocol() -> HistoricalV3Protocol {
    let source_frames = HistoricalV3Language::ALL
        .into_iter()
        .enumerate()
        .map(|(index, language)| HistoricalV3SourceFrameBinding {
            language,
            frame_id: format!("synthetic-frame-{index}"),
            policy_sha256: sha('1'),
            manifest_sha256: sha('2'),
            frame_sha256: sha('3'),
            repository_count: 500,
        })
        .collect();
    seal_historical_v3_protocol(HistoricalV3Protocol {
        schema_version: HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION,
        protocol_id: "synthetic-historical-v3".to_string(),
        protocol_contract: PROTOCOL_CONTRACT.to_string(),
        ranking_domain: RANKING_DOMAIN.to_string(),
        ranking_seed: sha('4'),
        prior_benchmark_identity_seal_sha256: sha('5'),
        repository_created_after_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        languages: HistoricalV3Language::ALL.to_vec(),
        source_frames,
        candidate_window: HistoricalV3CandidateWindow {
            merged_at_or_after_utc: "2025-01-01T00:00:00Z".to_string(),
            merged_before_utc: "2026-01-01T00:00:00Z".to_string(),
            github_api_version: GITHUB_API_VERSION.to_string(),
            partition: CANDIDATE_PARTITION.to_string(),
            pagination: CANDIDATE_PAGINATION.to_string(),
        },
        allowed_metadata_fields: HistoricalV3AllowedMetadataField::ALL.to_vec(),
        forbidden_metadata_fields: HistoricalV3ForbiddenMetadataField::ALL.to_vec(),
        mechanical_requirements: HistoricalV3MechanicalRequirement::ALL.to_vec(),
        mechanical_policy: HistoricalV3MechanicalPolicy {
            production_method_minimum: 1,
            production_method_maximum: 500,
            generated_path_segments: vec!["generated".to_string()],
            vendored_path_segments: vec!["vendor".to_string()],
            documentation_path_segments: vec!["docs".to_string()],
            fixture_path_segments: vec!["fixtures".to_string()],
            test_path_segments: vec!["tests".to_string()],
            test_file_suffixes: vec![".test.ts".to_string(), "_test.go".to_string()],
        },
        test_recipe_policy: HistoricalV3TestRecipePolicy {
            selector_contract: TEST_RECIPE_SELECTOR_CONTRACT.to_string(),
            selectors: HistoricalV3TestRecipeSelector::ALL.to_vec(),
            maximum_input_file_bytes: 4 * 1024 * 1024,
            maximum_total_input_bytes: 16 * 1024 * 1024,
            execution_platform: "linux/amd64".to_string(),
            network_disabled_during_tests: true,
            environments: HistoricalV3Language::ALL
                .into_iter()
                .map(|language| HistoricalV3TestEnvironmentBinding {
                    language,
                    image_digest: format!("sha256:{}", "a".repeat(64)),
                    toolchain_manifest_sha256: "b".repeat(64),
                    dependency_store_sha256: "c".repeat(64),
                })
                .collect(),
        },
        identical_test_policy: HistoricalV3IdenticalTestPolicy {
            execution_contract: IDENTICAL_TEST_EXECUTION_POLICY_CONTRACT.to_string(),
            cpu_limit_millis: 4_000,
            memory_limit_bytes: 8 * 1024 * 1024 * 1024,
            process_limit: 1_024,
            temporary_filesystem_bytes: 2 * 1024 * 1024 * 1024,
            preparation_command_timeout_seconds: 30 * 60,
            test_command_timeout_seconds: 60 * 60,
            retained_output_bytes: 64 * 1024,
            network_disabled_during_all_commands: true,
            ephemeral_container_filesystem: true,
            host_source_mounts_forbidden: true,
            all_capabilities_dropped: true,
            no_new_privileges: true,
        },
        human_review_policy: HistoricalV3HumanReviewPolicy {
            source_only_review: true,
            independent_reviewers: 2,
            distinct_dispute_resolver: true,
            reviewers_must_not_see_sniff_output: true,
            reviewers_must_not_see_repository_identity: true,
            reviewers_must_not_see_change_metadata: true,
            reviewers_must_not_see_each_other_labels: true,
            human_only_review: true,
            complete_source_context_required: true,
            behavior_evidence_required: true,
            exact_before_mechanism_required: true,
            exact_after_removal_required: true,
            relocation_check_required: true,
            simpler_counterfactual_required: true,
        },
        stop_rule: HistoricalV3StopRule {
            accepted_target_per_language: 40,
            distinct_repository_floor_per_language: 20,
            accepted_case_cap_per_repository: 4,
            reviewable_candidate_cap_per_repository: 8,
            adjudication_cap_per_language: 400,
        },
        no_fallbacks: true,
        model_access_forbidden: true,
        sniff_output_access_forbidden: true,
        protocol_sha256: String::new(),
    })
    .unwrap()
}

fn identity(repository_id: u64, pull_request_number: u64) -> HistoricalV3CandidateIdentity {
    HistoricalV3CandidateIdentity {
        language: HistoricalV3Language::Rust,
        repository_id,
        pull_request_number,
        base_commit: "a".repeat(40),
        head_commit: "b".repeat(40),
        merge_commit: "c".repeat(40),
    }
}

fn review_record(
    candidate: &HistoricalV3CandidateTask,
    disposition: HistoricalV3ReviewDisposition,
) -> HistoricalV3ReviewRecord {
    HistoricalV3ReviewRecord {
        stream_rank: candidate.stream_rank,
        rank_sha256: candidate.rank_sha256.clone(),
        language: candidate.identity.language,
        repository_id: candidate.identity.repository_id,
        disposition,
    }
}

fn review_task(
    protocol: &HistoricalV3Protocol,
    repositories: impl IntoIterator<Item = u64>,
) -> HistoricalV3StreamTask {
    let identities = repositories
        .into_iter()
        .enumerate()
        .map(|(index, repository_id)| identity(repository_id, index as u64 + 1))
        .collect();
    prepare_historical_v3_stream_task(protocol, identities).unwrap()
}

#[test]
fn seals_only_the_locked_blind_fail_closed_protocol() {
    let protocol = protocol();
    validate_historical_v3_protocol(&protocol).unwrap();

    let mut changed = protocol.clone();
    changed.repository_created_after_utc = "2026-08-06T20:46:11Z".to_string();
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("repository creation cutoff changed")
    );

    let mut changed = protocol.clone();
    changed.mechanical_policy.production_method_maximum = 0;
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("method bounds")
    );

    let mut changed = protocol.clone();
    changed.mechanical_policy.test_path_segments = vec!["generated".to_string()];
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("path role segments must be disjoint")
    );

    let mut changed = protocol.clone();
    changed.stop_rule.adjudication_cap_per_language = 401;
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("stopping rule changed")
    );

    let mut changed = protocol.clone();
    changed.test_recipe_policy.selectors.swap(0, 1);
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("test-recipe policy")
    );

    let mut changed = protocol.clone();
    changed.test_recipe_policy.execution_platform = "linux/arm64".to_string();
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("test-recipe policy")
    );

    let mut changed = protocol.clone();
    changed.test_recipe_policy.environments.pop();
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("every language")
    );

    let mut changed = protocol.clone();
    changed
        .identical_test_policy
        .network_disabled_during_all_commands = false;
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("identical-test policy")
    );

    let mut changed = protocol.clone();
    changed.human_review_policy.independent_reviewers = 3;
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("human-review policy")
    );

    let mut changed = protocol.clone();
    changed.model_access_forbidden = false;
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("remain blind")
    );

    let mut changed = protocol.clone();
    changed.candidate_window.pagination = "github_link_header_until_exhausted".to_string();
    assert!(
        seal_historical_v3_protocol(changed)
            .unwrap_err()
            .contains("candidate window is invalid")
    );

    let mut changed = protocol;
    changed.protocol_id.push_str("-tampered");
    assert!(
        validate_historical_v3_protocol(&changed)
            .unwrap_err()
            .contains("commitment changed")
    );
}

#[test]
fn ranks_and_commits_the_same_candidate_stream_independent_of_input_order() {
    let protocol = protocol();
    let identities = vec![identity(30, 3), identity(10, 1), identity(20, 2)];
    let mut reversed = identities.clone();
    reversed.reverse();

    let task = prepare_historical_v3_stream_task(&protocol, identities).unwrap();
    let same_task = prepare_historical_v3_stream_task(&protocol, reversed).unwrap();
    assert_eq!(task, same_task);
    assert_eq!(
        task.candidates
            .iter()
            .map(|candidate| candidate.stream_rank)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    validate_historical_v3_stream_task(&protocol, &task).unwrap();

    let mut changed = task;
    changed.candidates.swap(0, 1);
    assert!(
        validate_historical_v3_stream_task(&protocol, &changed)
            .unwrap_err()
            .contains("immutable candidates")
    );
}

#[test]
fn rejects_duplicate_candidate_identities_and_metadata_tampering() {
    let protocol = protocol();
    let duplicate = identity(10, 1);
    assert!(
        prepare_historical_v3_stream_task(&protocol, vec![duplicate.clone(), duplicate])
            .unwrap_err()
            .contains("identity is duplicated")
    );

    let mut changed = identity(10, 1);
    changed.merge_commit = "not-a-git-object".to_string();
    assert!(
        historical_v3_candidate_rank_sha256(&protocol, &changed)
            .unwrap_err()
            .contains("full lowercase Git object ID")
    );
}

#[test]
fn rejects_review_evidence_detached_from_the_committed_stream() {
    let protocol = protocol();
    let task = review_task(&protocol, [10, 20]);
    let mut record = review_record(&task.candidates[0], HistoricalV3ReviewDisposition::Rejected);
    record.repository_id += 1;

    assert!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &[record],
        )
        .unwrap_err()
        .contains("not bound")
    );
}

#[test]
fn rejects_skipped_language_ranks() {
    let protocol = protocol();
    let task = review_task(&protocol, [1, 2, 3]);
    let skipped = review_record(&task.candidates[1], HistoricalV3ReviewDisposition::Rejected);
    assert!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &[skipped],
        )
        .unwrap_err()
        .contains("not bound")
    );
}

#[test]
fn rejects_unresolved_disputes_before_stopping() {
    let protocol = protocol();
    let task = review_task(&protocol, [1]);
    let disputed = review_record(&task.candidates[0], HistoricalV3ReviewDisposition::Disputed);
    assert!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &[disputed],
        )
        .unwrap_err()
        .contains("unresolved dispute")
    );
}

#[test]
fn language_prefix_ignores_interleaved_other_language_ranks() {
    let protocol = protocol();
    let mut python = identity(2, 2);
    python.language = HistoricalV3Language::Python;
    let task =
        prepare_historical_v3_stream_task(&protocol, vec![identity(1, 1), python, identity(3, 3)])
            .unwrap();
    let records = task
        .candidates
        .iter()
        .filter(|candidate| candidate.identity.language == HistoricalV3Language::Rust)
        .map(|candidate| review_record(candidate, HistoricalV3ReviewDisposition::Rejected))
        .collect::<Vec<_>>();
    assert!(matches!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &records,
        )
        .unwrap(),
        HistoricalV3StopStatus::FailedSourceExhausted { reviewed: 2, .. }
    ));
}

#[test]
fn stops_at_the_first_diverse_forty_case_prefix() {
    let protocol = protocol();
    let repositories = (1..=20).flat_map(|repository| [repository, repository]);
    let task = review_task(&protocol, repositories);
    let records = task
        .candidates
        .iter()
        .map(|candidate| review_record(candidate, HistoricalV3ReviewDisposition::Accepted))
        .collect::<Vec<_>>();

    assert_eq!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &records,
        )
        .unwrap(),
        HistoricalV3StopStatus::TargetReached {
            reviewed_prefix: 40,
            accepted: 40,
            distinct_accepted_repositories: 20,
        }
    );

    let repositories = (1..=20)
        .flat_map(|repository| [repository, repository])
        .chain([21]);
    let continued_task = review_task(&protocol, repositories);
    let continued = continued_task
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let disposition = if index < 40 {
                HistoricalV3ReviewDisposition::Accepted
            } else {
                HistoricalV3ReviewDisposition::Rejected
            };
            review_record(candidate, disposition)
        })
        .collect::<Vec<_>>();
    assert!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &continued_task,
            HistoricalV3Language::Rust,
            &continued,
        )
        .unwrap_err()
        .contains("continued past")
    );
}

#[test]
fn fails_at_the_locked_cap_and_rejects_repository_concentration() {
    let protocol = protocol();
    let task = review_task(&protocol, 1..=400);
    let records = task
        .candidates
        .iter()
        .map(|candidate| review_record(candidate, HistoricalV3ReviewDisposition::Rejected))
        .collect::<Vec<_>>();
    assert!(matches!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &records,
        )
        .unwrap(),
        HistoricalV3StopStatus::FailedAdjudicationCap { reviewed: 400, .. }
    ));

    let concentrated_task = review_task(&protocol, [1, 1, 1, 1, 1]);
    let concentrated = concentrated_task
        .candidates
        .iter()
        .map(|candidate| review_record(candidate, HistoricalV3ReviewDisposition::Accepted))
        .collect::<Vec<_>>();
    assert!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &concentrated_task,
            HistoricalV3Language::Rust,
            &concentrated,
        )
        .unwrap_err()
        .contains("acceptance cap")
    );
}

#[test]
fn distinguishes_more_work_from_terminal_source_exhaustion() {
    let protocol = protocol();
    let task = review_task(&protocol, [1, 2]);
    let first = review_record(&task.candidates[0], HistoricalV3ReviewDisposition::Rejected);
    let second = review_record(&task.candidates[1], HistoricalV3ReviewDisposition::Rejected);
    assert!(matches!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            std::slice::from_ref(&first),
        )
        .unwrap(),
        HistoricalV3StopStatus::Continue { reviewed: 1, .. }
    ));
    assert!(matches!(
        evaluate_historical_v3_review_prefix(
            &protocol,
            &task,
            HistoricalV3Language::Rust,
            &[first, second],
        )
        .unwrap(),
        HistoricalV3StopStatus::FailedSourceExhausted { reviewed: 2, .. }
    ));
}
