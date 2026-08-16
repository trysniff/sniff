use super::*;

#[test]
fn complete_identical_event_sequence_is_accepted() {
    let plan = fixture_plan();
    let raw = HistoricalV2RawIdenticalTestExecution {
        image_id: image_id(),
        events: complete_events(&plan),
        outcome: HistoricalV2IdenticalTestOutcome::Passed,
    };
    validate_raw_execution(&plan, &raw).unwrap();
    let mut execution = seal_execution(&plan, raw).unwrap();
    validate_historical_v2_identical_test_execution(&plan, &execution).unwrap();
    execution.image_id = format!("sha256:{}", "f".repeat(64));
    assert!(validate_historical_v2_identical_test_execution(&plan, &execution).is_err());
}

#[test]
fn execution_cannot_skip_or_reorder_a_side() {
    let plan = fixture_plan();
    let mut skipped = complete_events(&plan);
    skipped.remove(1);
    let raw = HistoricalV2RawIdenticalTestExecution {
        image_id: image_id(),
        events: skipped,
        outcome: HistoricalV2IdenticalTestOutcome::Passed,
    };
    assert!(validate_raw_execution(&plan, &raw).is_err());

    let mut reordered = complete_events(&plan);
    reordered.swap(0, 1);
    let raw = HistoricalV2RawIdenticalTestExecution {
        image_id: image_id(),
        events: reordered,
        outcome: HistoricalV2IdenticalTestOutcome::Passed,
    };
    assert!(validate_raw_execution(&plan, &raw).is_err());
}

#[test]
fn terminal_failure_must_match_the_last_command() {
    let plan = fixture_plan();
    let mut events = complete_events(&plan);
    events[1].exit_code = Some(1);
    events.truncate(2);
    let accepted = HistoricalV2RawIdenticalTestExecution {
        image_id: image_id(),
        events: events.clone(),
        outcome: HistoricalV2IdenticalTestOutcome::Excluded {
            reason: HistoricalV2IdenticalTestExclusionReason::TestCommandsFailed {
                side: HistoricalV2ExecutionSide::Base,
            },
        },
    };
    validate_raw_execution(&plan, &accepted).unwrap();

    let mut continued = accepted.clone();
    continued.events.push(complete_events(&plan)[2].clone());
    assert!(validate_raw_execution(&plan, &continued).is_err());

    let mut wrong_reason = accepted;
    wrong_reason.outcome = HistoricalV2IdenticalTestOutcome::Excluded {
        reason: HistoricalV2IdenticalTestExclusionReason::InstallCommandFailed {
            side: HistoricalV2ExecutionSide::Base,
            command_index: 0,
        },
    };
    assert!(validate_raw_execution(&plan, &wrong_reason).is_err());
}

#[test]
fn frozen_policy_forbids_networked_tests_and_privileged_containers() {
    let policy = frozen_policy("linux/amd64");
    assert!(policy.install_network_enabled);
    assert!(!policy.test_network_enabled);
    assert!(policy.ephemeral_root_filesystem);
    assert!(policy.host_source_mounts_forbidden);
    assert!(policy.all_capabilities_dropped);
    assert!(policy.no_new_privileges);
    assert!(policy.cpu_limit_millis > 0);
    assert!(policy.memory_limit_bytes > 0);
    assert!(policy.process_limit > 0);
}

fn fixture_plan() -> HistoricalV2IdenticalTestPlan {
    let install_commands = vec!["python -m pip install -e .".to_string()];
    let test_commands = vec!["pytest -q".to_string(), "python smoke.py".to_string()];
    seal_plan(HistoricalV2IdenticalTestPlan {
        schema_version: HISTORICAL_V2_IDENTICAL_TEST_PLAN_SCHEMA_VERSION,
        plan_contract: PLAN_CONTRACT.to_string(),
        assessment_identity_sha256: digest(b"identity"),
        qualification_sha256: digest(b"qualification"),
        test_recipe_sha256: digest(b"recipe"),
        execution_harness_sha256: digest(b"harness"),
        materialization_sha256: digest(b"materialization"),
        test_materialization_sha256: Some(digest(b"test-materialization")),
        language: "python".to_string(),
        slot_number: 1,
        canonical_repository: "example/project".to_string(),
        base_commit_oid: "1".repeat(40),
        patched_commit_oid: "2".repeat(40),
        base_image_name: "python_3.11".to_string(),
        dockerfile_path: "base_dockerfiles/Dockerfile_python_3.11".to_string(),
        dockerfile_blob_oid: "3".repeat(40),
        install_command_sha256: install_commands
            .iter()
            .map(|command| digest(command.as_bytes()))
            .collect(),
        install_commands,
        test_script_sha256: digest(test_script(&test_commands).as_bytes()),
        test_commands,
        policy: frozen_policy("linux/amd64"),
        plan_sha256: String::new(),
    })
    .unwrap()
}

fn complete_events(
    plan: &HistoricalV2IdenticalTestPlan,
) -> Vec<HistoricalV2ExecutionCommandEvidence> {
    expected_commands(plan)
        .into_iter()
        .map(|expected| HistoricalV2ExecutionCommandEvidence {
            side: expected.side,
            phase: expected.phase,
            command_index: expected.command_index,
            command_sha256: expected.command_sha256,
            exit_code: Some(0),
            timed_out: false,
            duration_millis: 10,
            stdout_sha256: digest(b"stdout"),
            stderr_sha256: digest(b"stderr"),
            retained_stdout: "stdout".to_string(),
            retained_stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
        .collect()
}

fn image_id() -> String {
    format!("sha256:{}", digest(b"image"))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
