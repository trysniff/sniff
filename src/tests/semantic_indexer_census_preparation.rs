use super::*;

#[test]
fn unprepared_go_cannot_bind_inputs_or_accept_models() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    assert!(journal.bind_inputs(go_inputs()).is_err());
    assert!(journal.finish(Ok(vec![plan()])).is_err());
    assert!(terminal(&journal).go_preparation.is_none());
    assert!(!journal.root.join("inputs.json").exists());
}

#[test]
fn interrupted_intent_survives_without_invented_launch_or_output() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod"]);
    journal.begin_go_command(".", 1).unwrap();
    assert!(journal.root.join("prepare-intent-00000000.json").is_file());
    assert!(journal.finish_go_preparation(&go_inputs()).is_err());
    assert!(
        journal
            .finish(Err(
                journal.failure("interrupted before command construction")
            ))
            .is_err()
    );
    let saved = terminal(&journal);
    let prep = saved.go_preparation.unwrap();
    assert_eq!(prep.intents.len(), 1);
    assert_eq!(prep.launches, vec![None]);
    assert_eq!(prep.outcomes, vec![None]);
    assert!(prep.completed_inputs.is_none());
    assert!(saved.inputs.is_none());
    let TerminalOutcome::Failed { failure } = saved.result else {
        panic!("accepted incomplete preparation")
    };
    assert!(failure.process.is_none());
    assert!(
        journal
            .record_go_launch(0, &preparation_command(&journal, "."))
            .is_err()
    );
}

#[test]
fn pending_launch_blocks_next_command_and_model_binding() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod", "z/go.mod"]);
    let sequence = journal.begin_go_command(".", 1).unwrap();
    journal
        .record_go_launch(sequence, &preparation_command(&journal, "."))
        .unwrap();
    assert!(journal.begin_go_command("z", 1).is_err());
    assert!(journal.bind_inputs(go_inputs()).is_err());
    assert!(journal.finish_go_preparation(&go_inputs()).is_err());
}

#[test]
fn rejected_transitions_cannot_replace_or_erase_the_current_witness() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod", "z/go.mod"]);
    prepare_command(&journal, ".", 1, Ok(output("actual root worker"))).unwrap();
    assert!(journal.begin_go_command(".", 2).is_err());
    assert!(
        journal
            .record_go_outcome(0, Ok(output("invented repeated worker")))
            .is_err()
    );
    let failure = journal
        .check_go_preparation_integrity(Err::<(), _>("source changed".into()))
        .unwrap_err();
    assert_eq!(failure.process.unwrap().stdout, "actual root worker");
    let sequence = journal.begin_go_command("z", 1).unwrap();
    assert!(
        journal
            .record_go_outcome(sequence, Ok(output("invented unlaunched worker")))
            .is_err()
    );
    let failure = journal
        .check_go_preparation_integrity(Err::<(), _>("source changed".into()))
        .unwrap_err();
    assert!(failure.process.is_none());
}

#[test]
fn module_and_attempt_order_are_checked_before_launch() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod", "z/go.mod"]);
    for (module, attempt) in [("z", 1), (".", 2), (".", 0), (".", 4), ("../z", 1)] {
        assert!(journal.begin_go_command(module, attempt).is_err());
    }
    prepare_command(&journal, ".", 1, Ok(output("root"))).unwrap();
    assert!(journal.begin_go_command(".", 1).is_err());
    assert!(journal.finish_go_preparation(&go_inputs()).is_err());
    prepare_command(&journal, "z", 1, Ok(output("neighbor"))).unwrap();
    journal.finish_go_preparation(&go_inputs()).unwrap();
    assert!(journal.begin_go_command("z", 1).is_err());
    journal.bind_inputs(go_inputs()).unwrap();
    complete_command(&journal);
    journal.finish(Ok(vec![plan()])).unwrap();
    let prep = terminal(&journal).go_preparation.unwrap();
    assert_eq!(prep.intents.len(), 2);
    assert!(prep.completed_inputs.is_some());
    assert!(prep.outcomes.iter().all(Option::is_some));
}

#[test]
fn transport_retry_records_both_attempts_in_order() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod"]);
    let mut failed = output("");
    failed.status_code = Some(1);
    failed.stderr = "connection reset by peer".into();
    failed.stderr_sha256 = format!("{:x}", Sha256::digest(failed.stderr.as_bytes()));
    prepare_command(&journal, ".", 1, Ok(failed)).unwrap();
    assert!(journal.begin_go_command(".", 1).is_err());
    assert!(journal.begin_go_command(".", 3).is_err());
    prepare_command(&journal, ".", 2, Ok(output("resolved"))).unwrap();
    journal.finish_go_preparation(&go_inputs()).unwrap();
    journal.bind_inputs(go_inputs()).unwrap();
    complete_command(&journal);
    journal.finish(Ok(vec![plan()])).unwrap();
    assert_eq!(terminal(&journal).go_preparation.unwrap().outcomes.len(), 2);
}

#[test]
fn non_retryable_results_cannot_start_another_attempt() {
    for mode in ["invalid", "timeout", "memory", "process", "no-status"] {
        let root = TempDir::new().unwrap();
        let journal = journal(root.path(), SemanticIndexerKind::Go);
        start_preparation(&journal, &["go.mod"]);
        let mut failed = output("");
        failed.status_code = Some(1);
        failed.stderr = "invalid go version".into();
        match mode {
            "timeout" => failed.timed_out = true,
            "memory" => failed.memory_limit_exceeded = true,
            "process" => failed.process_limit_exceeded = true,
            "no-status" => failed.status_code = None,
            _ => {}
        }
        failed.stderr_sha256 = format!("{:x}", Sha256::digest(failed.stderr.as_bytes()));
        prepare_command(&journal, ".", 1, Ok(failed)).unwrap();
        assert!(journal.begin_go_command(".", 2).is_err(), "{mode}");
        assert!(
            journal.finish_go_preparation(&go_inputs()).is_err(),
            "{mode}"
        );
    }
}

#[test]
fn construction_failure_does_not_borrow_preceding_module_output() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod", "z/go.mod"]);
    prepare_command(&journal, ".", 1, Ok(output("preceding module"))).unwrap();
    let sequence = journal.begin_go_command("z", 1).unwrap();
    let failure = journal.failure("command construction failed");
    let returned = journal
        .record_go_outcome(sequence, Err(failure))
        .unwrap_err();
    assert!(returned.process.is_none());
    assert!(journal.finish(Err(returned)).is_err());
    let TerminalOutcome::Failed { failure } = terminal(&journal).result else {
        panic!("accepted startup failure")
    };
    assert!(failure.process.is_none());
    assert!(!journal.root.join("prepare-launch-00000001.json").exists());
}

#[test]
fn launch_must_match_intent_and_cannot_repeat() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod"]);
    let sequence = journal.begin_go_command(".", 1).unwrap();
    assert!(
        journal
            .record_go_outcome(sequence, Ok(output("unlaunched")))
            .is_err()
    );
    let mut command = preparation_command(&journal, "z");
    assert!(journal.record_go_launch(sequence, &command).is_err());
    command.args = go_dependency_arguments(".");
    command.allow_network = false;
    assert!(journal.record_go_launch(sequence, &command).is_err());
    command.allow_network = true;
    journal.record_go_launch(sequence, &command).unwrap();
    assert!(journal.record_go_launch(sequence, &command).is_err());
    journal
        .record_go_outcome(sequence, Ok(output("prepared")))
        .unwrap();
    assert!(
        journal
            .record_go_outcome(sequence, Ok(output("repeated")))
            .is_err()
    );
}

#[test]
fn changed_runtime_and_incomplete_capture_cannot_bind_models() {
    for mode in ["executable", "sdk", "stdout", "stderr"] {
        let root = TempDir::new().unwrap();
        let journal = journal(root.path(), SemanticIndexerKind::Go);
        start_preparation(&journal, &["go.mod"]);
        let mut returned = output("prepared");
        if mode == "stdout" {
            returned.stdout.push_str("missing from hash");
        }
        if mode == "stderr" {
            returned.stderr.push_str("missing from hash");
        }
        prepare_command(&journal, ".", 1, Ok(returned)).unwrap();
        let mut inputs = go_inputs();
        if let Inputs::Go {
            executable_sha256,
            sdk_sha256,
            ..
        } = &mut inputs
        {
            if mode == "executable" {
                *executable_sha256 = "f".repeat(64);
            }
            if mode == "sdk" {
                *sdk_sha256 = "f".repeat(64);
            }
        }
        assert!(journal.finish_go_preparation(&inputs).is_err(), "{mode}");
        assert!(journal.bind_inputs(inputs).is_err(), "{mode}");
    }
}

#[test]
fn launch_preserves_ordered_environment_overrides_used_by_the_builder() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod"]);
    let sequence = journal.begin_go_command(".", 1).unwrap();
    let mut command = preparation_command(&journal, ".");
    command.env.extend([
        ("TEMP".into(), "private-temp".into()),
        ("TEMP".into(), "owned-run-temp".into()),
    ]);
    journal.record_go_launch(sequence, &command).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(
        &fs::read(journal.root.join("prepare-launch-00000000.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        saved["value"]["command"]["env"],
        serde_json::to_value(command.env).unwrap()
    );
    journal
        .record_go_outcome(sequence, Ok(output("prepared")))
        .unwrap();
    journal.finish_go_preparation(&go_inputs()).unwrap();
    journal.bind_inputs(go_inputs()).unwrap();
    complete_command(&journal);
    journal.finish(Ok(vec![plan()])).unwrap();
}

#[test]
fn tampered_or_missing_receipts_cannot_accept_a_census() {
    for name in [
        "prepare-scope.json",
        "prepare-intent-00000000.json",
        "prepare-launch-00000000.json",
        "prepare-outcome-00000000.json",
        "prepare-inputs.json",
    ] {
        for remove in [false, true] {
            let root = TempDir::new().unwrap();
            let journal = journal(root.path(), SemanticIndexerKind::Go);
            bind(&journal);
            complete_command(&journal);
            if remove {
                fs::remove_file(journal.root.join(name)).unwrap();
            } else {
                fs::write(journal.root.join(name), b"{}").unwrap();
            }
            assert!(
                journal.finish(Ok(vec![plan()])).is_err(),
                "{name} remove={remove}"
            );
            assert!(matches!(
                terminal(&journal).result,
                TerminalOutcome::Failed { .. }
            ));
        }
    }
}

#[test]
fn persistence_and_integrity_failure_keep_actual_worker_output() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    start_preparation(&journal, &["go.mod"]);
    let sequence = journal.begin_go_command(".", 1).unwrap();
    journal
        .record_go_launch(sequence, &preparation_command(&journal, "."))
        .unwrap();
    fs::write(
        journal.root.join("prepare-outcome-00000000.json"),
        b"occupied",
    )
    .unwrap();
    let failure = journal
        .record_go_outcome(sequence, Ok(output("actual worker")))
        .unwrap_err();
    assert_eq!(failure.process.as_ref().unwrap().stdout, "actual worker");
    let guard = journal
        .check_go_preparation_integrity(Err::<(), _>("source changed".into()))
        .unwrap_err();
    assert_eq!(guard.phase, SemanticIndexerRunPhase::IntegrityVerification);
    assert_eq!(guard.process.unwrap().stdout, "actual worker");
}

#[test]
fn preparation_scope_rejects_wrong_provider_and_project_paths() {
    for projects in [
        vec![],
        vec!["z/go.mod", "go.mod"],
        vec!["go.mod", "go.mod"],
        vec!["../go.mod"],
        vec!["z\\go.mod"],
        vec!["/go.mod"],
        vec!["not-go.mod"],
    ] {
        let root = TempDir::new().unwrap();
        let journal = journal(root.path(), SemanticIndexerKind::Go);
        assert!(
            journal
                .begin_go_preparation(
                    root.path(),
                    projects
                        .into_iter()
                        .map(|path| RepositoryPath(path.into()))
                        .collect(),
                    go_inputs()
                )
                .is_err()
        );
        assert!(!journal.root.join("prepare-scope.json").exists());
    }
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::TypeScriptJavaScript);
    assert!(
        journal
            .begin_go_preparation(
                root.path(),
                vec![RepositoryPath("go.mod".into())],
                go_inputs()
            )
            .is_err()
    );
}
