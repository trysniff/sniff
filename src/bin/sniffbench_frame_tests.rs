use super::*;
use sniff::benchmark::{
    HistoricalV2SelectedSlotRunSummary, HistoricalV2SemanticCheckpointKind,
    HistoricalV2SemanticCheckpointProgress, HistoricalV2SemanticSnapshotSide,
    HistoricalV2SemanticWorldProgress, HistoricalV2SlotRunDisposition, HistoricalV2SlotRunSummary,
    HistoricalV2SlotStage,
};

#[test]
fn durable_unit_progress_changes_the_hosted_progress_line_without_an_assembly() {
    let mut world = HistoricalV2SemanticWorldProgress {
        language: "go".to_string(),
        slot_number: 122,
        side: HistoricalV2SemanticSnapshotSide::Patched,
        family: "go".to_string(),
        world: "world-id".to_string(),
        variant_identity: None,
        dimensions: Default::default(),
        planned_unit_count: 15,
        completed_unit_count: 0,
        next_unit_id: Some("document-00000000".to_string()),
        durable_unit_count: 0,
        next_durable_unit_id: Some("document-00000000".to_string()),
    };
    let before = sniffbench_frame_run::semantic_world_progress_line(&world);
    world.durable_unit_count = 1;
    world.next_durable_unit_id = Some("document-00000001".to_string());
    let after = sniffbench_frame_run::semantic_world_progress_line(&world);

    assert_ne!(before, after);
    assert!(before.contains("units=0/15 next=document-00000000 durable_units=0/15"));
    assert!(after.contains("units=0/15 next=document-00000000 durable_units=1/15"));
    assert!(after.starts_with("  go/slot-0122 "));
}

#[test]
fn committed_semantic_checkpoint_line_enters_the_durable_progress_ledger() {
    let checkpoint = HistoricalV2SemanticCheckpointProgress {
        language: "go".to_string(),
        slot_number: 122,
        side: HistoricalV2SemanticSnapshotSide::Base,
        kind: HistoricalV2SemanticCheckpointKind::Contribution,
        identity: "a".repeat(64),
        checkpoint_sha256: "b".repeat(64),
    };
    let line = sniffbench_frame_run::semantic_checkpoint_progress_line(&checkpoint);
    assert_eq!(
        line,
        format!(
            "  go/slot-0122 side=base checkpoint=contribution identity={} sha256={}",
            "a".repeat(64),
            "b".repeat(64)
        )
    );
}

#[test]
fn run_slots_requires_every_execution_boundary_explicitly() {
    let parsed = Args::try_parse_from(run_slots_arguments()).unwrap();
    let Command::RunSlots { .. } = parsed.command else {
        panic!("run-slots command was not parsed");
    };
}

#[test]
fn run_slots_has_no_implicit_docker_executable() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--docker-executable")
        .unwrap();
    arguments.drain(index..=index + 1);

    assert!(Args::try_parse_from(arguments).is_err());
}

#[test]
fn run_slots_has_no_unbounded_slot_admission_mode() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--max-new-slots")
        .unwrap();
    arguments.drain(index..=index + 1);

    assert!(Args::try_parse_from(arguments).is_err());
}

#[test]
fn run_slots_accepts_a_zero_slot_admission_limit_for_resume_only_sweeps() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--max-new-slots")
        .unwrap();
    arguments[index + 1] = "0";

    let parsed = Args::try_parse_from(arguments).unwrap();
    let Command::RunSlots { .. } = parsed.command else {
        panic!("run-slots command was not parsed");
    };
}

#[test]
fn run_slots_rejects_a_zero_stage_slice() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--max-new-stages-per-slot")
        .unwrap();
    arguments[index + 1] = "0";

    assert!(Args::try_parse_from(arguments).is_err());
}

#[test]
fn run_slots_rejects_an_unknown_stage_ceiling() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--through-stage")
        .unwrap();
    arguments[index + 1] = "not-a-stage";

    assert!(Args::try_parse_from(arguments).is_err());
}

#[test]
fn run_slots_reports_only_slots_that_executed_in_the_current_slice() {
    let untouched = HistoricalV2SelectedSlotRunSummary {
        language: "go".to_string(),
        slot_number: 2,
        canonical_repository: "example/untouched".to_string(),
        run: HistoricalV2SlotRunSummary {
            resumed_after_sequence: 0,
            executed_stages: Vec::new(),
            terminal_checkpoint_sha256: None,
            disposition: HistoricalV2SlotRunDisposition::Paused {
                next_stage: HistoricalV2SlotStage::Payload,
            },
        },
    };
    let mut touched = untouched.clone();
    touched
        .run
        .executed_stages
        .push(HistoricalV2SlotStage::Payload);

    assert!(!sniffbench_frame_run::should_report_slot(&untouched));
    assert!(sniffbench_frame_run::should_report_slot(&touched));
}

#[test]
fn state_status_requires_every_frozen_boundary() {
    for required in [
        "--protocol",
        "--artifact-root",
        "--frame",
        "--exclusions",
        "--selection",
        "--payloads",
        "--state-root",
    ] {
        let mut arguments = state_status_arguments();
        let index = arguments
            .iter()
            .position(|value| *value == required)
            .unwrap();
        arguments.drain(index..=index + 1);
        assert!(
            Args::try_parse_from(arguments).is_err(),
            "{required} was optional"
        );
    }
}

#[test]
fn recover_slot_work_parses_every_frozen_boundary() {
    let parsed = Args::try_parse_from(recover_slot_work_arguments()).unwrap();
    let Command::RecoverSlotWork { .. } = parsed.command else {
        panic!("recover-slot-work command was not parsed");
    };
}

#[test]
fn recover_slot_work_requires_every_frozen_boundary() {
    for required in [
        "--protocol",
        "--artifact-root",
        "--frame",
        "--exclusions",
        "--selection",
        "--payloads",
        "--work-root",
    ] {
        let mut arguments = recover_slot_work_arguments();
        let index = arguments
            .iter()
            .position(|value| *value == required)
            .unwrap();
        arguments.drain(index..=index + 1);
        assert!(
            Args::try_parse_from(arguments).is_err(),
            "{required} was optional"
        );
    }
}

#[test]
fn replay_compiler_census_requires_an_explicit_slot_identity_and_roots() {
    let parsed = Args::try_parse_from(replay_compiler_census_arguments()).unwrap();
    let Command::ReplayCompilerCensus { .. } = parsed.command else {
        panic!("replay-compiler-census command was not parsed");
    };
    for required in ["--state-root", "--work-root", "--language", "--slot-number"] {
        let mut arguments = replay_compiler_census_arguments();
        let index = arguments
            .iter()
            .position(|value| *value == required)
            .unwrap();
        arguments.drain(index..=index + 1);
        assert!(
            Args::try_parse_from(arguments).is_err(),
            "{required} was optional"
        );
    }
}

fn run_slots_arguments() -> Vec<&'static str> {
    vec![
        "sniffbench-frame",
        "run-slots",
        "--protocol",
        "protocol.json",
        "--artifact-root",
        "artifacts",
        "--frame",
        "frame.json",
        "--exclusions",
        "exclusions.json",
        "--selection",
        "selection.json",
        "--payloads",
        "payloads.json",
        "--state-root",
        "state",
        "--work-root",
        "work",
        "--harness-repository-root",
        "harness",
        "--docker-executable",
        "docker-test",
        "--max-new-slots",
        "1",
        "--max-new-stages-per-slot",
        "1",
        "--through-stage",
        "payload",
    ]
}

fn recover_slot_work_arguments() -> Vec<&'static str> {
    vec![
        "sniffbench-frame",
        "recover-slot-work",
        "--protocol",
        "protocol.json",
        "--artifact-root",
        "artifacts",
        "--frame",
        "frame.json",
        "--exclusions",
        "exclusions.json",
        "--selection",
        "selection.json",
        "--payloads",
        "payloads.json",
        "--work-root",
        "work",
    ]
}

fn replay_compiler_census_arguments() -> Vec<&'static str> {
    vec![
        "sniffbench-frame",
        "replay-compiler-census",
        "--protocol",
        "protocol.json",
        "--artifact-root",
        "artifacts",
        "--frame",
        "frame.json",
        "--exclusions",
        "exclusions.json",
        "--selection",
        "selection.json",
        "--payloads",
        "payloads.json",
        "--state-root",
        "state",
        "--work-root",
        "work",
        "--language",
        "go",
        "--slot-number",
        "123",
    ]
}

fn state_status_arguments() -> Vec<&'static str> {
    vec![
        "sniffbench-frame",
        "state-status",
        "--protocol",
        "protocol.json",
        "--artifact-root",
        "artifacts",
        "--frame",
        "frame.json",
        "--exclusions",
        "exclusions.json",
        "--selection",
        "selection.json",
        "--payloads",
        "payloads.json",
        "--state-root",
        "state",
    ]
}
