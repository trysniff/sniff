use super::*;
use sniff::benchmark::{
    HistoricalV2SelectedSlotRunSummary, HistoricalV2SlotRunDisposition, HistoricalV2SlotRunSummary,
    HistoricalV2SlotStage,
};

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
fn run_slots_rejects_a_zero_slot_admission_limit() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--max-new-slots")
        .unwrap();
    arguments[index + 1] = "0";

    assert!(Args::try_parse_from(arguments).is_err());
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
