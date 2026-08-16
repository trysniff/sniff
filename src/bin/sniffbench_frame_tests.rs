use super::*;

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
fn run_slots_rejects_a_zero_stage_slice() {
    let mut arguments = run_slots_arguments();
    let index = arguments
        .iter()
        .position(|value| *value == "--max-new-stages-per-slot")
        .unwrap();
    arguments[index + 1] = "0";

    assert!(Args::try_parse_from(arguments).is_err());
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
        "--max-new-stages-per-slot",
        "1",
    ]
}
