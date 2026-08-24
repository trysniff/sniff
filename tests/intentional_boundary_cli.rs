use std::process::Command;

#[test]
fn collection_help_builds_on_the_sized_runner_stack() {
    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .args(["benchmark", "collect-intentional-frame", "--help"])
        .output()
        .expect("run intentional-boundary collection help");

    assert!(
        output.status.success(),
        "help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("help must be UTF-8");
    assert!(stdout.contains("without model access"));
    assert!(stdout.contains("--max-new-ranks"));
}
