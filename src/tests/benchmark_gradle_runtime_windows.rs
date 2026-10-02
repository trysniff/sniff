use super::super::non_blind_history_runtime_support::resolve_on_path;
use super::*;

fn version_probe(direct_java: bool) {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("cache");
    fs::create_dir(&cache).unwrap();
    let command = vec!["{sniff_gradle}".to_string(), "--version".to_string()];
    let mut plan = prepare_historical_runtime(root.path(), &cache, &command).unwrap();
    if direct_java {
        plan.command.program = resolve_on_path("java")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        plan.command.args = vec![
            "-XshowSettings:properties".to_string(),
            "-version".to_string(),
        ];
    }
    plan.command.timeout = Duration::from_secs(30);
    plan.command.output_limit = 64 * 1024;
    let output = crate::sandbox::run(&plan.command).unwrap();
    assert!(
        !output.timed_out,
        "selected runtime did not start: {output:?}"
    );
    assert_eq!(
        output.status_code,
        Some(0),
        "selected runtime failed: {output:?}"
    );
    assert!(!output.memory_limit_exceeded && !output.process_limit_exceeded);
    let expected = if direct_java { "17.0." } else { "Gradle 8.8" };
    assert!(
        output.stdout.contains(expected) || output.stderr.contains(expected),
        "selected runtime output did not identify {expected}: {output:?}",
    );
    if direct_java {
        let home = output
            .stderr
            .lines()
            .find_map(|line| line.trim().strip_prefix("java.home = "))
            .expect("selected JVM must report its named home");
        let selected = resolve_on_path("java").unwrap();
        assert_eq!(
            Path::new(home).file_name(),
            selected
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name),
            "sandbox JVM lost the selected installation's directory name: {home}"
        );
    }
}

#[test]
#[ignore = "requires the selected Gradle 8.8 distribution and JDK 17 in AppContainer"]
fn selected_jvm_starts_in_the_gradle_runtime_sandbox() {
    version_probe(true);
}

#[test]
#[ignore = "requires the selected Gradle 8.8 distribution and JDK 17 in AppContainer"]
fn selected_gradle_reports_its_version_in_the_runtime_sandbox() {
    version_probe(false);
}
