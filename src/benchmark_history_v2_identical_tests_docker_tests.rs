use super::*;
use crate::benchmark::{
    HistoricalV2ExecutionErrorKind, HistoricalV2ExecutionPolicy, HistoricalV2IdenticalTestPlan,
};

#[test]
fn container_creation_enforces_every_frozen_boundary() {
    let root = tempfile::tempdir().unwrap();
    let plan = fixture_plan();
    let request = HistoricalV2IdenticalTestExecutionRequest {
        plan: &plan,
        harness_repository_root: root.path(),
        repository_root: root.path(),
    };
    let args = container_create_args(
        &request,
        &format!("sha256:{}", "a".repeat(64)),
        "network",
        "container",
        "volume",
    )
    .into_iter()
    .map(|value| value.into_string().unwrap())
    .collect::<Vec<_>>();
    assert!(args.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--security-opt", "no-new-privileges"])
    );
    assert!(args.contains(&"--pids-limit".to_string()));
    assert!(args.contains(&"--memory".to_string()));
    assert!(args.contains(&"--cpus".to_string()));
    assert!(args.contains(&"--tmpfs".to_string()));
    assert!(!args.contains(&"--privileged".to_string()));
    assert!(!args.contains(&"--cap-add".to_string()));
    assert!(!args.iter().any(|argument| argument.contains("type=bind")));
    assert!(args.contains(&plan_label(&plan.plan_sha256)));
}

#[test]
fn container_exec_trusts_only_the_ephemeral_repository_for_every_git_child() {
    let args = container_exec_args("container", "git status")
        .into_iter()
        .map(|value| value.into_string().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        args,
        [
            "exec",
            "--env",
            "GIT_CONFIG_COUNT=1",
            "--env",
            "GIT_CONFIG_KEY_0=safe.directory",
            "--env",
            "GIT_CONFIG_VALUE_0=/workspace",
            "--workdir",
            "/workspace",
            "container",
            "/bin/bash",
            "-lc",
            "git status",
        ]
    );
    assert!(!args.iter().any(|argument| argument.contains('*')));
    assert!(!args.iter().any(|argument| argument.contains("--global")));
    assert!(!args.iter().any(|argument| argument == "--user"));
}

#[test]
fn workspace_permission_control_is_separate_and_receives_only_fowner() {
    let root = tempfile::tempdir().unwrap();
    let plan = fixture_plan();
    let request = HistoricalV2IdenticalTestExecutionRequest {
        plan: &plan,
        harness_repository_root: root.path(),
        repository_root: root.path(),
    };
    let args = workspace_permission_container_create_args(
        &request,
        &format!("sha256:{}", "a".repeat(64)),
        "permission-container",
        "workspace-volume",
    )
    .into_iter()
    .map(|value| value.into_string().unwrap())
    .collect::<Vec<_>>();

    assert_eq!(
        args,
        [
            "create",
            "--name",
            "permission-container",
            "--label",
            "org.trysniff.historical-v2=true",
            "--label",
            &plan_label(&plan.plan_sha256),
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "FOWNER",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "16",
            "--memory",
            "67108864",
            "--cpus",
            "0.250",
            "--read-only",
            "--mount",
            "type=volume,source=workspace-volume,target=/workspace",
            "--workdir",
            "/workspace",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/chmod",
            &format!("sha256:{}", "a".repeat(64)),
            "-R",
            "a+rwX",
            "--",
            "/workspace",
        ]
    );
    assert!(
        !args
            .iter()
            .any(|argument| argument == "/bin/bash" || argument == "/bin/sh")
    );
    assert!(
        !args
            .iter()
            .any(|argument| argument == "-c" || argument == "-lc")
    );
    assert!(!args.contains(&"--privileged".to_string()));
    assert!(!args.iter().any(|argument| argument.contains("type=bind")));
    assert_eq!(
        args.windows(2)
            .filter(|pair| pair[0] == "--cap-add")
            .map(|pair| pair[1].as_str())
            .collect::<Vec<_>>(),
        ["FOWNER"]
    );
}

#[test]
fn resource_names_are_stable_across_process_restarts() {
    let plan = fixture_plan();
    let first = ResourceNames::new(&plan.plan_sha256);
    let second = ResourceNames::new(&plan.plan_sha256);

    assert_eq!(first.network, second.network);
    assert_eq!(first.base_container, second.base_container);
    assert_eq!(first.patched_container, second.patched_container);
    assert_eq!(first.base_volume, second.base_volume);
    assert_eq!(first.patched_volume, second.patched_volume);
}

#[test]
fn recovery_rejects_unexpected_plan_labelled_resources() {
    let plan = fixture_plan();
    let names = ResourceNames::new(&plan.plan_sha256);
    require_expected_resources(
        std::slice::from_ref(&names.base_container),
        [
            &names.base_container,
            &names.patched_container,
            &names.base_permission_container,
            &names.patched_permission_container,
        ],
        "container",
    )
    .unwrap();
    require_expected_resources(
        std::slice::from_ref(&names.base_permission_container),
        [
            &names.base_container,
            &names.patched_container,
            &names.base_permission_container,
            &names.patched_permission_container,
        ],
        "container",
    )
    .unwrap();

    let error = require_expected_resources(
        &["unrelated-container".to_string()],
        [
            &names.base_container,
            &names.patched_container,
            &names.base_permission_container,
            &names.patched_permission_container,
        ],
        "container",
    )
    .unwrap_err();
    assert!(error.detail.contains("unexpected"));
}

#[test]
fn missing_docker_is_retryable_infrastructure_unavailability() {
    let root = tempfile::tempdir().unwrap();
    let plan = fixture_plan();
    let request = HistoricalV2IdenticalTestExecutionRequest {
        plan: &plan,
        harness_repository_root: root.path(),
        repository_root: root.path(),
    };
    let error = DockerHistoricalV2TestExecutor::new(root.path().join("missing-docker"))
        .execute(&request)
        .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV2ExecutionErrorKind::InfrastructureUnavailable
    );
}

fn fixture_plan() -> HistoricalV2IdenticalTestPlan {
    HistoricalV2IdenticalTestPlan {
        schema_version: 1,
        plan_contract: "fixture".to_string(),
        assessment_identity_sha256: "a".repeat(64),
        qualification_sha256: "b".repeat(64),
        test_recipe_sha256: "c".repeat(64),
        execution_harness_sha256: "d".repeat(64),
        materialization_sha256: "e".repeat(64),
        test_materialization_sha256: None,
        language: "python".to_string(),
        slot_number: 1,
        canonical_repository: "example/project".to_string(),
        base_commit_oid: "1".repeat(40),
        patched_commit_oid: "2".repeat(40),
        base_image_name: "python_3.11".to_string(),
        dockerfile_path: "base_dockerfiles/Dockerfile_python_3.11".to_string(),
        dockerfile_blob_oid: "3".repeat(40),
        install_commands: Vec::new(),
        install_command_sha256: Vec::new(),
        test_commands: vec!["pytest".to_string()],
        test_script_sha256: "f".repeat(64),
        policy: HistoricalV2ExecutionPolicy {
            platform: "linux/amd64".to_string(),
            cpu_limit_millis: 4_000,
            memory_limit_bytes: 8 * 1024 * 1024 * 1024,
            process_limit: 1_024,
            temporary_filesystem_bytes: 2 * 1024 * 1024 * 1024,
            install_command_timeout_seconds: 1_800,
            test_timeout_seconds: 3_600,
            retained_output_bytes: 1024 * 1024,
            install_network_enabled: true,
            test_network_enabled: false,
            ephemeral_root_filesystem: true,
            host_source_mounts_forbidden: true,
            all_capabilities_dropped: true,
            no_new_privileges: true,
        },
        plan_sha256: "0".repeat(64),
    }
}
