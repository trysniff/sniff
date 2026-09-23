use super::super::{HistoricalV3IdenticalTestPolicy, HistoricalV3RecipeCommand};
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(super) const TOOLCHAIN_LABEL: &str = "org.trysniff.toolchain-manifest-sha256";
pub(super) const DEPENDENCY_STORE_LABEL: &str = "org.trysniff.dependency-store-sha256";
pub(super) const EXECUTION_LABEL: &str = "org.trysniff.historical-v3.execution";
pub(super) const CONTAINER_REPOSITORY: &str = "/workspace";

pub(super) struct ResourceNames {
    pub base_container: String,
    pub merge_container: String,
    pub base_volume: String,
    pub merge_volume: String,
}

impl ResourceNames {
    pub(super) fn new(identity: &str) -> Option<Self> {
        if !valid_sha256(identity) {
            return None;
        }
        let prefix = format!("sniff-hv3-{}", &identity[..24]);
        Some(Self {
            base_container: format!("{prefix}-base"),
            merge_container: format!("{prefix}-merge"),
            base_volume: format!("{prefix}-base-work"),
            merge_volume: format!("{prefix}-merge-work"),
        })
    }
}

pub(super) fn resource_label(identity: &str) -> String {
    format!("{EXECUTION_LABEL}={identity}")
}

pub(super) fn container_create_args(
    policy: &HistoricalV3IdenticalTestPolicy,
    execution_identity_sha256: &str,
    execution_platform: &str,
    image_digest: &str,
    container: &str,
    volume: &str,
) -> Vec<OsString> {
    vec![
        "create".into(),
        "--name".into(),
        container.into(),
        "--label".into(),
        "org.trysniff.historical-v3=true".into(),
        "--label".into(),
        resource_label(execution_identity_sha256).into(),
        "--platform".into(),
        execution_platform.into(),
        "--network".into(),
        "none".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        policy.process_limit.to_string().into(),
        "--memory".into(),
        policy.memory_limit_bytes.to_string().into(),
        "--cpus".into(),
        format!("{:.3}", policy.cpu_limit_millis as f64 / 1000.0).into(),
        "--tmpfs".into(),
        format!(
            "/tmp:rw,nosuid,nodev,noexec,size={}",
            policy.temporary_filesystem_bytes
        )
        .into(),
        "--mount".into(),
        format!("type=volume,source={volume},target={CONTAINER_REPOSITORY}").into(),
        "--workdir".into(),
        CONTAINER_REPOSITORY.into(),
        image_digest.into(),
        "/bin/sh".into(),
        "-c".into(),
        "trap : TERM INT; while :; do sleep 3600; done".into(),
    ]
}

pub(super) fn copy_source_argument(root: &Path) -> OsString {
    let mut source = root.as_os_str().to_os_string();
    source.push(OsStr::new(std::path::MAIN_SEPARATOR_STR));
    source.push(OsStr::new("."));
    source
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn command_exec_args(
    container: &str,
    command: &HistoricalV3RecipeCommand,
) -> Vec<OsString> {
    let mut args = vec!["exec".into()];
    for (key, value) in &command.environment {
        args.push("--env".into());
        args.push(format!("{key}={value}").into());
    }
    args.extend([
        "--workdir".into(),
        CONTAINER_REPOSITORY.into(),
        container.into(),
    ]);
    args.extend(command.argv.iter().map(OsString::from));
    args
}

pub(super) fn root_exec_args(container: &str, program: &str, args: &[&str]) -> Vec<OsString> {
    let mut values = vec![
        "exec".into(),
        "--user".into(),
        "0:0".into(),
        container.into(),
        program.into(),
    ];
    values.extend(args.iter().map(OsString::from));
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{HistoricalV3IdenticalTestPolicy, HistoricalV3RecipeCommand};
    use std::collections::BTreeMap;

    #[test]
    fn direct_exec_preserves_argv_and_environment_without_a_shell() {
        let command = HistoricalV3RecipeCommand {
            argv: vec!["cargo".to_string(), "test".to_string(), "a b".to_string()],
            environment: BTreeMap::from([("CARGO_NET_OFFLINE".to_string(), "true".to_string())]),
        };
        let args = command_exec_args("candidate", &command);
        assert!(args.iter().any(|value| value == "CARGO_NET_OFFLINE=true"));
        assert_eq!(args.last().unwrap(), "a b");
        assert!(!args.iter().any(|value| value == "/bin/sh" || value == "-c"));
    }

    #[test]
    fn container_creation_enforces_the_sealed_isolation_policy() {
        let policy = HistoricalV3IdenticalTestPolicy {
            execution_contract: "sniffbench-historical-v3-identical-test-policy-v1".to_string(),
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
        };
        let identity = "a".repeat(64);
        let image = format!("sha256:{}", "b".repeat(64));
        let args = container_create_args(
            &policy,
            &identity,
            "linux/amd64",
            &image,
            "candidate",
            "workspace",
        );
        let args = args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        for pair in [
            ["--network", "none"],
            ["--cap-drop", "ALL"],
            ["--security-opt", "no-new-privileges"],
            ["--pids-limit", "1024"],
            ["--memory", "8589934592"],
            ["--cpus", "4.000"],
            ["--platform", "linux/amd64"],
        ] {
            assert!(args.windows(2).any(|window| window == pair));
        }
        assert!(
            args.iter()
                .any(|value| { value == "/tmp:rw,nosuid,nodev,noexec,size=2147483648" })
        );
        assert!(
            args.iter()
                .any(|value| { value == "type=volume,source=workspace,target=/workspace" })
        );
        assert!(args.iter().any(|value| value == &image));
        assert!(
            !args
                .iter()
                .any(|value| value == "--volume" || value == "-v")
        );
        assert!(!args.iter().any(|value| value.contains("type=bind")));
    }

    #[test]
    fn resource_names_reject_untrusted_execution_identities() {
        assert!(ResourceNames::new(&"a".repeat(64)).is_some());
        assert!(ResourceNames::new("short").is_none());
        assert!(ResourceNames::new(&"G".repeat(64)).is_none());
    }
}
