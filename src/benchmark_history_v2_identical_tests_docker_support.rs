use super::*;
use std::ffi::{OsStr, OsString};
use std::path::Path;

const CONTAINER_REPOSITORY: &str = "/workspace";
const PERMISSION_CONTROL_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const PERMISSION_CONTROL_PROCESS_LIMIT: u16 = 16;

pub(super) fn workspace_permission_container_create_args(
    request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
    image_id: &str,
    container: &str,
    volume: &str,
) -> Vec<OsString> {
    vec![
        "create".into(),
        "--name".into(),
        container.into(),
        "--label".into(),
        "org.trysniff.historical-v2=true".into(),
        "--label".into(),
        plan_label(&request.plan.plan_sha256).into(),
        "--platform".into(),
        request.plan.policy.platform.as_str().into(),
        "--network".into(),
        "none".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "FOWNER".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        PERMISSION_CONTROL_PROCESS_LIMIT.to_string().into(),
        "--memory".into(),
        PERMISSION_CONTROL_MEMORY_BYTES.to_string().into(),
        "--cpus".into(),
        "0.250".into(),
        "--read-only".into(),
        "--mount".into(),
        format!("type=volume,source={volume},target={CONTAINER_REPOSITORY}").into(),
        "--workdir".into(),
        CONTAINER_REPOSITORY.into(),
        "--user".into(),
        "0:0".into(),
        "--entrypoint".into(),
        "/bin/chmod".into(),
        image_id.into(),
        "-R".into(),
        "a+rwX".into(),
        "--".into(),
        CONTAINER_REPOSITORY.into(),
    ]
}

pub(super) fn container_exec_args(container: &str, script: &str) -> Vec<OsString> {
    vec![
        "exec".into(),
        "--env".into(),
        "GIT_CONFIG_COUNT=1".into(),
        "--env".into(),
        "GIT_CONFIG_KEY_0=safe.directory".into(),
        "--env".into(),
        format!("GIT_CONFIG_VALUE_0={CONTAINER_REPOSITORY}").into(),
        "--workdir".into(),
        CONTAINER_REPOSITORY.into(),
        container.into(),
        "/bin/bash".into(),
        "-lc".into(),
        script.into(),
    ]
}

pub(super) fn container_create_args(
    request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
    image_id: &str,
    network: &str,
    container: &str,
    volume: &str,
) -> Vec<OsString> {
    let policy = &request.plan.policy;
    vec![
        "create".into(),
        "--name".into(),
        container.into(),
        "--label".into(),
        "org.trysniff.historical-v2=true".into(),
        "--label".into(),
        plan_label(&request.plan.plan_sha256).into(),
        "--platform".into(),
        policy.platform.as_str().into(),
        "--network".into(),
        network.into(),
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
        image_id.into(),
        "/bin/sh".into(),
        "-c".into(),
        "trap : TERM INT; while :; do sleep 3600; done".into(),
    ]
}

pub(super) fn failed_outcome(
    event: &HistoricalV2ExecutionCommandEvidence,
) -> Option<HistoricalV2IdenticalTestOutcome> {
    if !event.timed_out && event.exit_code == Some(0) {
        return None;
    }
    let reason = match (event.phase, event.timed_out) {
        (HistoricalV2ExecutionPhase::Install, true) => {
            HistoricalV2IdenticalTestExclusionReason::InstallCommandTimedOut {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV2ExecutionPhase::Install, false) => {
            HistoricalV2IdenticalTestExclusionReason::InstallCommandFailed {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV2ExecutionPhase::Test, true) => {
            HistoricalV2IdenticalTestExclusionReason::TestCommandsTimedOut { side: event.side }
        }
        (HistoricalV2ExecutionPhase::Test, false) => {
            HistoricalV2IdenticalTestExclusionReason::TestCommandsFailed { side: event.side }
        }
    };
    Some(HistoricalV2IdenticalTestOutcome::Excluded { reason })
}

pub(super) struct ResourceNames {
    pub(super) network: String,
    pub(super) base_container: String,
    pub(super) patched_container: String,
    pub(super) base_permission_container: String,
    pub(super) patched_permission_container: String,
    pub(super) base_volume: String,
    pub(super) patched_volume: String,
}

impl ResourceNames {
    pub(super) fn new(plan_sha256: &str) -> Self {
        let prefix = format!("sniff-hv2-{}", &plan_sha256[..24]);
        Self {
            network: format!("{prefix}-network"),
            base_container: format!("{prefix}-base"),
            patched_container: format!("{prefix}-patched"),
            base_permission_container: format!("{prefix}-base-permissions"),
            patched_permission_container: format!("{prefix}-patched-permissions"),
            base_volume: format!("{prefix}-base-work"),
            patched_volume: format!("{prefix}-patched-work"),
        }
    }
}

pub(super) struct DockerResources<'a> {
    docker: &'a DockerHistoricalV2TestExecutor,
    containers: Vec<String>,
    volumes: Vec<String>,
    networks: Vec<String>,
    cleaned: bool,
}

impl<'a> DockerResources<'a> {
    pub(super) fn new(docker: &'a DockerHistoricalV2TestExecutor) -> Self {
        Self {
            docker,
            containers: Vec::new(),
            volumes: Vec::new(),
            networks: Vec::new(),
            cleaned: false,
        }
    }

    pub(super) fn create_network(
        &mut self,
        name: &str,
        plan_sha256: &str,
    ) -> Result<(), HistoricalV2ExecutionError> {
        let output = self.docker.run_control(
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--label",
                "org.trysniff.historical-v2=true",
                "--label",
                &plan_label(plan_sha256),
                name,
            ],
            CONTROL_TIMEOUT,
        )?;
        require_control_success(&output, "create historical-v2 install network")?;
        self.networks.push(name.to_string());
        Ok(())
    }

    pub(super) fn create_volume(
        &mut self,
        name: &str,
        plan_sha256: &str,
    ) -> Result<(), HistoricalV2ExecutionError> {
        let output = self.docker.run_control(
            [
                "volume",
                "create",
                "--label",
                "org.trysniff.historical-v2=true",
                "--label",
                &plan_label(plan_sha256),
                name,
            ],
            CONTROL_TIMEOUT,
        )?;
        require_control_success(&output, "create historical-v2 workspace volume")?;
        self.volumes.push(name.to_string());
        Ok(())
    }

    pub(super) fn track_container(&mut self, name: &str) {
        self.containers.push(name.to_string());
    }

    pub(super) fn cleanup(&mut self) -> Result<(), HistoricalV2ExecutionError> {
        let mut failures = Vec::new();
        for container in self.containers.iter().rev() {
            cleanup_resource(
                self.docker,
                ["rm", "--force", container.as_str()],
                "container",
                container,
                &mut failures,
            );
        }
        for volume in self.volumes.iter().rev() {
            cleanup_resource(
                self.docker,
                ["volume", "rm", "--force", volume.as_str()],
                "volume",
                volume,
                &mut failures,
            );
        }
        for network in self.networks.iter().rev() {
            cleanup_resource(
                self.docker,
                ["network", "rm", network.as_str()],
                "network",
                network,
                &mut failures,
            );
        }
        self.cleaned = true;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(HistoricalV2ExecutionError::infrastructure(format!(
                "historical-v2 Docker cleanup failed: {}",
                failures.join("; ")
            )))
        }
    }
}

pub(super) fn plan_label(plan_sha256: &str) -> String {
    format!("org.trysniff.historical-v2.plan={plan_sha256}")
}

impl Drop for DockerResources<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

pub(super) fn cleanup_resource<'a>(
    docker: &DockerHistoricalV2TestExecutor,
    args: impl IntoIterator<Item = &'a str>,
    kind: &str,
    name: &str,
    failures: &mut Vec<String>,
) {
    match docker.run_control(args, CONTROL_TIMEOUT) {
        Ok(output) if output.status.success() && !output.timed_out => {}
        Ok(output) => failures.push(format!("{kind} {name}: {}", compact_stderr(&output))),
        Err(error) => failures.push(format!("{kind} {name}: {error}")),
    }
}

pub(super) fn require_control_success(
    output: &BoundedOutput,
    label: &str,
) -> Result<(), HistoricalV2ExecutionError> {
    if output.status.success() && !output.timed_out {
        Ok(())
    } else {
        Err(HistoricalV2ExecutionError::infrastructure(format!(
            "failed to {label}: {}",
            compact_stderr(output)
        )))
    }
}

pub(super) fn compact_stderr(output: &BoundedOutput) -> String {
    if output.timed_out {
        return "command timed out".to_string();
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let compact = stderr.trim();
    if compact.is_empty() {
        format!("exit code {:?}", output.status.code())
    } else {
        compact.to_string()
    }
}

pub(super) fn utf8_trimmed(
    bytes: &[u8],
    label: &str,
) -> Result<String, HistoricalV2ExecutionError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| HistoricalV2ExecutionError::infrastructure(format!("{label} is not UTF-8")))?;
    let value = value.trim();
    if value.is_empty() {
        Err(HistoricalV2ExecutionError::infrastructure(format!(
            "{label} is empty"
        )))
    } else {
        Ok(value.to_string())
    }
}

pub(super) fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

pub(super) fn copy_source_argument(root: &Path) -> OsString {
    let mut source = root.as_os_str().to_os_string();
    source.push(OsStr::new(std::path::MAIN_SEPARATOR_STR));
    source.push(OsStr::new("."));
    source
}

pub(super) fn valid_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
