use super::super::{
    HistoricalV3ExecutionCommandEvidence, HistoricalV3ExecutionPhase, HistoricalV3ExecutionSide,
    HistoricalV3IdenticalTestExclusionReason, HistoricalV3IdenticalTestExecutionError,
    HistoricalV3IdenticalTestExecutionRequest, HistoricalV3IdenticalTestExecutor,
    HistoricalV3IdenticalTestOutcome, HistoricalV3RawIdenticalTestExecution,
};
use super::commitment::command_sha256;
use super::docker_support::{
    CONTAINER_REPOSITORY, DEPENDENCY_STORE_LABEL, EXECUTION_LABEL, ResourceNames, TOOLCHAIN_LABEL,
    command_exec_args, container_create_args, copy_source_argument, resource_label, root_exec_args,
};
use crate::bounded_process::BoundedOutput;
use base64::Engine;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONTROL_OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum DockerResourceKind {
    Container,
    Volume,
}

#[derive(Clone, Copy)]
struct ExecutionStep {
    side: HistoricalV3ExecutionSide,
    phase: HistoricalV3ExecutionPhase,
    command_index: usize,
}

impl DockerResourceKind {
    fn name(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Volume => "volume",
        }
    }

    fn label_format(self) -> String {
        match self {
            Self::Container => format!("{{{{index .Config.Labels \"{EXECUTION_LABEL}\"}}}}"),
            Self::Volume => format!("{{{{index .Labels \"{EXECUTION_LABEL}\"}}}}"),
        }
    }

    fn missing_marker(self) -> &'static str {
        match self {
            Self::Container => "no such container",
            Self::Volume => "no such volume",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DockerHistoricalV3TestExecutor {
    program: PathBuf,
}

impl DockerHistoricalV3TestExecutor {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    pub fn from_path() -> Self {
        Self::new("docker")
    }

    fn require_daemon(&self) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        let output = self.run(
            ["version", "--format", "{{.Server.Version}}"],
            CONTROL_TIMEOUT,
        )?;
        if output.timed_out || !output.status.success() || output.stdout.is_empty() {
            return Err(HistoricalV3IdenticalTestExecutionError::unavailable(
                "historical-v3 requires a reachable Docker daemon",
            ));
        }
        Ok(())
    }

    fn verify_image(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        let format = format!(
            "{{{{.Id}}}}\n{{{{index .Config.Labels \"{TOOLCHAIN_LABEL}\"}}}}\n{{{{index .Config.Labels \"{DEPENDENCY_STORE_LABEL}\"}}}}"
        );
        let output = self.run(
            [
                "image",
                "inspect",
                "--format",
                format.as_str(),
                request.recipe.image_digest.as_str(),
            ],
            CONTROL_TIMEOUT,
        )?;
        require_success(&output, "inspect sealed historical-v3 image")?;
        let fields = std::str::from_utf8(&output.stdout)
            .map_err(|_| infrastructure("Docker returned non-UTF-8 image identity"))?
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>();
        if fields
            != [
                request.recipe.image_digest.as_str(),
                request.recipe.toolchain_manifest_sha256.as_str(),
                request.recipe.dependency_store_sha256.as_str(),
            ]
        {
            return Err(infrastructure(
                "Docker image labels do not match the committed test environment",
            ));
        }
        Ok(())
    }

    fn execute_inner(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        self.require_daemon()?;
        self.verify_image(request)?;
        let names = ResourceNames::new(request.execution_identity_sha256).ok_or_else(|| {
            HistoricalV3IdenticalTestExecutionError::invalid(
                "historical-v3 execution identity is not a lowercase SHA-256",
            )
        })?;
        let mut events = Vec::new();
        for (side, root, container, volume) in [
            (
                HistoricalV3ExecutionSide::Base,
                request.base_root,
                names.base_container.as_str(),
                names.base_volume.as_str(),
            ),
            (
                HistoricalV3ExecutionSide::Merge,
                request.merge_root,
                names.merge_container.as_str(),
                names.merge_volume.as_str(),
            ),
        ] {
            self.create_volume(request, volume)?;
            self.create_container(request, container, volume)?;
            self.start_and_stage(root, container)?;
            for (index, command) in request.recipe.preparation_commands.iter().enumerate() {
                let event = self.run_command(
                    request,
                    container,
                    ExecutionStep {
                        side,
                        phase: HistoricalV3ExecutionPhase::Preparation,
                        command_index: index,
                    },
                    command,
                    request.policy.preparation_command_timeout_seconds,
                )?;
                let failed = failed_outcome(&event);
                events.push(event);
                if let Some(outcome) = failed {
                    return Ok(raw(request, events, outcome));
                }
            }
            let event = self.run_command(
                request,
                container,
                ExecutionStep {
                    side,
                    phase: HistoricalV3ExecutionPhase::Test,
                    command_index: 0,
                },
                &request.recipe.test_command,
                request.policy.test_command_timeout_seconds,
            )?;
            let failed = failed_outcome(&event);
            events.push(event);
            if let Some(outcome) = failed {
                return Ok(raw(request, events, outcome));
            }
        }
        Ok(raw(
            request,
            events,
            HistoricalV3IdenticalTestOutcome::Passed,
        ))
    }

    fn create_volume(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
        volume: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        let label = resource_label(request.execution_identity_sha256);
        let output = self.run(
            ["volume", "create", "--label", label.as_str(), volume],
            CONTROL_TIMEOUT,
        )?;
        require_success(&output, "create historical-v3 workspace volume")
    }

    fn create_container(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
        container: &str,
        volume: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        let output = self.run_os(
            container_create_args(
                request.policy,
                request.execution_identity_sha256,
                &request.recipe.execution_platform,
                &request.recipe.image_digest,
                container,
                volume,
            ),
            CONTROL_TIMEOUT,
            CONTROL_OUTPUT_LIMIT,
        )?;
        require_success(&output, "create hardened historical-v3 container")
    }

    fn start_and_stage(
        &self,
        root: &Path,
        container: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        require_success(
            &self.run(["start", container], CONTROL_TIMEOUT)?,
            "start historical-v3 container",
        )?;
        let target = format!("{container}:{CONTAINER_REPOSITORY}");
        require_success(
            &self.run_os(
                [
                    OsString::from("cp"),
                    copy_source_argument(root),
                    target.into(),
                ],
                CONTROL_TIMEOUT,
                CONTROL_OUTPUT_LIMIT,
            )?,
            "copy exact repository snapshot into container",
        )?;
        require_success(
            &self.run_os(
                root_exec_args(container, "/bin/rm", &["-rf", "--", "/workspace/.git"]),
                CONTROL_TIMEOUT,
                CONTROL_OUTPUT_LIMIT,
            )?,
            "remove staged Git metadata",
        )?;
        require_success(
            &self.run_os(
                root_exec_args(
                    container,
                    "/bin/chmod",
                    &["-R", "a+rwX", "--", "/workspace"],
                ),
                CONTROL_TIMEOUT,
                CONTROL_OUTPUT_LIMIT,
            )?,
            "prepare isolated workspace permissions",
        )
    }

    fn run_command(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
        container: &str,
        step: ExecutionStep,
        command: &super::super::HistoricalV3RecipeCommand,
        timeout_seconds: u64,
    ) -> Result<HistoricalV3ExecutionCommandEvidence, HistoricalV3IdenticalTestExecutionError> {
        let started = Instant::now();
        let output = self.run_os(
            command_exec_args(container, command),
            Duration::from_secs(timeout_seconds),
            request.policy.retained_output_bytes,
        )?;
        if output.timed_out || !output.status.success() {
            self.verify_failed_command_transport(container)?;
        }
        Ok(HistoricalV3ExecutionCommandEvidence {
            side: step.side,
            phase: step.phase,
            command_index: step.command_index,
            command_sha256: command_sha256(command)
                .map_err(HistoricalV3IdenticalTestExecutionError::invalid)?,
            exit_code: output.status.code(),
            timed_out: output.timed_out,
            duration_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            stdout_sha256: output.stdout_sha256,
            stderr_sha256: output.stderr_sha256,
            stdout_byte_count: output.stdout_byte_count,
            stderr_byte_count: output.stderr_byte_count,
            retained_stdout_base64: base64::engine::general_purpose::STANDARD.encode(output.stdout),
            retained_stderr_base64: base64::engine::general_purpose::STANDARD.encode(output.stderr),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        })
    }

    fn run<'a>(
        &self,
        args: impl IntoIterator<Item = &'a str>,
        timeout: Duration,
    ) -> Result<BoundedOutput, HistoricalV3IdenticalTestExecutionError> {
        self.run_os(
            args.into_iter().map(OsString::from),
            timeout,
            CONTROL_OUTPUT_LIMIT,
        )
    }

    fn run_os(
        &self,
        args: impl IntoIterator<Item = OsString>,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<BoundedOutput, HistoricalV3IdenticalTestExecutionError> {
        let mut command = Command::new(&self.program);
        command.args(args);
        crate::bounded_process::run_with_output_limit(&mut command, timeout, output_limit)
            .map_err(|error| infrastructure(format!("failed to execute Docker: {error}")))
    }

    fn verify_failed_command_transport(
        &self,
        container: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        self.require_daemon()?;
        let output = self.run(
            ["container", "inspect", "--format", "{{.Id}}", container],
            CONTROL_TIMEOUT,
        )?;
        require_success(
            &output,
            "verify the candidate container after a failed command",
        )
    }
}

impl HistoricalV3IdenticalTestExecutor for DockerHistoricalV3TestExecutor {
    fn recover(&self, identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        self.require_daemon()?;
        let names = ResourceNames::new(identity).ok_or_else(|| {
            HistoricalV3IdenticalTestExecutionError::invalid(
                "historical-v3 execution identity is not a lowercase SHA-256",
            )
        })?;
        for container in [&names.base_container, &names.merge_container] {
            self.remove_labeled(DockerResourceKind::Container, container, identity)?;
        }
        for volume in [&names.base_volume, &names.merge_volume] {
            self.remove_labeled(DockerResourceKind::Volume, volume, identity)?;
        }
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        let result = self.execute_inner(request);
        let cleanup = self.recover(request.execution_identity_sha256);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
}

impl DockerHistoricalV3TestExecutor {
    fn remove_labeled(
        &self,
        kind: DockerResourceKind,
        name: &str,
        identity: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        let format = kind.label_format();
        let output = self.run(
            [kind.name(), "inspect", "--format", format.as_str(), name],
            CONTROL_TIMEOUT,
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if !output.timed_out && stderr.contains(kind.missing_marker()) {
                return Ok(());
            }
            return Err(infrastructure(format!(
                "failed to inspect historical-v3 {} {name}: {}",
                kind.name(),
                compact_failure(&output)
            )));
        }
        if std::str::from_utf8(&output.stdout).ok().map(str::trim) != Some(identity) {
            return Err(infrastructure(format!(
                "refusing to remove unlabeled historical-v3 {} {name}",
                kind.name()
            )));
        }
        let args = if matches!(kind, DockerResourceKind::Container) {
            vec!["container", "rm", "--force", name]
        } else {
            vec!["volume", "rm", "--force", name]
        };
        require_success(
            &self.run(args, CONTROL_TIMEOUT)?,
            "remove historical-v3 resource",
        )
    }
}

fn raw(
    request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    events: Vec<HistoricalV3ExecutionCommandEvidence>,
    outcome: HistoricalV3IdenticalTestOutcome,
) -> HistoricalV3RawIdenticalTestExecution {
    HistoricalV3RawIdenticalTestExecution {
        image_digest: request.recipe.image_digest.clone(),
        toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
        dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
        events,
        outcome,
    }
}

fn failed_outcome(
    event: &HistoricalV3ExecutionCommandEvidence,
) -> Option<HistoricalV3IdenticalTestOutcome> {
    if !event.timed_out && event.exit_code == Some(0) {
        return None;
    }
    let reason = match (event.phase, event.timed_out) {
        (HistoricalV3ExecutionPhase::Preparation, true) => {
            HistoricalV3IdenticalTestExclusionReason::PreparationTimedOut {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV3ExecutionPhase::Preparation, false) => {
            HistoricalV3IdenticalTestExclusionReason::PreparationFailed {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV3ExecutionPhase::Test, true) => {
            HistoricalV3IdenticalTestExclusionReason::TestTimedOut { side: event.side }
        }
        (HistoricalV3ExecutionPhase::Test, false) => {
            HistoricalV3IdenticalTestExclusionReason::TestFailed { side: event.side }
        }
    };
    Some(HistoricalV3IdenticalTestOutcome::Excluded { reason })
}

fn require_success(
    output: &BoundedOutput,
    context: &str,
) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
    if !output.timed_out && output.status.success() {
        Ok(())
    } else {
        Err(infrastructure(format!(
            "Docker failed to {context}: {}",
            compact_failure(output)
        )))
    }
}

fn compact_failure(output: &BoundedOutput) -> String {
    if output.timed_out {
        return "command timed out".to_string();
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    if detail.is_empty() {
        format!("exit code {:?}", output.status.code())
    } else {
        detail.to_string()
    }
}

fn infrastructure(detail: impl Into<String>) -> HistoricalV3IdenticalTestExecutionError {
    HistoricalV3IdenticalTestExecutionError::infrastructure(detail)
}
