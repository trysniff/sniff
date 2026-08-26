use super::{
    HistoricalV2ExecutionCommandEvidence, HistoricalV2ExecutionError, HistoricalV2ExecutionPhase,
    HistoricalV2ExecutionSide, HistoricalV2IdenticalTestExclusionReason,
    HistoricalV2IdenticalTestExecutionRequest, HistoricalV2IdenticalTestExecutor,
    HistoricalV2IdenticalTestOutcome, HistoricalV2RawIdenticalTestExecution,
    HistoricalV2RecoverableTestExecutor,
};
use crate::bounded_process::BoundedOutput;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const CONTROL_OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DockerHistoricalV2TestExecutor {
    program: PathBuf,
}

impl DockerHistoricalV2TestExecutor {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    pub fn from_path() -> Self {
        Self::new("docker")
    }

    pub fn recover_plan_resources(
        &self,
        plan: &super::HistoricalV2IdenticalTestPlan,
    ) -> Result<(), HistoricalV2ExecutionError> {
        if plan.plan_sha256.len() != 64
            || !plan
                .plan_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HistoricalV2ExecutionError::infrastructure(
                "cannot recover Docker resources for an invalid historical-v2 plan identity",
            ));
        }
        self.require_daemon()?;
        let names = ResourceNames::new(&plan.plan_sha256);
        let label_filter = format!("label={}", plan_label(&plan.plan_sha256));
        let containers = self.list_named_resources(
            [
                "ps",
                "--all",
                "--format",
                "{{.Names}}",
                "--filter",
                label_filter.as_str(),
            ],
            "containers",
        )?;
        let volumes = self.list_named_resources(
            [
                "volume",
                "ls",
                "--format",
                "{{.Name}}",
                "--filter",
                label_filter.as_str(),
            ],
            "volumes",
        )?;
        let networks = self.list_named_resources(
            [
                "network",
                "ls",
                "--format",
                "{{.Name}}",
                "--filter",
                label_filter.as_str(),
            ],
            "networks",
        )?;
        require_expected_resources(
            &containers,
            [&names.base_container, &names.patched_container],
            "container",
        )?;
        require_expected_resources(
            &volumes,
            [&names.base_volume, &names.patched_volume],
            "volume",
        )?;
        require_expected_resources(&networks, [&names.network], "network")?;

        let mut failures = Vec::new();
        for container in containers.iter().rev() {
            cleanup_resource(
                self,
                ["rm", "--force", container.as_str()],
                "container",
                container,
                &mut failures,
            );
        }
        for volume in volumes.iter().rev() {
            cleanup_resource(
                self,
                ["volume", "rm", "--force", volume.as_str()],
                "volume",
                volume,
                &mut failures,
            );
        }
        for network in networks.iter().rev() {
            cleanup_resource(
                self,
                ["network", "rm", network.as_str()],
                "network",
                network,
                &mut failures,
            );
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(HistoricalV2ExecutionError::infrastructure(format!(
                "historical-v2 Docker recovery failed: {}",
                failures.join("; ")
            )))
        }
    }

    fn list_named_resources<'a>(
        &self,
        args: impl IntoIterator<Item = &'a str>,
        kind: &str,
    ) -> Result<Vec<String>, HistoricalV2ExecutionError> {
        let output = self.run_control(args, CONTROL_TIMEOUT)?;
        require_control_success(&output, &format!("list historical-v2 {kind}"))?;
        let text = std::str::from_utf8(&output.stdout).map_err(|_| {
            HistoricalV2ExecutionError::infrastructure(format!(
                "Docker returned non-UTF-8 historical-v2 {kind}"
            ))
        })?;
        let mut names = text
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn execute_inner(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
        resources: &mut DockerResources<'_>,
    ) -> Result<HistoricalV2RawIdenticalTestExecution, HistoricalV2ExecutionError> {
        self.require_daemon()?;
        let image_id = self.build_image(request)?;
        let names = ResourceNames::new(&request.plan.plan_sha256);
        resources.create_network(&names.network, &request.plan.plan_sha256)?;
        let mut events = Vec::new();
        for (side, commit_oid, container, volume) in [
            (
                HistoricalV2ExecutionSide::Base,
                request.plan.base_commit_oid.as_str(),
                names.base_container.as_str(),
                names.base_volume.as_str(),
            ),
            (
                HistoricalV2ExecutionSide::Patched,
                request.plan.patched_commit_oid.as_str(),
                names.patched_container.as_str(),
                names.patched_volume.as_str(),
            ),
        ] {
            resources.create_volume(volume, &request.plan.plan_sha256)?;
            self.create_container(request, &image_id, &names.network, container, volume)?;
            resources.track_container(container);
            self.start_and_stage_repository(request, container, commit_oid)?;
            if let Some(outcome) =
                self.run_install_commands(request, side, container, &mut events)?
            {
                return Ok(HistoricalV2RawIdenticalTestExecution {
                    image_id,
                    events,
                    outcome,
                });
            }
            self.disable_and_verify_network(container, &names.network)?;
            if let Some(outcome) = self.run_test_commands(request, side, container, &mut events)? {
                return Ok(HistoricalV2RawIdenticalTestExecution {
                    image_id,
                    events,
                    outcome,
                });
            }
        }
        Ok(HistoricalV2RawIdenticalTestExecution {
            image_id,
            events,
            outcome: HistoricalV2IdenticalTestOutcome::Passed,
        })
    }

    fn require_daemon(&self) -> Result<(), HistoricalV2ExecutionError> {
        let output = self.run_control(
            ["version", "--format", "{{.Server.Version}}"],
            CONTROL_TIMEOUT,
        )?;
        if output.timed_out || !output.status.success() || output.stdout.is_empty() {
            return Err(HistoricalV2ExecutionError::unavailable(format!(
                "historical-v2 requires a reachable Docker daemon: {}",
                compact_stderr(&output)
            )));
        }
        Ok(())
    }

    fn build_image(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
    ) -> Result<String, HistoricalV2ExecutionError> {
        let dockerfile = request
            .harness_repository_root
            .join(&request.plan.dockerfile_path);
        let tag = format!(
            "sniffbench-historical-v2-base:{}",
            request.plan.dockerfile_blob_oid
        );
        let output = self.run_control_os(
            [
                OsString::from("build"),
                OsString::from("--pull"),
                OsString::from("--platform"),
                OsString::from(&request.plan.policy.platform),
                OsString::from("--file"),
                dockerfile.into_os_string(),
                OsString::from("--tag"),
                OsString::from(&tag),
                OsString::from("--label"),
                OsString::from(format!(
                    "org.trysniff.historical-v2-harness={}",
                    request.plan.execution_harness_sha256
                )),
                request.harness_repository_root.as_os_str().to_os_string(),
            ],
            BUILD_TIMEOUT,
            CONTROL_OUTPUT_LIMIT,
        )?;
        require_control_success(&output, "build frozen historical-v2 base image")?;
        let inspect = self.run_control(
            ["image", "inspect", "--format", "{{.Id}}", &tag],
            CONTROL_TIMEOUT,
        )?;
        require_control_success(&inspect, "inspect historical-v2 base image")?;
        let image_id = utf8_trimmed(&inspect.stdout, "Docker image identity")?;
        if !valid_image_id(&image_id) {
            return Err(HistoricalV2ExecutionError::infrastructure(
                "Docker returned an invalid historical-v2 image identity",
            ));
        }
        Ok(image_id)
    }

    fn create_container(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
        image_id: &str,
        network: &str,
        container: &str,
        volume: &str,
    ) -> Result<(), HistoricalV2ExecutionError> {
        let output = self.run_control_os(
            container_create_args(request, image_id, network, container, volume),
            CONTROL_TIMEOUT,
            CONTROL_OUTPUT_LIMIT,
        )?;
        require_control_success(&output, "create hardened historical-v2 container")
    }

    fn start_and_stage_repository(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
        container: &str,
        commit_oid: &str,
    ) -> Result<(), HistoricalV2ExecutionError> {
        let start = self.run_control(["start", container], CONTROL_TIMEOUT)?;
        require_control_success(&start, "start historical-v2 container")?;
        let source = copy_source_argument(request.repository_root);
        let target = format!("{container}:/workspace");
        let copied = self.run_control_os(
            [OsString::from("cp"), source, OsString::from(target)],
            CONTROL_TIMEOUT,
            CONTROL_OUTPUT_LIMIT,
        )?;
        require_control_success(&copied, "copy committed repository into container")?;
        let permissions = self.run_control_os(
            container_workspace_permission_args(container),
            CONTROL_TIMEOUT,
            CONTROL_OUTPUT_LIMIT,
        )?;
        require_control_success(
            &permissions,
            "make the isolated repository writable by the image user",
        )?;
        let script = format!(
            "set -euo pipefail\ngit reset --hard {commit_oid}\ngit clean -ffdqx\ntest \"$(git rev-parse HEAD)\" = \"{commit_oid}\"\ntest -z \"$(git status --porcelain=v1 --untracked-files=all)\"\n"
        );
        let prepared =
            self.exec_script(container, &script, CONTROL_TIMEOUT, CONTROL_OUTPUT_LIMIT)?;
        require_control_success(&prepared, "prepare committed repository snapshot")
    }

    fn run_install_commands(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
        side: HistoricalV2ExecutionSide,
        container: &str,
        events: &mut Vec<HistoricalV2ExecutionCommandEvidence>,
    ) -> Result<Option<HistoricalV2IdenticalTestOutcome>, HistoricalV2ExecutionError> {
        for (command_index, command) in request.plan.install_commands.iter().enumerate() {
            let event = self.exec_evidence(
                request,
                container,
                side,
                HistoricalV2ExecutionPhase::Install,
                command_index,
                &request.plan.install_command_sha256[command_index],
                &format!("set -euo pipefail\n{command}\n"),
                request.plan.policy.install_command_timeout_seconds,
            )?;
            let outcome = failed_outcome(&event);
            events.push(event);
            if outcome.is_some() {
                return Ok(outcome);
            }
        }
        Ok(None)
    }

    fn run_test_commands(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
        side: HistoricalV2ExecutionSide,
        container: &str,
        events: &mut Vec<HistoricalV2ExecutionCommandEvidence>,
    ) -> Result<Option<HistoricalV2IdenticalTestOutcome>, HistoricalV2ExecutionError> {
        let script = super::history_v2_identical_tests::test_script(&request.plan.test_commands);
        let event = self.exec_evidence(
            request,
            container,
            side,
            HistoricalV2ExecutionPhase::Test,
            0,
            &request.plan.test_script_sha256,
            &script,
            request.plan.policy.test_timeout_seconds,
        )?;
        let outcome = failed_outcome(&event);
        events.push(event);
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_evidence(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
        container: &str,
        side: HistoricalV2ExecutionSide,
        phase: HistoricalV2ExecutionPhase,
        command_index: usize,
        command_sha256: &str,
        script: &str,
        timeout_seconds: u64,
    ) -> Result<HistoricalV2ExecutionCommandEvidence, HistoricalV2ExecutionError> {
        let started = Instant::now();
        let output = self.exec_script(
            container,
            script,
            Duration::from_secs(timeout_seconds),
            request.plan.policy.retained_output_bytes,
        )?;
        if output.timed_out {
            let _ = self.run_control(["kill", container], CONTROL_TIMEOUT);
        }
        if output.timed_out || !output.status.success() {
            self.verify_failed_exec_environment(container)?;
        }
        Ok(HistoricalV2ExecutionCommandEvidence {
            side,
            phase,
            command_index,
            command_sha256: command_sha256.to_string(),
            exit_code: output.status.code(),
            timed_out: output.timed_out,
            duration_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            stdout_sha256: output.stdout_sha256,
            stderr_sha256: output.stderr_sha256,
            retained_stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            retained_stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        })
    }

    fn verify_failed_exec_environment(
        &self,
        container: &str,
    ) -> Result<(), HistoricalV2ExecutionError> {
        self.require_daemon()?;
        let inspected = self.run_control(
            ["inspect", "--format", "{{.Id}}", container],
            CONTROL_TIMEOUT,
        )?;
        require_control_success(
            &inspected,
            "verify Docker infrastructure after a candidate command failure",
        )
    }

    fn disable_and_verify_network(
        &self,
        container: &str,
        network: &str,
    ) -> Result<(), HistoricalV2ExecutionError> {
        let disconnected = self.run_control(
            ["network", "disconnect", network, container],
            CONTROL_TIMEOUT,
        )?;
        require_control_success(&disconnected, "disable historical-v2 test networking")?;
        let inspected = self.run_control(
            [
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                container,
            ],
            CONTROL_TIMEOUT,
        )?;
        require_control_success(&inspected, "verify historical-v2 test networking")?;
        let networks = serde_json::from_slice::<BTreeMap<String, serde_json::Value>>(trim_ascii(
            &inspected.stdout,
        ))
        .map_err(|error| {
            HistoricalV2ExecutionError::infrastructure(format!(
                "Docker returned invalid network inspection data: {error}"
            ))
        })?;
        if !networks.is_empty() {
            return Err(HistoricalV2ExecutionError::infrastructure(
                "historical-v2 test container retained a network attachment",
            ));
        }
        Ok(())
    }

    fn exec_script(
        &self,
        container: &str,
        script: &str,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<BoundedOutput, HistoricalV2ExecutionError> {
        self.run_control_os(
            container_exec_args(container, script),
            timeout,
            output_limit,
        )
    }

    fn run_control<'a>(
        &self,
        args: impl IntoIterator<Item = &'a str>,
        timeout: Duration,
    ) -> Result<BoundedOutput, HistoricalV2ExecutionError> {
        self.run_control_os(
            args.into_iter().map(OsString::from),
            timeout,
            CONTROL_OUTPUT_LIMIT,
        )
    }

    fn run_control_os(
        &self,
        args: impl IntoIterator<Item = OsString>,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<BoundedOutput, HistoricalV2ExecutionError> {
        let mut command = Command::new(&self.program);
        command.args(args);
        crate::bounded_process::run_with_output_limit(&mut command, timeout, output_limit).map_err(
            |error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    HistoricalV2ExecutionError::unavailable(format!(
                        "Docker executable is unavailable: {error}"
                    ))
                } else {
                    HistoricalV2ExecutionError::infrastructure(format!(
                        "Docker command could not execute: {error}"
                    ))
                }
            },
        )
    }
}

fn require_expected_resources<const N: usize>(
    actual: &[String],
    expected: [&String; N],
    kind: &str,
) -> Result<(), HistoricalV2ExecutionError> {
    let expected = expected
        .into_iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unexpected = actual
        .iter()
        .map(String::as_str)
        .filter(|name| !expected.contains(name))
        .collect::<Vec<_>>();
    if unexpected.is_empty() {
        Ok(())
    } else {
        Err(HistoricalV2ExecutionError::infrastructure(format!(
            "refusing to remove unexpected historical-v2 Docker {kind} resources: {}",
            unexpected.join(", ")
        )))
    }
}

impl Default for DockerHistoricalV2TestExecutor {
    fn default() -> Self {
        Self::from_path()
    }
}

impl HistoricalV2IdenticalTestExecutor for DockerHistoricalV2TestExecutor {
    fn execute(
        &self,
        request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV2RawIdenticalTestExecution, HistoricalV2ExecutionError> {
        let mut resources = DockerResources::new(self);
        let execution = self.execute_inner(request, &mut resources);
        let cleanup = resources.cleanup();
        match (execution, cleanup) {
            (Ok(execution), Ok(())) => Ok(execution),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(error), Err(cleanup)) => Err(HistoricalV2ExecutionError::infrastructure(format!(
                "{error}; additionally, {cleanup}"
            ))),
        }
    }
}

impl HistoricalV2RecoverableTestExecutor for DockerHistoricalV2TestExecutor {
    fn recover(
        &self,
        plan: &super::HistoricalV2IdenticalTestPlan,
    ) -> Result<(), HistoricalV2ExecutionError> {
        self.recover_plan_resources(plan)
    }
}

#[path = "benchmark_history_v2_identical_tests_docker_support.rs"]
mod docker_support;

use docker_support::*;

#[cfg(test)]
#[path = "benchmark_history_v2_identical_tests_docker_tests.rs"]
mod docker_tests;
