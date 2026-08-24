use super::benchmark_run::{read_json, write_new_file};
use crate::benchmark::{
    IntentionalBoundaryFrameError, IntentionalBoundaryFrameErrorKind, IntentionalBoundaryFrameTask,
    IntentionalBoundaryProductionSweepInputs, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankStageErrorKind, complete_intentional_boundary_candidate_frame_typed,
    run_intentional_boundary_production_sweep_slice, validate_intentional_boundary_frame_task,
    validate_intentional_boundary_protocol,
};
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::num::NonZeroUsize;
use std::path::Path;

pub(crate) struct IntentionalBoundaryCollectionInputs<'a> {
    pub policy_path: &'a str,
    pub population_path: &'a str,
    pub blind_seal_path: &'a str,
    pub protocol_path: &'a str,
    pub task_path: &'a str,
    pub state_directory: &'a str,
    pub work_directory: &'a str,
    pub frame_directory: &'a str,
    pub output_path: &'a str,
    pub maximum_new_ranks: NonZeroUsize,
}

pub(crate) async fn collect_intentional_boundary_benchmark_frame(
    inputs: IntentionalBoundaryCollectionInputs<'_>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let IntentionalBoundaryCollectionInputs {
        policy_path,
        population_path,
        blind_seal_path,
        protocol_path,
        task_path,
        state_directory,
        work_directory,
        frame_directory,
        output_path,
        maximum_new_ranks,
    } = inputs;
    let output_path = std::path::absolute(output_path)?;
    validate_new_output(&output_path)?;
    let policy = fs::read(policy_path)?;
    let population = fs::read(population_path)?;
    let blind_seal = fs::read(blind_seal_path)?;
    let protocol_bytes = fs::read(protocol_path)?;
    let protocol =
        validate_intentional_boundary_protocol(&policy, &population, &blind_seal, &protocol_bytes)
            .map_err(|error| invalid_data("intentional-boundary protocol is invalid", error))?;
    let task = read_json::<IntentionalBoundaryFrameTask>(task_path)?;
    validate_intentional_boundary_frame_task(
        &policy,
        &population,
        &blind_seal,
        &protocol_bytes,
        &task,
    )
    .map_err(|error| invalid_data("intentional-boundary frame task is invalid", error))?;

    let state_directory = std::path::absolute(state_directory)?;
    let work_directory = std::path::absolute(work_directory)?;
    let frame_directory = std::path::absolute(frame_directory)?;
    let token = std::env::var("GH_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    let summary = run_intentional_boundary_production_sweep_slice(
        IntentionalBoundaryProductionSweepInputs {
            protocol: &protocol,
            task: &task,
            state_root: &state_directory,
            work_root: &work_directory,
            frame_root: &frame_directory,
            github_token: token.as_deref(),
            maximum_new_stages_per_rank: None,
            through_stage: None,
        },
        maximum_new_ranks,
    )
    .await
    .map_err(rank_stage_error)?;

    let terminal_count = summary.completed_count + summary.excluded_count;
    let newly_advanced = summary
        .ranks
        .iter()
        .filter(|rank| !rank.executed_stages.is_empty())
        .count();
    if summary.rank_count < task.repositories.len() {
        eprintln!(
            "Intentional-boundary collection checkpointed\nTerminal prefix: {terminal_count}/{}\nNew ranks advanced: {newly_advanced}\nState: {}\nFrame state: {}\nFinal output not written; rerun the same command to resume.",
            task.repositories.len(),
            state_directory.display(),
            frame_directory.display()
        );
        return Ok(0);
    }
    if summary.paused_count != 0 {
        return Err(invalid_data(
            "intentional-boundary collection did not reach terminal state",
            format!("{} ranks remain paused", summary.paused_count),
        )
        .into());
    }

    let frame = complete_intentional_boundary_candidate_frame_typed(&frame_directory, &task)
        .map_err(frame_error)?;
    write_new_file(&output_path, &serde_json::to_vec_pretty(&frame)?)?;
    eprintln!(
        "Completed intentional-boundary candidate frame written to {}\nRepositories: {}\nAnalyzed: {}\nExcluded: {}\nCandidates: {}\nFrame commitment: {}",
        output_path.display(),
        frame.rank_records.len(),
        frame.analyzed_repository_count,
        frame.excluded_repository_count,
        frame.candidates.len(),
        frame.frame_sha256
    );
    Ok(0)
}

fn validate_new_output(path: &Path) -> Result<(), IoError> {
    match path.try_exists() {
        Ok(false) => {}
        Ok(true) => {
            return Err(IoError::new(
                ErrorKind::AlreadyExists,
                format!(
                    "intentional-boundary output already exists: {}",
                    path.display()
                ),
            ));
        }
        Err(error) => {
            return Err(IoError::new(
                error.kind(),
                format!(
                    "failed to inspect intentional-boundary output {}: {error}",
                    path.display()
                ),
            ));
        }
    }
    let parent = path.parent().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidInput,
            "intentional-boundary output has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!(
                "intentional-boundary output parent does not exist or is not a directory: {}",
                parent.display()
            ),
        ));
    }
    Ok(())
}

fn rank_stage_error(error: IntentionalBoundaryRankStageError) -> IoError {
    let kind = match error.kind {
        IntentionalBoundaryRankStageErrorKind::InvalidInput => ErrorKind::InvalidData,
        IntentionalBoundaryRankStageErrorKind::InfrastructureUnavailable => ErrorKind::NotFound,
        IntentionalBoundaryRankStageErrorKind::InfrastructureFailed => ErrorKind::Other,
    };
    IoError::new(
        kind,
        format!(
            "intentional-boundary collection failed at {:?} ({:?}): {}",
            error.stage, error.kind, error.detail
        ),
    )
}

fn frame_error(error: IntentionalBoundaryFrameError) -> IoError {
    let kind = match error.kind {
        IntentionalBoundaryFrameErrorKind::InvalidInput
        | IntentionalBoundaryFrameErrorKind::CorruptState => ErrorKind::InvalidData,
        IntentionalBoundaryFrameErrorKind::InfrastructureFailed => ErrorKind::Other,
    };
    IoError::new(
        kind,
        format!(
            "intentional-boundary frame finalization failed ({:?}): {}",
            error.kind, error.detail
        ),
    )
}

fn invalid_data(context: &str, detail: impl std::fmt::Display) -> IoError {
    IoError::new(ErrorKind::InvalidData, format!("{context}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::prepare_intentional_boundary_frame_task;

    const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
    const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
    const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
    const PROTOCOL: &[u8] =
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

    #[tokio::test]
    async fn invalid_task_fails_before_production_roots_are_created() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.json");
        let population = root.path().join("population.json");
        let blind_seal = root.path().join("blind-seal.json");
        let protocol = root.path().join("protocol.json");
        let task_path = root.path().join("task.json");
        fs::write(&policy, POLICY).unwrap();
        fs::write(&population, POPULATION).unwrap();
        fs::write(&blind_seal, BLIND_SEAL).unwrap();
        fs::write(&protocol, PROTOCOL).unwrap();
        let mut task =
            prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL)
                .unwrap();
        task.model_access_forbidden = false;
        fs::write(&task_path, serde_json::to_vec_pretty(&task).unwrap()).unwrap();
        let state = root.path().join("state");
        let work = root.path().join("work");
        let frame = root.path().join("frame");
        let output = root.path().join("candidate-frame.json");

        let error =
            collect_intentional_boundary_benchmark_frame(IntentionalBoundaryCollectionInputs {
                policy_path: policy.to_str().unwrap(),
                population_path: population.to_str().unwrap(),
                blind_seal_path: blind_seal.to_str().unwrap(),
                protocol_path: protocol.to_str().unwrap(),
                task_path: task_path.to_str().unwrap(),
                state_directory: state.to_str().unwrap(),
                work_directory: work.to_str().unwrap(),
                frame_directory: frame.to_str().unwrap(),
                output_path: output.to_str().unwrap(),
                maximum_new_ranks: NonZeroUsize::new(1).unwrap(),
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("frame task is invalid"));
        assert!(!state.exists());
        assert!(!work.exists());
        assert!(!frame.exists());
        assert!(!output.exists());
    }

    #[tokio::test]
    async fn existing_output_fails_before_inputs_or_roots_are_read() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("candidate-frame.json");
        fs::write(&output, b"preserve").unwrap();

        let state = root.path().join("state");
        let work = root.path().join("work");
        let frame = root.path().join("frame");
        let error =
            collect_intentional_boundary_benchmark_frame(IntentionalBoundaryCollectionInputs {
                policy_path: "missing-policy",
                population_path: "missing-population",
                blind_seal_path: "missing-seal",
                protocol_path: "missing-protocol",
                task_path: "missing-task",
                state_directory: state.to_str().unwrap(),
                work_directory: work.to_str().unwrap(),
                frame_directory: frame.to_str().unwrap(),
                output_path: output.to_str().unwrap(),
                maximum_new_ranks: NonZeroUsize::new(1).unwrap(),
            })
            .await
            .unwrap_err();

        assert_eq!(
            error.downcast_ref::<IoError>().unwrap().kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(output).unwrap(), b"preserve");
    }

    #[tokio::test]
    async fn missing_output_parent_fails_before_inputs_or_roots_are_read() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let work = root.path().join("work");
        let frame = root.path().join("frame");
        let output = root.path().join("missing").join("candidate-frame.json");

        let error =
            collect_intentional_boundary_benchmark_frame(IntentionalBoundaryCollectionInputs {
                policy_path: "missing-policy",
                population_path: "missing-population",
                blind_seal_path: "missing-seal",
                protocol_path: "missing-protocol",
                task_path: "missing-task",
                state_directory: state.to_str().unwrap(),
                work_directory: work.to_str().unwrap(),
                frame_directory: frame.to_str().unwrap(),
                output_path: output.to_str().unwrap(),
                maximum_new_ranks: NonZeroUsize::new(1).unwrap(),
            })
            .await
            .unwrap_err();

        assert_eq!(
            error.downcast_ref::<IoError>().unwrap().kind(),
            ErrorKind::NotFound
        );
        assert!(!state.exists());
        assert!(!work.exists());
        assert!(!frame.exists());
    }
}
