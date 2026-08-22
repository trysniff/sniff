use super::intentional_boundary_project_model::finish_project_model_census;
use super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, ProjectModelProcessOutput,
    project_model_error,
};
use super::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExclusionReason,
    IntentionalBoundaryProjectModelFailureEvidence, IntentionalBoundaryProjectModelFailurePhase,
    IntentionalBoundaryProjectModelProcessEvidence, IntentionalBoundaryProjectModelProvider,
    IntentionalBoundaryProjectModelStageError, IntentionalBoundaryProjectModelStageErrorKind,
    IntentionalBoundaryRepositoryInventory,
    validate_intentional_boundary_project_model_census_commitment,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const RETAINED_EVIDENCE_LIMIT: usize = 4 * 1024;

pub(super) type ProjectModelProviderRun = (
    IntentionalBoundaryProjectModelProvider,
    Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError>,
);

#[derive(Debug)]
pub(super) enum ResolvedProjectModelRun {
    Completed(IntentionalBoundaryProjectModelCensus),
    Excluded(Vec<IntentionalBoundaryProjectModelFailureEvidence>),
}

pub(super) fn resolve_project_model_runs(
    inventory: &IntentionalBoundaryRepositoryInventory,
    runs: Vec<ProjectModelProviderRun>,
) -> Result<ResolvedProjectModelRun, IntentionalBoundaryProjectModelStageError> {
    let providers = runs
        .iter()
        .map(|(provider, _)| *provider)
        .collect::<Vec<_>>();
    if providers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(stage_error(
            IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
            "project-model provider runs are repeated or not canonical",
        ));
    }
    let mut completed = Vec::new();
    let mut terminal = Vec::new();
    let mut operational = Vec::new();
    for (provider, run) in runs {
        match run {
            Ok(census) => match validate_provider_census(inventory, provider, census) {
                Ok(census) => completed.push(census),
                Err(error) => terminal.push(failure_evidence(error)?),
            },
            Err(error) => match classify_failure(error) {
                Ok(evidence) => terminal.push(evidence),
                Err(error) => operational.push(error),
            },
        }
    }
    if !operational.is_empty() {
        return Err(combine_errors(operational));
    }
    if !terminal.is_empty() {
        terminal.sort_by(failure_key);
        return Ok(ResolvedProjectModelRun::Excluded(terminal));
    }
    let executions = completed
        .iter_mut()
        .flat_map(|census| std::mem::take(&mut census.executions))
        .collect();
    let targets = completed
        .iter_mut()
        .flat_map(|census| std::mem::take(&mut census.targets))
        .collect();
    finish_project_model_census(inventory, executions, targets)
        .map(ResolvedProjectModelRun::Completed)
        .map_err(|detail| {
            stage_error(
                IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
                detail,
            )
        })
}

fn validate_provider_census(
    inventory: &IntentionalBoundaryRepositoryInventory,
    provider: IntentionalBoundaryProjectModelProvider,
    census: IntentionalBoundaryProjectModelCensus,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError> {
    let execution_providers = census
        .executions
        .iter()
        .map(|execution| execution.provider)
        .collect::<BTreeSet<_>>();
    if census.executions.is_empty()
        || execution_providers != BTreeSet::from([provider])
        || census
            .targets
            .iter()
            .any(|target| target.provider != provider)
        || census
            .execution_count_by_provider
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != BTreeSet::from([provider])
    {
        return Err(project_model_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            provider,
            IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
            None,
            "project-model provider contribution changed provider coverage",
        ));
    }
    validate_intentional_boundary_project_model_census_commitment(inventory, &census).map_err(
        |detail| {
            project_model_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                provider,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                None,
                detail,
            )
        },
    )?;
    Ok(census)
}

fn classify_failure(
    error: ProjectModelDerivationError,
) -> Result<IntentionalBoundaryProjectModelFailureEvidence, IntentionalBoundaryProjectModelStageError>
{
    match error.kind {
        ProjectModelDerivationErrorKind::InvalidInput => Err(stage_error(
            IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
            error.detail,
        )),
        ProjectModelDerivationErrorKind::InfrastructureUnavailable => Err(stage_error(
            IntentionalBoundaryProjectModelStageErrorKind::InfrastructureUnavailable,
            error.detail,
        )),
        ProjectModelDerivationErrorKind::InfrastructureFailed => Err(stage_error(
            IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed,
            error.detail,
        )),
        ProjectModelDerivationErrorKind::UnsupportedProjectShape
        | ProjectModelDerivationErrorKind::ProviderRejectedRepository
        | ProjectModelDerivationErrorKind::ProviderOutputIncomplete => failure_evidence(error),
    }
}

fn failure_evidence(
    error: ProjectModelDerivationError,
) -> Result<IntentionalBoundaryProjectModelFailureEvidence, IntentionalBoundaryProjectModelStageError>
{
    let reason = match error.kind {
        ProjectModelDerivationErrorKind::UnsupportedProjectShape => {
            IntentionalBoundaryProjectModelExclusionReason::UnsupportedProjectShape
        }
        ProjectModelDerivationErrorKind::ProviderRejectedRepository => {
            IntentionalBoundaryProjectModelExclusionReason::ProviderRejectedRepository
        }
        ProjectModelDerivationErrorKind::ProviderOutputIncomplete => {
            IntentionalBoundaryProjectModelExclusionReason::ProviderOutputIncomplete
        }
        ProjectModelDerivationErrorKind::InvalidInput
        | ProjectModelDerivationErrorKind::InfrastructureUnavailable
        | ProjectModelDerivationErrorKind::InfrastructureFailed => {
            return Err(stage_error(
                IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
                "operational project-model error cannot become exclusion evidence",
            ));
        }
    };
    let (retained_detail, detail_truncated) = retain(&error.detail);
    Ok(IntentionalBoundaryProjectModelFailureEvidence {
        reason,
        provider: error.provider,
        phase: error.phase,
        invocation_anchor_repository_path: error.invocation_anchor_repository_path,
        detail_sha256: sha256(error.detail.as_bytes()),
        retained_detail,
        detail_truncated,
        process: error.process.map(|process| process_evidence(*process)),
    })
}

fn process_evidence(
    process: ProjectModelProcessOutput,
) -> IntentionalBoundaryProjectModelProcessEvidence {
    let (retained_stdout, local_stdout_truncated) = retain(&process.stdout);
    let (retained_stderr, local_stderr_truncated) = retain(&process.stderr);
    IntentionalBoundaryProjectModelProcessEvidence {
        status_code: process.status_code,
        stdout_sha256: process.stdout_sha256.clone(),
        stderr_sha256: process.stderr_sha256.clone(),
        retained_stdout,
        retained_stderr,
        stdout_truncated: local_stdout_truncated
            || sha256(process.stdout.as_bytes()) != process.stdout_sha256,
        stderr_truncated: local_stderr_truncated
            || sha256(process.stderr.as_bytes()) != process.stderr_sha256,
        timed_out: process.timed_out,
    }
}

pub(super) fn failure_key(
    left: &IntentionalBoundaryProjectModelFailureEvidence,
    right: &IntentionalBoundaryProjectModelFailureEvidence,
) -> std::cmp::Ordering {
    (
        left.provider,
        left.phase,
        left.reason,
        &left.invocation_anchor_repository_path,
        &left.detail_sha256,
    )
        .cmp(&(
            right.provider,
            right.phase,
            right.reason,
            &right.invocation_anchor_repository_path,
            &right.detail_sha256,
        ))
}

fn combine_errors(
    errors: Vec<IntentionalBoundaryProjectModelStageError>,
) -> IntentionalBoundaryProjectModelStageError {
    let kind = if errors
        .iter()
        .any(|error| error.kind == IntentionalBoundaryProjectModelStageErrorKind::InvalidInput)
    {
        IntentionalBoundaryProjectModelStageErrorKind::InvalidInput
    } else if errors.iter().any(|error| {
        error.kind == IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed
    }) {
        IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed
    } else {
        IntentionalBoundaryProjectModelStageErrorKind::InfrastructureUnavailable
    };
    IntentionalBoundaryProjectModelStageError {
        kind,
        detail: errors
            .into_iter()
            .map(|error| error.detail)
            .collect::<Vec<_>>()
            .join("; additionally, "),
    }
}

fn stage_error(
    kind: IntentionalBoundaryProjectModelStageErrorKind,
    detail: impl Into<String>,
) -> IntentionalBoundaryProjectModelStageError {
    IntentionalBoundaryProjectModelStageError {
        kind,
        detail: detail.into(),
    }
}

fn retain(value: &str) -> (String, bool) {
    if value.len() <= RETAINED_EVIDENCE_LIMIT {
        return (value.to_string(), false);
    }
    let mut end = RETAINED_EVIDENCE_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
