use super::{NonBlindHistoryWorksheet, validate_intentional_boundary_protocol};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INTENTIONAL_BOUNDARY_FRAME_TASK_SCHEMA_VERSION: u32 = 1;
const FRAME_TASK_CONTRACT: &str = "sniffbench-intentional-boundary-frame-task-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryFrameExclusionReason {
    RepositoryInaccessible,
    EmptyRepository,
    NoSupportedSources,
    UnsupportedProjectShape,
    MissingLicense,
}

impl IntentionalBoundaryFrameExclusionReason {
    fn all() -> Vec<Self> {
        vec![
            Self::RepositoryInaccessible,
            Self::EmptyRepository,
            Self::NoSupportedSources,
            Self::UnsupportedProjectShape,
            Self::MissingLicense,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryRepositoryTask {
    pub population_rank: usize,
    pub repository: String,
    pub population_rank_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryFrameTask {
    pub schema_version: u32,
    pub frame_task_contract: String,
    pub protocol_sha256: String,
    pub policy_sha256: String,
    pub population_sha256: String,
    pub population_task_sha256: String,
    pub blind_source_seal_sha256: String,
    pub blind_source_seal_commitment_sha256: String,
    pub no_fallbacks: bool,
    pub model_access_forbidden: bool,
    pub sniff_output_access_forbidden: bool,
    pub terminal_exclusions: Vec<IntentionalBoundaryFrameExclusionReason>,
    pub repositories: Vec<IntentionalBoundaryRepositoryTask>,
    pub task_sha256: String,
}

pub fn prepare_intentional_boundary_frame_task(
    policy_bytes: &[u8],
    population_bytes: &[u8],
    blind_seal_bytes: &[u8],
    protocol_bytes: &[u8],
) -> Result<IntentionalBoundaryFrameTask, String> {
    let validated = validate_intentional_boundary_protocol(
        policy_bytes,
        population_bytes,
        blind_seal_bytes,
        protocol_bytes,
    )?;
    let population: NonBlindHistoryWorksheet = serde_json::from_slice(population_bytes)
        .map_err(|error| format!("failed to parse intentional-boundary population: {error}"))?;
    let protocol = validated.protocol;
    let repositories = population
        .candidates
        .iter()
        .map(|candidate| IntentionalBoundaryRepositoryTask {
            population_rank: candidate.rank,
            repository: candidate.repository.clone(),
            population_rank_sha256: candidate.rank_sha256.clone(),
        })
        .collect::<Vec<_>>();
    let terminal_exclusions = IntentionalBoundaryFrameExclusionReason::all();
    let mut task = IntentionalBoundaryFrameTask {
        schema_version: INTENTIONAL_BOUNDARY_FRAME_TASK_SCHEMA_VERSION,
        frame_task_contract: FRAME_TASK_CONTRACT.to_string(),
        protocol_sha256: validated.protocol_sha256,
        policy_sha256: protocol.selection_policy.sha256,
        population_sha256: protocol.repository_population.sha256,
        population_task_sha256: protocol.repository_population.task_sha256,
        blind_source_seal_sha256: protocol.blind_source_seal.sha256,
        blind_source_seal_commitment_sha256: protocol.blind_source_seal.seal_sha256,
        no_fallbacks: true,
        model_access_forbidden: true,
        sniff_output_access_forbidden: true,
        terminal_exclusions,
        repositories,
        task_sha256: String::new(),
    };
    task.task_sha256 = compute_task_sha256(&task)?;
    Ok(task)
}

pub fn validate_intentional_boundary_frame_task(
    policy_bytes: &[u8],
    population_bytes: &[u8],
    blind_seal_bytes: &[u8],
    protocol_bytes: &[u8],
    task: &IntentionalBoundaryFrameTask,
) -> Result<(), String> {
    let expected = prepare_intentional_boundary_frame_task(
        policy_bytes,
        population_bytes,
        blind_seal_bytes,
        protocol_bytes,
    )?;
    if task != &expected {
        return Err("intentional-boundary frame task changed its immutable population".to_string());
    }
    Ok(())
}

fn compute_task_sha256(task: &IntentionalBoundaryFrameTask) -> Result<String, String> {
    #[derive(Serialize)]
    struct CommittedTask<'a> {
        schema_version: u32,
        frame_task_contract: &'a str,
        protocol_sha256: &'a str,
        policy_sha256: &'a str,
        population_sha256: &'a str,
        population_task_sha256: &'a str,
        blind_source_seal_sha256: &'a str,
        blind_source_seal_commitment_sha256: &'a str,
        no_fallbacks: bool,
        model_access_forbidden: bool,
        sniff_output_access_forbidden: bool,
        terminal_exclusions: &'a [IntentionalBoundaryFrameExclusionReason],
        repositories: &'a [IntentionalBoundaryRepositoryTask],
    }

    let committed = CommittedTask {
        schema_version: task.schema_version,
        frame_task_contract: &task.frame_task_contract,
        protocol_sha256: &task.protocol_sha256,
        policy_sha256: &task.policy_sha256,
        population_sha256: &task.population_sha256,
        population_task_sha256: &task.population_task_sha256,
        blind_source_seal_sha256: &task.blind_source_seal_sha256,
        blind_source_seal_commitment_sha256: &task.blind_source_seal_commitment_sha256,
        no_fallbacks: task.no_fallbacks,
        model_access_forbidden: task.model_access_forbidden,
        sniff_output_access_forbidden: task.sniff_output_access_forbidden,
        terminal_exclusions: &task.terminal_exclusions,
        repositories: &task.repositories,
    };
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit intentional-boundary frame task: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
    const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
    const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
    const PROTOCOL: &[u8] =
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

    fn task() -> IntentionalBoundaryFrameTask {
        prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
    }

    #[test]
    fn prepares_the_exact_blank_six_hundred_repository_task() {
        let task = task();
        let population: NonBlindHistoryWorksheet = serde_json::from_slice(POPULATION).unwrap();

        assert_eq!(task.repositories.len(), 600);
        assert_eq!(task.repositories[0].population_rank, 1);
        assert_eq!(task.repositories[599].population_rank, 600);
        assert_eq!(
            task.repositories[0].repository,
            population.candidates[0].repository
        );
        assert_eq!(
            task.repositories[599].repository,
            population.candidates[599].repository
        );
        assert_eq!(task.task_sha256.len(), 64);
        assert!(task.no_fallbacks);
        assert!(task.model_access_forbidden);
        assert!(task.sniff_output_access_forbidden);
        validate_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL, &task)
            .unwrap();
    }

    #[test]
    fn rejects_rank_order_identity_and_task_tampering() {
        let mut changed = task();
        changed.repositories.swap(0, 1);
        assert!(
            validate_intentional_boundary_frame_task(
                POLICY, POPULATION, BLIND_SEAL, PROTOCOL, &changed,
            )
            .unwrap_err()
            .contains("immutable population")
        );

        let mut changed = task();
        changed.repositories[0].population_rank = 2;
        assert!(
            validate_intentional_boundary_frame_task(
                POLICY, POPULATION, BLIND_SEAL, PROTOCOL, &changed,
            )
            .is_err()
        );

        let mut changed = task();
        changed.repositories[0].repository.push_str("-different");
        assert!(
            validate_intentional_boundary_frame_task(
                POLICY, POPULATION, BLIND_SEAL, PROTOCOL, &changed,
            )
            .is_err()
        );

        let mut changed = task();
        changed.task_sha256.replace_range(..1, "0");
        assert!(
            validate_intentional_boundary_frame_task(
                POLICY, POPULATION, BLIND_SEAL, PROTOCOL, &changed,
            )
            .is_err()
        );
    }

    #[test]
    fn excludes_operational_failures_from_the_terminal_reason_contract() {
        let values = task()
            .terminal_exclusions
            .iter()
            .map(|reason| serde_json::to_value(reason).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            values,
            vec![
                "repository_inaccessible",
                "empty_repository",
                "no_supported_sources",
                "unsupported_project_shape",
                "missing_license",
            ]
        );
        assert!(
            serde_json::from_str::<IntentionalBoundaryFrameExclusionReason>(
                "\"transport_failure\""
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<IntentionalBoundaryFrameExclusionReason>(
                "\"indexer_unavailable\""
            )
            .is_err()
        );
    }
}
