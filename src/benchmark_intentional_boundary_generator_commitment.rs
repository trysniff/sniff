use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) fn validate_replay_success(
    success: &ReplaySuccess,
    command: &GeneratorCommand,
    expected: &[ExpectedOutput],
) -> Result<(), String> {
    let preparation_valid = match &command.preparation {
        None => success.preparations.is_empty(),
        Some(preparation) => {
            success.preparations.len() == 2
                && success
                    .preparations
                    .iter()
                    .enumerate()
                    .all(|(index, execution)| {
                        execution.run_number == (index + 1) as u8
                            && execution.command == *preparation
                            && execution.environment == command.preparation_environment
                            && execution.status_code == 0
                            && !execution.timed_out
                            && execution.network_enabled
                            && is_sha256(&execution.runtime_identity_sha256)
                            && is_sha256(&execution.stdout_sha256)
                            && is_sha256(&execution.stderr_sha256)
                    })
        }
    };
    if !preparation_valid
        || success.executions.len() != 2
        || success
            .executions
            .iter()
            .enumerate()
            .any(|(index, execution)| {
                execution.run_number != (index + 1) as u8
                    || execution.command != command.execution
                    || execution.environment != command.execution_environment
                    || execution.status_code != 0
                    || execution.timed_out
                    || execution.network_enabled
                    || !is_sha256(&execution.runtime_identity_sha256)
                    || !is_sha256(&execution.stdout_sha256)
                    || !is_sha256(&execution.stderr_sha256)
            })
        || success.outputs.len() != expected.len()
    {
        return Err("generator replay executor violated its receipt contract".to_string());
    }
    for (actual, expected) in success.outputs.iter().zip(expected) {
        if actual.repository_path != expected.repository_path
            || actual.object_id != expected.object_id
            || actual.byte_length != expected.byte_length
            || actual.committed_sha256 != expected.committed_sha256
            || actual.first_run_sha256 != expected.committed_sha256
            || actual.second_run_sha256 != expected.committed_sha256
        {
            return Err("generator replay executor changed reproduced output identity".to_string());
        }
    }
    Ok(())
}

pub(super) fn expected_output(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    path: &str,
) -> Result<ExpectedOutput, String> {
    let entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == path)
        .ok_or_else(|| format!("generated output is not tracked: {path}"))?;
    let source = source_census
        .source_files
        .iter()
        .find(|file| file.repository_path == path)
        .ok_or_else(|| format!("generated output is not in the source census: {path}"))?;
    if entry.kind != BoundaryGitEntryKind::RegularBlob
        || entry.byte_length != Some(source.byte_length)
        || entry.object_id != source.object_id
    {
        return Err(format!("generated output identity changed: {path}"));
    }
    Ok(ExpectedOutput {
        repository_path: path.to_string(),
        object_id: entry.object_id.clone(),
        byte_length: source.byte_length,
        committed_sha256: source.source_sha256.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_census(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source: &IntentionalBoundarySourceCensus,
    semantic: &IntentionalBoundarySemanticCensus,
    project_models: &IntentionalBoundaryProjectModelCensus,
    manifests: &IntentionalBoundaryManifestCensus,
    bindings: &IntentionalBoundaryManifestBindingCensus,
    evidence: &IntentionalBoundaryEvidenceCensus,
    mut replays: Vec<IntentionalBoundaryGeneratorReplay>,
) -> Result<IntentionalBoundaryGeneratorCensus, String> {
    replays.sort();
    let replay_count_by_status = replays.iter().fold(BTreeMap::new(), |mut counts, replay| {
        let status = match replay.outcome {
            IntentionalBoundaryGeneratorReplayOutcome::Reproduced { .. } => "reproduced",
            IntentionalBoundaryGeneratorReplayOutcome::Unresolved { .. } => "unresolved",
        };
        *counts.entry(status.to_string()).or_default() += 1;
        counts
    });
    let mut census = IntentionalBoundaryGeneratorCensus {
        schema_version: INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION,
        generator_contract: GENERATOR_CONTRACT.to_string(),
        repository: source.repository.clone(),
        revision: source.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_sha256: source.census_sha256.clone(),
        semantic_census_sha256: semantic.semantic_census_sha256.clone(),
        project_model_census_sha256: project_models.project_model_census_sha256.clone(),
        manifest_census_sha256: manifests.manifest_census_sha256.clone(),
        manifest_binding_census_sha256: bindings.binding_census_sha256.clone(),
        base_evidence_census_sha256: evidence.evidence_census_sha256.clone(),
        replays,
        replay_count_by_status,
        generator_census_sha256: String::new(),
    };
    census.generator_census_sha256 = generator_census_sha256(&census)?;
    Ok(census)
}

pub(in crate::benchmark::release) fn replay_id(
    repository: &str,
    revision: &str,
    candidate_configuration_ids: &[String],
    subjects: &[IntentionalBoundaryGeneratorSubject],
) -> Result<String, String> {
    Ok(format!(
        "ibgr-v1:{}",
        hash_json(&(
            GENERATOR_CONTRACT,
            repository,
            revision,
            candidate_configuration_ids,
            subjects
        ))?
    ))
}

pub(in crate::benchmark::release) fn generator_census_sha256(
    census: &IntentionalBoundaryGeneratorCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.generator_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.project_model_census_sha256,
        &census.manifest_census_sha256,
        &census.manifest_binding_census_sha256,
        &census.base_evidence_census_sha256,
        &census.replays,
        &census.replay_count_by_status,
    ))
}

pub(super) fn unresolved(
    reason: IntentionalBoundaryGeneratorUnresolvedReason,
    detail: impl Into<String>,
) -> IntentionalBoundaryGeneratorReplayOutcome {
    IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
        reason,
        detail: detail.into(),
    }
}

pub(super) fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit generator replay: {error}"))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(in crate::benchmark::release) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
