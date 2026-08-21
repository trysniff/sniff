use super::intentional_boundary_compiler_evidence::{
    finish_evidence_census, push_typed_atom, validate_evidence_census_commitment,
};
use super::intentional_boundary_generator::configuration::{
    GeneratorConfiguration, GeneratorConfigurationEvidenceProof, configurations,
    configurations_by_id, validate_candidate_partition,
};
use super::intentional_boundary_generator::{
    GENERATOR_CONTRACT, ReplayContext, generator_census_sha256, generator_subjects, is_sha256,
    replay_id,
};
use super::intentional_boundary_manifest::validate_manifest_census_commitment;
use super::{
    BoundaryEvidenceKind, INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceProof,
    IntentionalBoundaryGeneratorCensus, IntentionalBoundaryGeneratorProofKind,
    IntentionalBoundaryGeneratorReplayOutcome, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestCensus, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_manifest_bindings,
    validate_intentional_boundary_project_model_census_commitment,
    validate_intentional_boundary_semantic_census,
};
use std::collections::{BTreeMap, BTreeSet};

const GENERATOR_INPUT: &str = "generator_replay";

#[derive(Clone, Copy)]
pub struct IntentionalBoundaryGeneratorEvidenceInputs<'a> {
    pub inventory: &'a IntentionalBoundaryRepositoryInventory,
    pub source_census: &'a IntentionalBoundarySourceCensus,
    pub semantic_census: &'a IntentionalBoundarySemanticCensus,
    pub project_model_census: &'a IntentionalBoundaryProjectModelCensus,
    pub manifest_census: &'a IntentionalBoundaryManifestCensus,
    pub binding_census: &'a IntentionalBoundaryManifestBindingCensus,
    pub base_evidence: &'a IntentionalBoundaryEvidenceCensus,
    pub generator_census: &'a IntentionalBoundaryGeneratorCensus,
}

pub fn compose_intentional_boundary_generator_evidence(
    inputs: IntentionalBoundaryGeneratorEvidenceInputs<'_>,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    let IntentionalBoundaryGeneratorEvidenceInputs {
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        manifest_census,
        binding_census,
        base_evidence,
        generator_census,
    } = inputs;
    validate_intentional_boundary_generator_census_commitment(
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        manifest_census,
        binding_census,
        base_evidence,
        generator_census,
    )?;
    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut atoms = base_evidence.atoms.clone();
    for replay in &generator_census.replays {
        let IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
            configuration_id,
            configuration_evidence_locations,
            ..
        } = &replay.outcome
        else {
            continue;
        };
        let configurations = configurations(&manifest_census.declarations, project_model_census)?;
        let configuration_by_id = configurations_by_id(&configurations);
        let configuration = configuration_by_id
            .get(configuration_id.as_str())
            .copied()
            .ok_or_else(|| "generator replay configuration is missing".to_string())?;
        let proof = match configuration.evidence_proof() {
            GeneratorConfigurationEvidenceProof::Manifest(kind) => {
                IntentionalBoundaryEvidenceProof::ManifestContract(kind)
            }
            GeneratorConfigurationEvidenceProof::ProjectModel(kind) => {
                IntentionalBoundaryEvidenceProof::ProjectModelContract(kind)
            }
        };
        for subject in &replay.subjects {
            let method = methods
                .get(subject.parser_unit_id.as_str())
                .copied()
                .ok_or_else(|| "generator replay invented a method".to_string())?;
            let mut configuration_locations = vec![subject.marker_location.clone()];
            configuration_locations.extend(configuration_evidence_locations.iter().cloned());
            push_typed_atom(
                &mut atoms,
                method,
                &subject.subject_symbol_id,
                BoundaryEvidenceKind::GeneratorConfiguration,
                proof,
                configuration_locations,
                Vec::new(),
            )?;
            push_typed_atom(
                &mut atoms,
                method,
                &subject.subject_symbol_id,
                BoundaryEvidenceKind::ReproducibleGeneratedOutput,
                IntentionalBoundaryEvidenceProof::GeneratorReplay(
                    IntentionalBoundaryGeneratorProofKind::ReproducedTrackedOutput,
                ),
                vec![subject.marker_location.clone()],
                Vec::new(),
            )?;
        }
    }
    let mut inputs = base_evidence.input_census_sha256.clone();
    if inputs
        .insert(
            GENERATOR_INPUT.to_string(),
            generator_census.generator_census_sha256.clone(),
        )
        .is_some()
    {
        return Err("generator evidence input collision".to_string());
    }
    finish_evidence_census(source_census, semantic_census, inputs, atoms)
}

pub fn validate_intentional_boundary_generator_evidence(
    inputs: IntentionalBoundaryGeneratorEvidenceInputs<'_>,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = compose_intentional_boundary_generator_evidence(inputs)?;
    if evidence_census != &expected {
        return Err("intentional-boundary generator evidence changed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_generator_census_commitment(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    census: &IntentionalBoundaryGeneratorCensus,
) -> Result<(), String> {
    if inventory.inventory_sha256 != source_census.inventory_sha256
        || inventory.repository != source_census.repository
        || inventory.revision != source_census.revision
    {
        return Err("intentional-boundary generator inventory identity changed".to_string());
    }
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_intentional_boundary_project_model_census_commitment(inventory, project_model_census)?;
    validate_manifest_census_commitment(&source_census.inventory_sha256, manifest_census)?;
    validate_intentional_boundary_manifest_bindings(
        source_census,
        semantic_census,
        manifest_census,
        binding_census,
    )?;
    validate_evidence_census_commitment(source_census, semantic_census, base_evidence)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION
        || census.generator_contract != GENERATOR_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.inventory_sha256 != source_census.inventory_sha256
        || census.source_census_sha256 != source_census.census_sha256
        || census.semantic_census_sha256 != semantic_census.semantic_census_sha256
        || census.project_model_census_sha256 != project_model_census.project_model_census_sha256
        || census.manifest_census_sha256 != manifest_census.manifest_census_sha256
        || census.manifest_binding_census_sha256 != binding_census.binding_census_sha256
        || census.base_evidence_census_sha256 != base_evidence.evidence_census_sha256
        || census.replays.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("intentional-boundary generator census identity changed".to_string());
    }
    let expected_subjects = generator_subjects(source_census, semantic_census, base_evidence)?;
    let configurations = configurations(&manifest_census.declarations, project_model_census)?;
    let configuration_by_id = configurations_by_id(&configurations);
    let mut actual_subjects = Vec::new();
    for replay in &census.replays {
        if replay.subjects.is_empty() || replay.subjects.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("generator replay subjects changed".to_string());
        }
        if !validate_candidate_partition(
            &replay.subjects,
            &configurations,
            &replay.candidate_configuration_ids,
        ) {
            return Err("generator replay configuration assignment changed".to_string());
        }
        match &replay.outcome {
            IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
                configuration_id,
                configuration_evidence_locations,
                preparations,
                command,
                outputs,
                executions,
            } => {
                validate_reproduced(
                    inventory,
                    source_census,
                    semantic_census,
                    project_model_census,
                    manifest_census,
                    binding_census,
                    configuration_by_id
                        .get(configuration_id.as_str())
                        .copied()
                        .ok_or_else(|| "generator replay configuration is missing".to_string())?,
                    replay,
                    configuration_id,
                    configuration_evidence_locations,
                    preparations,
                    command,
                    outputs,
                    executions,
                )?;
                if replay.configuration_id.as_deref() != Some(configuration_id)
                    || !replay
                        .candidate_configuration_ids
                        .iter()
                        .any(|candidate| candidate == configuration_id)
                {
                    return Err("generator replay configuration changed".to_string());
                }
            }
            IntentionalBoundaryGeneratorReplayOutcome::Unresolved { detail, .. } => {
                if detail.trim().is_empty() || replay.configuration_id.is_some() {
                    return Err("generator unresolved outcome has no detail".to_string());
                }
            }
        }
        if replay.replay_id
            != replay_id(
                &census.repository,
                &census.revision,
                &replay.candidate_configuration_ids,
                &replay.subjects,
            )?
        {
            return Err("generator replay identity changed".to_string());
        }
        actual_subjects.extend(replay.subjects.iter().cloned());
    }
    actual_subjects.sort();
    if actual_subjects != expected_subjects {
        return Err("generator replay omitted or duplicated subjects".to_string());
    }
    let counts = census
        .replays
        .iter()
        .fold(BTreeMap::new(), |mut counts, replay| {
            let status = match replay.outcome {
                IntentionalBoundaryGeneratorReplayOutcome::Reproduced { .. } => "reproduced",
                IntentionalBoundaryGeneratorReplayOutcome::Unresolved { .. } => "unresolved",
            };
            *counts.entry(status.to_string()).or_default() += 1;
            counts
        });
    if census.replay_count_by_status != counts
        || generator_census_sha256(census)? != census.generator_census_sha256
    {
        return Err("generator census commitment changed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_reproduced(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source: &IntentionalBoundarySourceCensus,
    semantic: &IntentionalBoundarySemanticCensus,
    project_models: &IntentionalBoundaryProjectModelCensus,
    manifests: &IntentionalBoundaryManifestCensus,
    bindings: &IntentionalBoundaryManifestBindingCensus,
    configuration: &GeneratorConfiguration<'_>,
    replay: &super::IntentionalBoundaryGeneratorReplay,
    configuration_id: &str,
    configuration_evidence_locations: &[super::IntentionalBoundarySemanticRange],
    preparations: &[super::IntentionalBoundaryGeneratorExecution],
    command: &[String],
    outputs: &[super::IntentionalBoundaryGeneratorOutput],
    executions: &[super::IntentionalBoundaryGeneratorExecution],
) -> Result<(), String> {
    let context = ReplayContext {
        inventory,
        source_census: source,
        semantic_census: semantic,
        project_model_census: project_models,
        binding_census: bindings,
        declarations: &manifests.declarations,
    };
    let planned = configuration
        .command(&context)
        .ok_or_else(|| "generator replay configuration is unsupported".to_string())?;
    let preparations_valid = match &planned.preparation {
        None => preparations.is_empty(),
        Some(preparation) => {
            preparations.len() == 2
                && preparations.iter().enumerate().all(|(index, execution)| {
                    execution.run_number == (index + 1) as u8
                        && execution.command == *preparation
                        && execution.environment == planned.preparation_environment
                        && execution.status_code == 0
                        && !execution.timed_out
                        && execution.network_enabled
                        && is_sha256(&execution.runtime_identity_sha256)
                        && is_sha256(&execution.stdout_sha256)
                        && is_sha256(&execution.stderr_sha256)
                })
        }
    };
    if configuration.id() != configuration_id
        || configuration.evidence_locations() != configuration_evidence_locations
        || planned.execution != command
        || !preparations_valid
        || executions.len() != 2
        || executions.iter().enumerate().any(|(index, execution)| {
            execution.run_number != (index + 1) as u8
                || execution.command != command
                || execution.environment != planned.execution_environment
                || execution.status_code != 0
                || execution.timed_out
                || execution.network_enabled
                || !is_sha256(&execution.runtime_identity_sha256)
                || !is_sha256(&execution.stdout_sha256)
                || !is_sha256(&execution.stderr_sha256)
        })
    {
        return Err("generator reproduced receipt changed".to_string());
    }
    let subject_paths = replay
        .subjects
        .iter()
        .map(|subject| subject.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let output_paths = outputs
        .iter()
        .map(|output| output.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    if outputs.is_empty()
        || outputs.windows(2).any(|pair| pair[0] >= pair[1])
        || output_paths != subject_paths
    {
        return Err("generator reproduced outputs changed".to_string());
    }
    for output in outputs {
        let file = source
            .source_files
            .iter()
            .find(|file| file.repository_path == output.repository_path)
            .ok_or_else(|| "generator output left the source census".to_string())?;
        if output.object_id != file.object_id
            || output.byte_length != file.byte_length
            || output.committed_sha256 != file.source_sha256
            || output.first_run_sha256 != file.source_sha256
            || output.second_run_sha256 != file.source_sha256
        {
            return Err("generator output bytes changed".to_string());
        }
    }
    Ok(())
}
