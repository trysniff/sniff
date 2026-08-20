use super::intentional_boundary_compiler_evidence::{
    finish_evidence_census, push_typed_atom, validate_evidence_census_commitment,
};
use super::intentional_boundary_generator::{
    GENERATOR_CONTRACT, cargo_generator_command, generator_census_sha256, generator_subjects,
    is_sha256, nearest_declaration, replay_id,
};
use super::intentional_boundary_manifest::validate_manifest_census_commitment;
use super::{
    BoundaryEvidenceKind, INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceProof,
    IntentionalBoundaryGeneratorCensus, IntentionalBoundaryGeneratorProofKind,
    IntentionalBoundaryGeneratorReplayOutcome, IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProofKind,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySourceCensus,
    validate_intentional_boundary_semantic_census,
};
use std::collections::{BTreeMap, BTreeSet};

const GENERATOR_INPUT: &str = "generator_replay";

pub fn compose_intentional_boundary_generator_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    generator_census: &IntentionalBoundaryGeneratorCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_intentional_boundary_generator_census_commitment(
        source_census,
        semantic_census,
        manifest_census,
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
            declaration_location,
            ..
        } = &replay.outcome
        else {
            continue;
        };
        for subject in &replay.subjects {
            let method = methods
                .get(subject.parser_unit_id.as_str())
                .copied()
                .ok_or_else(|| "generator replay invented a method".to_string())?;
            push_typed_atom(
                &mut atoms,
                method,
                &subject.subject_symbol_id,
                BoundaryEvidenceKind::GeneratorConfiguration,
                IntentionalBoundaryEvidenceProof::ManifestContract(
                    IntentionalBoundaryManifestProofKind::GeneratorConfiguration,
                ),
                vec![
                    subject.marker_location.clone(),
                    declaration_location.clone(),
                ],
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
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    generator_census: &IntentionalBoundaryGeneratorCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = compose_intentional_boundary_generator_evidence(
        source_census,
        semantic_census,
        manifest_census,
        base_evidence,
        generator_census,
    )?;
    if evidence_census != &expected {
        return Err("intentional-boundary generator evidence changed".to_string());
    }
    Ok(())
}

pub fn validate_intentional_boundary_generator_census_commitment(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    census: &IntentionalBoundaryGeneratorCensus,
) -> Result<(), String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_manifest_census_commitment(&source_census.inventory_sha256, manifest_census)?;
    validate_evidence_census_commitment(source_census, semantic_census, base_evidence)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION
        || census.generator_contract != GENERATOR_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.inventory_sha256 != source_census.inventory_sha256
        || census.source_census_sha256 != source_census.census_sha256
        || census.semantic_census_sha256 != semantic_census.semantic_census_sha256
        || census.manifest_census_sha256 != manifest_census.manifest_census_sha256
        || census.base_evidence_census_sha256 != base_evidence.evidence_census_sha256
        || census.replays.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("intentional-boundary generator census identity changed".to_string());
    }
    let expected_subjects = generator_subjects(source_census, semantic_census, base_evidence)?;
    let build_declarations = manifest_census
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.declaration_kind == IntentionalBoundaryManifestDeclarationKind::BuildScript
        })
        .collect::<Vec<_>>();
    let mut actual_subjects = Vec::new();
    for replay in &census.replays {
        if replay.subjects.is_empty() || replay.subjects.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("generator replay subjects changed".to_string());
        }
        let expected_configurations = replay
            .subjects
            .iter()
            .map(|subject| nearest_declaration(&subject.repository_path, &build_declarations))
            .collect::<BTreeSet<_>>();
        if expected_configurations.len() != 1
            || expected_configurations.first() != Some(&replay.configuration_declaration_id)
        {
            return Err("generator replay configuration assignment changed".to_string());
        }
        match &replay.outcome {
            IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
                declaration_id,
                declaration_location,
                command,
                outputs,
                executions,
            } => {
                validate_reproduced(
                    source_census,
                    manifest_census,
                    replay,
                    declaration_id,
                    declaration_location,
                    command,
                    outputs,
                    executions,
                )?;
                if replay.configuration_declaration_id.as_deref() != Some(declaration_id) {
                    return Err("generator replay configuration changed".to_string());
                }
            }
            IntentionalBoundaryGeneratorReplayOutcome::Unresolved { detail, .. } => {
                if detail.trim().is_empty() {
                    return Err("generator unresolved outcome has no detail".to_string());
                }
            }
        }
        if replay.replay_id
            != replay_id(
                &census.repository,
                &census.revision,
                replay.configuration_declaration_id.as_deref(),
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
    source: &IntentionalBoundarySourceCensus,
    manifests: &IntentionalBoundaryManifestCensus,
    replay: &super::IntentionalBoundaryGeneratorReplay,
    declaration_id: &str,
    declaration_location: &super::IntentionalBoundarySemanticRange,
    command: &[String],
    outputs: &[super::IntentionalBoundaryGeneratorOutput],
    executions: &[super::IntentionalBoundaryGeneratorExecution],
) -> Result<(), String> {
    let declaration = manifests
        .declarations
        .iter()
        .find(|declaration| declaration.declaration_id == declaration_id)
        .ok_or_else(|| "generator replay declaration is missing".to_string())?;
    if declaration.declaration_kind != IntentionalBoundaryManifestDeclarationKind::BuildScript
        || &declaration.declaration_location != declaration_location
        || cargo_generator_command(declaration).as_deref() != Some(command)
        || executions.len() != 2
        || executions.iter().enumerate().any(|(index, execution)| {
            execution.run_number != (index + 1) as u8
                || execution.command != command
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
