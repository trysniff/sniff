use super::super::{HistoricalTestRecipeDiscovery, HistoricalTestRecipeStatus};
use super::runtime::compute_execution_id;
use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub fn validate_intentional_boundary_behavior_census_commitment(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    census: &IntentionalBoundaryBehaviorCensus,
) -> Result<(), String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_evidence_census_commitment(source_census, semantic_census, base_evidence)?;
    validate_behavior_base_evidence(base_evidence)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION
        || census.behavior_contract != BEHAVIOR_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.source_census_sha256 != source_census.census_sha256
        || census.semantic_census_sha256 != semantic_census.semantic_census_sha256
        || census.base_evidence_census_sha256 != base_evidence.evidence_census_sha256
    {
        return Err("intentional-boundary behavior identity changed".to_string());
    }
    if census
        .candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id >= pair[1].candidate_id)
        || census
            .witnesses
            .windows(2)
            .any(|pair| pair[0].witness_id >= pair[1].witness_id)
        || census
            .executions
            .windows(2)
            .any(|pair| pair[0].execution_id >= pair[1].execution_id)
    {
        return Err("intentional-boundary behavior ordering changed".to_string());
    }

    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let expected_units = base_evidence
        .atoms
        .iter()
        .filter(|atom| {
            atom.evidence_kind == BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation
        })
        .map(|atom| atom.subject_parser_unit_id.as_str())
        .collect::<BTreeSet<_>>();
    let candidate_units = census
        .candidates
        .iter()
        .map(|candidate| candidate.production_parser_unit_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected_units != candidate_units || candidate_units.len() != census.candidates.len() {
        return Err("intentional-boundary behavior candidate coverage changed".to_string());
    }

    let candidates = census
        .candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let executions = census
        .executions
        .iter()
        .map(|execution| (execution.execution_id.as_str(), execution))
        .collect::<BTreeMap<_, _>>();
    for candidate in &census.candidates {
        let method = methods
            .get(candidate.production_parser_unit_id.as_str())
            .copied()
            .ok_or_else(|| "behavior candidate invented a production method".to_string())?;
        let symbol = resolved_symbol_id(method)
            .ok_or_else(|| "behavior candidate lost its compiler identity".to_string())?;
        if symbol != candidate.production_symbol_id
            || candidate_id(&candidate.production_parser_unit_id, symbol)? != candidate.candidate_id
        {
            return Err("intentional-boundary behavior candidate changed".to_string());
        }
        validate_candidate_status(candidate, &census.witnesses)?;
    }

    let mut referenced_executions = BTreeSet::new();
    for witness in &census.witnesses {
        let candidate = candidates
            .get(witness.candidate_id.as_str())
            .copied()
            .ok_or_else(|| "behavior witness has no candidate".to_string())?;
        if witness.production_parser_unit_id != candidate.production_parser_unit_id
            || witness.production_symbol_id != candidate.production_symbol_id
            || witness_id(
                &witness.candidate_id,
                &witness.test_symbol_id,
                witness.relationship_kind,
                witness.test_parser_unit_id.as_deref(),
            )? != witness.witness_id
            || !matches!(
                witness.relationship_kind,
                IntentionalBoundarySemanticTestKind::Exercises
                    | IntentionalBoundarySemanticTestKind::AssertsContract
            )
        {
            return Err("intentional-boundary behavior witness changed".to_string());
        }
        let production = methods
            .get(witness.production_parser_unit_id.as_str())
            .copied()
            .ok_or_else(|| "behavior witness invented a production method".to_string())?;
        let relationship = production.test_relationships.iter().find(|relationship| {
            relationship.test_symbol == witness.test_symbol_id
                && relationship.kind == witness.relationship_kind
        });
        let Some(relationship) = relationship else {
            return Err("behavior witness invented a compiler test relationship".to_string());
        };
        validate_relationship_and_selector(&methods, relationship, witness)?;
        validate_witness_outcome(witness, &executions, &mut referenced_executions)?;
    }
    if referenced_executions.len() != executions.len()
        || !executions
            .keys()
            .all(|execution_id| referenced_executions.contains(execution_id))
    {
        return Err("intentional-boundary behavior execution is unreferenced".to_string());
    }
    for execution in &census.executions {
        validate_execution(execution, &census.revision)?;
    }

    let candidate_counts = census.candidates.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<String, usize>, candidate| {
            let status = match candidate.status {
                IntentionalBoundaryBehaviorCandidateStatus::Passed { .. } => "passed",
                IntentionalBoundaryBehaviorCandidateStatus::NoResolvedBehaviorTest => {
                    "no_resolved_behavior_test"
                }
                IntentionalBoundaryBehaviorCandidateStatus::Unresolved => "unresolved",
            };
            *counts.entry(status.to_string()).or_default() += 1;
            counts
        },
    );
    let witness_counts = census.witnesses.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<String, usize>, witness| {
            let status = match witness.outcome {
                IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. } => "passed",
                IntentionalBoundaryBehaviorWitnessOutcome::Unresolved { .. } => "unresolved",
            };
            *counts.entry(status.to_string()).or_default() += 1;
            counts
        },
    );
    if census.candidate_count_by_status != candidate_counts
        || census.witness_count_by_status != witness_counts
        || compute_behavior_census_sha256(census)? != census.behavior_census_sha256
    {
        return Err("intentional-boundary behavior census commitment changed".to_string());
    }
    Ok(())
}

fn validate_candidate_status(
    candidate: &IntentionalBoundaryBehaviorCandidate,
    witnesses: &[IntentionalBoundaryBehaviorWitness],
) -> Result<(), String> {
    let candidate_witnesses = witnesses
        .iter()
        .filter(|witness| witness.candidate_id == candidate.candidate_id)
        .collect::<Vec<_>>();
    let passed = candidate_witnesses
        .iter()
        .filter(|witness| {
            matches!(
                witness.outcome,
                IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. }
            )
        })
        .map(|witness| witness.witness_id.clone())
        .collect::<Vec<_>>();
    let valid = match &candidate.status {
        IntentionalBoundaryBehaviorCandidateStatus::Passed { witness_ids } => {
            !passed.is_empty() && witness_ids == &passed
        }
        IntentionalBoundaryBehaviorCandidateStatus::NoResolvedBehaviorTest => {
            candidate_witnesses.is_empty()
        }
        IntentionalBoundaryBehaviorCandidateStatus::Unresolved => {
            !candidate_witnesses.is_empty() && passed.is_empty()
        }
    };
    if !valid {
        return Err("intentional-boundary behavior candidate status changed".to_string());
    }
    Ok(())
}

fn validate_relationship_and_selector(
    methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    relationship: &IntentionalBoundarySemanticTestFacts,
    witness: &IntentionalBoundaryBehaviorWitness,
) -> Result<(), String> {
    match &relationship.production {
        IntentionalBoundarySemanticResolution::Unresolved { detail, .. } => {
            if witness.test_parser_unit_id.is_some()
                || witness.selector.is_some()
                || !matches!(
                    &witness.outcome,
                    IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
                        reason: IntentionalBoundaryBehaviorUnresolvedReason::ProductionRelationshipUnresolved,
                        detail: outcome_detail,
                        execution_id: None,
                        ..
                    } if outcome_detail == detail
                )
            {
                return Err("unresolved production relationship gained proof".to_string());
            }
        }
        IntentionalBoundarySemanticResolution::Resolved { value } => {
            if value != &witness.production_symbol_id {
                return Err("behavior witness changed production identity".to_string());
            }
            let matching_tests = methods
                .values()
                .copied()
                .filter(|method| {
                    resolved_symbol_id(method) == Some(witness.test_symbol_id.as_str())
                })
                .collect::<Vec<_>>();
            match matching_tests.as_slice() {
                [] => {
                    if witness.selector.is_some()
                        || witness.test_parser_unit_id.is_some()
                        || !matches!(
                            witness.outcome,
                            IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
                                reason: IntentionalBoundaryBehaviorUnresolvedReason::TestMethodUnavailable,
                                execution_id: None,
                                ..
                            }
                        )
                    {
                        return Err("missing test method gained behavioral proof".to_string());
                    }
                }
                [test_method] => {
                    if witness.test_parser_unit_id.as_deref()
                        != Some(test_method.parser_unit_id.as_str())
                    {
                        return Err("behavior witness changed test compiler identity".to_string());
                    }
                    match selector_for(test_method) {
                        Ok(expected)
                            if witness.selector.as_ref() == Some(&expected)
                                && valid_resolved_selector_outcome(&expected, &witness.outcome) => {
                        }
                        Err((reason, _))
                            if witness.selector.is_none()
                                && matches!(
                                    witness.outcome,
                                    IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
                                        reason: actual,
                                        execution_id: None,
                                        ..
                                    } if actual == reason
                                ) => {}
                        _ => return Err("behavior witness selector changed".to_string()),
                    }
                }
                _ => {
                    return Err(
                        "behavior witness has an ambiguous compiler test identity".to_string()
                    );
                }
            }
        }
    }
    Ok(())
}

fn valid_resolved_selector_outcome(
    selector: &IntentionalBoundaryBehaviorSelector,
    outcome: &IntentionalBoundaryBehaviorWitnessOutcome,
) -> bool {
    match outcome {
        IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. }
        | IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
            reason:
                IntentionalBoundaryBehaviorUnresolvedReason::RecipeUnavailable
                | IntentionalBoundaryBehaviorUnresolvedReason::RecipeMismatch
                | IntentionalBoundaryBehaviorUnresolvedReason::RuntimeUnavailable
                | IntentionalBoundaryBehaviorUnresolvedReason::SandboxUnavailable
                | IntentionalBoundaryBehaviorUnresolvedReason::PreparationFailed
                | IntentionalBoundaryBehaviorUnresolvedReason::TargetedTestFailed
                | IntentionalBoundaryBehaviorUnresolvedReason::TargetCountMismatch,
            ..
        } => true,
        IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
            reason: IntentionalBoundaryBehaviorUnresolvedReason::UnsupportedTargetSelector,
            ..
        } => matches!(
            selector,
            IntentionalBoundaryBehaviorSelector::JavaScriptTest { .. }
                | IntentionalBoundaryBehaviorSelector::GradleTest { .. }
        ),
        _ => false,
    }
}

fn validate_witness_outcome<'a>(
    witness: &IntentionalBoundaryBehaviorWitness,
    executions: &BTreeMap<&'a str, &'a IntentionalBoundaryBehaviorExecution>,
    referenced: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    let execution_id = match &witness.outcome {
        IntentionalBoundaryBehaviorWitnessOutcome::Passed {
            proof: IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            execution_id,
        } => Some(execution_id),
        IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. } => {
            return Err("behavior witness claimed a non-targeted proof".to_string());
        }
        IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
            reason,
            execution_id,
            detail,
        } => {
            if detail.trim().is_empty()
                || execution_id.is_some()
                    != matches!(
                        reason,
                        IntentionalBoundaryBehaviorUnresolvedReason::PreparationFailed
                            | IntentionalBoundaryBehaviorUnresolvedReason::TargetedTestFailed
                            | IntentionalBoundaryBehaviorUnresolvedReason::TargetCountMismatch
                    )
            {
                return Err("behavior unresolved outcome changed".to_string());
            }
            execution_id.as_ref()
        }
    };
    let Some(execution_id) = execution_id else {
        return Ok(());
    };
    let execution = executions
        .get(execution_id.as_str())
        .copied()
        .ok_or_else(|| "behavior witness references no execution".to_string())?;
    if witness.selector.as_ref() != Some(&execution.selector) {
        return Err("behavior witness execution changed selector".to_string());
    }
    referenced.insert(execution.execution_id.as_str());
    if matches!(
        witness.outcome,
        IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. }
    ) && (execution.status_code != Some(0)
        || execution.timed_out
        || execution.network_enabled
        || !execution.test_executed
        || execution.executed_test_count != 1
        || execution.matched_test_count != 1)
    {
        return Err("passing behavior witness has no exact passing execution".to_string());
    }
    Ok(())
}

fn validate_execution(
    execution: &IntentionalBoundaryBehaviorExecution,
    expected_revision: &str,
) -> Result<(), String> {
    if execution.execution_id != compute_execution_id(execution)?
        || execution.revision != expected_revision
        || execution.provider != execution.selector.provider()
        || !is_sha256(&execution.recipe_sha256)
        || execution.command.is_empty()
        || execution
            .command
            .iter()
            .any(|argument| argument.is_empty() || argument.contains('\0'))
        || !is_sha256(&execution.runtime_identity_sha256)
        || execution.network_enabled
        || !is_sha256(&execution.stdout_sha256)
        || !is_sha256(&execution.stderr_sha256)
        || !is_sha256(&execution.raw_result_sha256)
        || (!execution.test_executed
            && (execution.executed_test_count != 0 || execution.matched_test_count != 0))
        || execution.matched_test_count > execution.executed_test_count
    {
        return Err("intentional-boundary behavior execution changed".to_string());
    }
    let recipe: HistoricalTestRecipeDiscovery = serde_json::from_str(&execution.recipe_json)
        .map_err(|_| "intentional-boundary behavior recipe receipt changed".to_string())?;
    if recipe.status != HistoricalTestRecipeStatus::Selected
        || sha256(execution.recipe_json.as_bytes()) != execution.recipe_sha256
    {
        return Err("intentional-boundary behavior recipe receipt changed".to_string());
    }
    let (preparation, command) = runtime::targeted_command(&execution.selector, &recipe)
        .map_err(|_| "intentional-boundary behavior targeted recipe changed".to_string())?;
    if command != execution.command {
        return Err("intentional-boundary behavior targeted command changed".to_string());
    }
    validate_raw_receipt(execution, &preparation)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecutionReceipt {
    schema_version: u32,
    revision: String,
    runtime_identity: String,
    network_enabled: bool,
    preparation: Vec<RawStepReceipt>,
    test: Option<RawStepReceipt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStepReceipt {
    stage: String,
    logical_command: Vec<String>,
    launcher_kind: String,
    status_code: Option<i32>,
    timed_out: bool,
    network_enabled: bool,
    stdout_complete_sha256: String,
    stderr_complete_sha256: String,
    stdout_bounded_sanitized: String,
    stderr_bounded_sanitized: String,
}

fn validate_raw_receipt(
    execution: &IntentionalBoundaryBehaviorExecution,
    expected_preparation: &[Vec<String>],
) -> Result<(), String> {
    if sha256(execution.raw_result_json.as_bytes()) != execution.raw_result_sha256 {
        return Err("intentional-boundary behavior raw receipt hash changed".to_string());
    }
    let raw: RawExecutionReceipt = serde_json::from_str(&execution.raw_result_json)
        .map_err(|_| "intentional-boundary behavior raw receipt changed".to_string())?;
    if raw.schema_version != 1
        || raw.revision != execution.revision
        || sha256(raw.runtime_identity.as_bytes()) != execution.runtime_identity_sha256
        || raw.network_enabled
        || raw.preparation.len() != expected_preparation.len()
    {
        return Err("intentional-boundary behavior raw receipt changed".to_string());
    }
    for (index, (step, expected)) in raw.preparation.iter().zip(expected_preparation).enumerate() {
        if step.stage != format!("preparation_{}", index + 1)
            || step.logical_command != *expected
            || step.launcher_kind.trim().is_empty()
            || step.network_enabled
            || !is_sha256(&step.stdout_complete_sha256)
            || !is_sha256(&step.stderr_complete_sha256)
        {
            return Err("intentional-boundary behavior preparation receipt changed".to_string());
        }
    }
    if execution.test_executed != raw.test.is_some() {
        return Err("intentional-boundary behavior test receipt changed".to_string());
    }
    if let Some(test) = &raw.test
        && (test.stage != "test"
            || test.logical_command != execution.command
            || test.launcher_kind.trim().is_empty()
            || test.network_enabled)
    {
        return Err("intentional-boundary behavior test receipt changed".to_string());
    }
    let representative = raw
        .test
        .as_ref()
        .or_else(|| raw.preparation.last())
        .ok_or_else(|| "intentional-boundary behavior receipt has no process result".to_string())?;
    if representative.status_code != execution.status_code
        || representative.timed_out != execution.timed_out
        || representative.stdout_complete_sha256 != execution.stdout_sha256
        || representative.stderr_complete_sha256 != execution.stderr_sha256
    {
        return Err("intentional-boundary behavior terminal result changed".to_string());
    }
    let replayed = if execution.test_executed
        && !execution.timed_out
        && execution.status_code == Some(0)
    {
        runtime::count_tests(
            &execution.selector,
            &representative.stdout_bounded_sanitized,
            &representative.stderr_bounded_sanitized,
        )
        .map_err(|_| "intentional-boundary behavior test count cannot be replayed".to_string())?
    } else {
        runtime::TestCount::default()
    };
    if replayed.executed != execution.executed_test_count
        || replayed.matched != execution.matched_test_count
    {
        return Err("intentional-boundary behavior test count changed".to_string());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
