use super::intentional_boundary_compiler_evidence::validate_evidence_census_commitment;
use super::intentional_boundary_compiler_evidence::{finish_evidence_census, push_typed_atom};
use super::{
    BoundaryEvidenceKind, INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryBehaviorCandidate, IntentionalBoundaryBehaviorCandidateStatus,
    IntentionalBoundaryBehaviorCensus, IntentionalBoundaryBehaviorExecution,
    IntentionalBoundaryBehaviorSelector, IntentionalBoundaryBehaviorTestProofKind,
    IntentionalBoundaryBehaviorUnresolvedReason, IntentionalBoundaryBehaviorWitness,
    IntentionalBoundaryBehaviorWitnessOutcome, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundaryEvidenceProof, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticTestFacts, IntentionalBoundarySemanticTestKind,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_repository_inventory,
    validate_intentional_boundary_semantic_census, validate_intentional_boundary_source_census,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

const BEHAVIOR_CONTRACT: &str = "sniffbench-intentional-boundary-behavior-v1";

#[path = "benchmark_intentional_boundary_behavior_runtime.rs"]
mod runtime;

#[path = "benchmark_intentional_boundary_behavior_validation.rs"]
mod validation;
pub use validation::validate_intentional_boundary_behavior_census_commitment;

#[derive(Clone)]
pub(super) struct BehaviorExecutionAttempt {
    pub(super) execution: Option<IntentionalBoundaryBehaviorExecution>,
    pub(super) outcome: IntentionalBoundaryBehaviorWitnessOutcome,
}

#[allow(clippy::too_many_arguments)]
pub fn census_intentional_boundary_behavior_tests(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryBehaviorCensus, String> {
    census_behavior_tests_with_executor(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        base_evidence,
        |selector| runtime::execute_behavior_selector(root, revision, selector),
    )
}

pub fn compose_intentional_boundary_behavior_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    behavior_census: &IntentionalBoundaryBehaviorCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_intentional_boundary_behavior_census_commitment(
        source_census,
        semantic_census,
        base_evidence,
        behavior_census,
    )?;
    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut atoms = base_evidence.atoms.clone();
    for witness in &behavior_census.witnesses {
        let IntentionalBoundaryBehaviorWitnessOutcome::Passed {
            proof: IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            ..
        } = witness.outcome
        else {
            continue;
        };
        let production = methods
            .get(witness.production_parser_unit_id.as_str())
            .copied()
            .ok_or_else(|| "behavior evidence invented a production method".to_string())?;
        let test = witness
            .test_parser_unit_id
            .as_deref()
            .and_then(|unit| methods.get(unit).copied())
            .ok_or_else(|| "passing behavior evidence has no test method".to_string())?;
        let locations = definition_locations(production)
            .into_iter()
            .chain(definition_locations(test))
            .collect();
        push_typed_atom(
            &mut atoms,
            production,
            &witness.production_symbol_id,
            BoundaryEvidenceKind::PassingBehaviorTest,
            IntentionalBoundaryEvidenceProof::ExecutedBehaviorTest(
                IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            ),
            locations,
            vec![witness.test_symbol_id.clone()],
        )?;
    }
    let mut inputs = base_evidence.input_census_sha256.clone();
    inputs.insert(
        "targeted_behavior_tests".to_string(),
        behavior_census.behavior_census_sha256.clone(),
    );
    finish_evidence_census(source_census, semantic_census, inputs, atoms)
}

pub fn validate_intentional_boundary_behavior_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    behavior_census: &IntentionalBoundaryBehaviorCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = compose_intentional_boundary_behavior_evidence(
        source_census,
        semantic_census,
        base_evidence,
        behavior_census,
    )?;
    if evidence_census != &expected {
        return Err("intentional-boundary behavior evidence changed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn census_behavior_tests_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    mut executor: F,
) -> Result<IntentionalBoundaryBehaviorCensus, String>
where
    F: FnMut(&IntentionalBoundaryBehaviorSelector) -> Result<BehaviorExecutionAttempt, String>,
{
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_evidence_census_commitment(source_census, semantic_census, base_evidence)?;
    validate_behavior_base_evidence(base_evidence)?;

    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let symbol_methods = semantic_census
        .methods
        .iter()
        .filter_map(|method| resolved_symbol_id(method).map(|symbol| (symbol, method)))
        .collect::<BTreeMap<_, _>>();
    let candidate_units = base_evidence
        .atoms
        .iter()
        .filter(|atom| {
            matches!(
                atom.evidence_kind,
                BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation
                    | BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes
            )
        })
        .map(|atom| atom.subject_parser_unit_id.as_str())
        .collect::<BTreeSet<_>>();

    let mut candidates = Vec::new();
    let mut witnesses = Vec::new();
    let mut executions = Vec::new();
    let mut execution_ids = BTreeSet::new();
    let mut attempts =
        BTreeMap::<IntentionalBoundaryBehaviorSelector, BehaviorExecutionAttempt>::new();
    for parser_unit_id in candidate_units {
        let method = methods.get(parser_unit_id).copied().ok_or_else(|| {
            format!("intentional-boundary behavior evidence invented method {parser_unit_id}")
        })?;
        let production_symbol_id = resolved_symbol_id(method).ok_or_else(|| {
            format!("behavior-test candidate has no compiler identity: {parser_unit_id}")
        })?;
        if base_evidence.atoms.iter().any(|atom| {
            atom.subject_parser_unit_id == parser_unit_id
                && matches!(
                    atom.evidence_kind,
                    BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation
                        | BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes
                )
                && atom.subject_symbol_id != production_symbol_id
        }) {
            return Err(format!(
                "behavior-test candidate changed compiler identity: {parser_unit_id}"
            ));
        }
        let candidate_id = candidate_id(parser_unit_id, production_symbol_id)?;
        let behavior_relationships = method
            .test_relationships
            .iter()
            .filter(|relationship| {
                matches!(
                    relationship.kind,
                    IntentionalBoundarySemanticTestKind::Exercises
                        | IntentionalBoundarySemanticTestKind::AssertsContract
                )
            })
            .filter(|relationship| match &relationship.production {
                IntentionalBoundarySemanticResolution::Resolved { value } => {
                    value == production_symbol_id
                }
                IntentionalBoundarySemanticResolution::Unresolved { .. } => true,
            })
            .collect::<Vec<_>>();
        let witness_start = witnesses.len();
        for relationship in behavior_relationships {
            let (test_method, selector, attempt) = match &relationship.production {
                IntentionalBoundarySemanticResolution::Unresolved { detail, .. } => (
                    None,
                    None,
                    BehaviorExecutionAttempt {
                        execution: None,
                        outcome: unresolved(
                            IntentionalBoundaryBehaviorUnresolvedReason::ProductionRelationshipUnresolved,
                            detail.clone(),
                        ),
                    },
                ),
                IntentionalBoundarySemanticResolution::Resolved { .. } => {
                    match symbol_methods.get(relationship.test_symbol.as_str()).copied() {
                        None => (
                            None,
                            None,
                            BehaviorExecutionAttempt {
                                execution: None,
                                outcome: unresolved(
                                    IntentionalBoundaryBehaviorUnresolvedReason::TestMethodUnavailable,
                                    format!(
                                        "compiler test symbol has no parser method: {}",
                                        relationship.test_symbol
                                    ),
                                ),
                            },
                        ),
                        Some(test_method) => match selector_for(test_method) {
                            Ok(selector) => {
                                let attempt = match attempts.get(&selector) {
                                    Some(attempt) => attempt.clone(),
                                    None => {
                                        let attempt = executor(&selector)?;
                                        attempts.insert(selector.clone(), attempt.clone());
                                        attempt
                                    }
                                };
                                (Some(test_method), Some(selector), attempt)
                            }
                            Err((reason, detail)) => (
                                Some(test_method),
                                None,
                                BehaviorExecutionAttempt {
                                    execution: None,
                                    outcome: unresolved(reason, detail),
                                },
                            ),
                        },
                    }
                }
            };
            if let Some(execution) = attempt.execution
                && execution_ids.insert(execution.execution_id.clone())
            {
                executions.push(execution);
            }
            let test_parser_unit_id = test_method.map(|method| method.parser_unit_id.clone());
            let witness_id = witness_id(
                &candidate_id,
                &relationship.test_symbol,
                relationship.kind,
                test_parser_unit_id.as_deref(),
            )?;
            witnesses.push(IntentionalBoundaryBehaviorWitness {
                witness_id,
                candidate_id: candidate_id.clone(),
                production_parser_unit_id: method.parser_unit_id.clone(),
                production_symbol_id: production_symbol_id.to_string(),
                test_parser_unit_id,
                test_symbol_id: relationship.test_symbol.clone(),
                relationship_kind: relationship.kind,
                selector,
                outcome: attempt.outcome,
            });
        }
        let candidate_witnesses = &witnesses[witness_start..];
        let mut passed_witness_ids = candidate_witnesses
            .iter()
            .filter(|witness| {
                matches!(
                    witness.outcome,
                    IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. }
                )
            })
            .map(|witness| witness.witness_id.clone())
            .collect::<Vec<_>>();
        passed_witness_ids.sort();
        let status = if !passed_witness_ids.is_empty() {
            IntentionalBoundaryBehaviorCandidateStatus::Passed {
                witness_ids: passed_witness_ids,
            }
        } else if candidate_witnesses.is_empty() {
            IntentionalBoundaryBehaviorCandidateStatus::NoResolvedBehaviorTest
        } else {
            IntentionalBoundaryBehaviorCandidateStatus::Unresolved
        };
        candidates.push(IntentionalBoundaryBehaviorCandidate {
            candidate_id,
            production_parser_unit_id: method.parser_unit_id.clone(),
            production_symbol_id: production_symbol_id.to_string(),
            status,
        });
    }
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    let census = finish_behavior_census(
        source_census,
        semantic_census,
        base_evidence,
        candidates,
        witnesses,
        executions,
    )?;
    validate_intentional_boundary_behavior_census_commitment(
        source_census,
        semantic_census,
        base_evidence,
        &census,
    )?;
    Ok(census)
}

fn selector_for(
    test_method: &IntentionalBoundarySemanticMethod,
) -> Result<
    IntentionalBoundaryBehaviorSelector,
    (IntentionalBoundaryBehaviorUnresolvedReason, String),
> {
    if test_method.symbol_name.trim().is_empty()
        || !is_safe_repository_path(&test_method.repository_path)
    {
        return Err((
            IntentionalBoundaryBehaviorUnresolvedReason::UnsupportedTargetSelector,
            "test method has no safe exact selector".to_string(),
        ));
    }
    Ok(match test_method.indexer {
        IntentionalBoundaryIndexerKind::Rust => IntentionalBoundaryBehaviorSelector::CargoTest {
            test_name: exact_rust_test_name(test_method)?,
        },
        IntentionalBoundaryIndexerKind::Python => IntentionalBoundaryBehaviorSelector::Pytest {
            repository_path: test_method.repository_path.clone(),
            test_name: exact_python_test_name(test_method)?,
        },
        IntentionalBoundaryIndexerKind::Go => IntentionalBoundaryBehaviorSelector::GoTest {
            package_repository_path: parent_repository_path(&test_method.repository_path),
            test_name: exact_go_test_name(test_method)?,
        },
        IntentionalBoundaryIndexerKind::TypeScriptJavaScript => {
            IntentionalBoundaryBehaviorSelector::JavaScriptTest {
                repository_path: test_method.repository_path.clone(),
                test_name: test_method.symbol_name.clone(),
            }
        }
        IntentionalBoundaryIndexerKind::Kotlin => IntentionalBoundaryBehaviorSelector::GradleTest {
            repository_path: test_method.repository_path.clone(),
            test_name: test_method.symbol_name.clone(),
        },
    })
}

fn exact_rust_test_name(
    method: &IntentionalBoundarySemanticMethod,
) -> Result<String, (IntentionalBoundaryBehaviorUnresolvedReason, String)> {
    let symbol_id = resolved_symbol_id(method).ok_or_else(unsupported_selector)?;
    rust_harness_name(symbol_id, &method.symbol_name).ok_or_else(unsupported_selector)
}

fn rust_harness_name(symbol_id: &str, leaf_name: &str) -> Option<String> {
    let mut fields = symbol_id.splitn(5, ' ');
    if fields.next()? != "rust-analyzer"
        || fields.next()? != "cargo"
        || fields.next()?.is_empty()
        || fields.next()?.is_empty()
    {
        return None;
    }
    let mut descriptors = fields.next()?;
    let mut components = Vec::new();
    while let Some((component, remaining)) = descriptors.split_once('/') {
        if !is_ascii_identifier(component) {
            return None;
        }
        components.push(component);
        descriptors = remaining;
    }
    let function = descriptors.strip_suffix("().")?;
    if function != leaf_name || !is_ascii_identifier(function) {
        return None;
    }
    components.push(function);
    Some(components.join("::"))
}

fn exact_python_test_name(
    method: &IntentionalBoundarySemanticMethod,
) -> Result<String, (IntentionalBoundaryBehaviorUnresolvedReason, String)> {
    let symbol = resolved_symbol(method).ok_or_else(unsupported_selector)?;
    if symbol.category != IntentionalBoundarySemanticSymbolCategory::Callable
        || !is_ascii_identifier(&method.symbol_name)
    {
        return Err(unsupported_selector());
    }
    Ok(method.symbol_name.clone())
}

fn exact_go_test_name(
    method: &IntentionalBoundarySemanticMethod,
) -> Result<String, (IntentionalBoundaryBehaviorUnresolvedReason, String)> {
    if !is_ascii_identifier(&method.symbol_name) {
        return Err(unsupported_selector());
    }
    Ok(method.symbol_name.clone())
}

fn unsupported_selector() -> (IntentionalBoundaryBehaviorUnresolvedReason, String) {
    (
        IntentionalBoundaryBehaviorUnresolvedReason::UnsupportedTargetSelector,
        "compiler identity cannot be converted to an exact test selector".to_string(),
    )
}

fn is_ascii_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn parent_repository_path(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(|| ".".to_string(), |(parent, _)| parent.to_string())
}

fn resolved_symbol_id(method: &IntentionalBoundarySemanticMethod) -> Option<&str> {
    resolved_symbol(method).map(|symbol| symbol.symbol_id.as_str())
}

fn resolved_symbol(
    method: &IntentionalBoundarySemanticMethod,
) -> Option<&super::IntentionalBoundarySemanticSymbolFacts> {
    match &method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => Some(symbol),
        _ => None,
    }
}

fn definition_locations(
    method: &IntentionalBoundarySemanticMethod,
) -> BTreeSet<super::IntentionalBoundarySemanticRange> {
    match &method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved {
            symbol,
            joined_definition,
        } => joined_definition
            .iter()
            .cloned()
            .chain(symbol.definitions.iter().cloned())
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn unresolved(
    reason: IntentionalBoundaryBehaviorUnresolvedReason,
    detail: String,
) -> IntentionalBoundaryBehaviorWitnessOutcome {
    IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
        reason,
        detail,
        execution_id: None,
    }
}

fn validate_behavior_base_evidence(
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    if base_evidence
        .input_census_sha256
        .contains_key("targeted_behavior_tests")
        || base_evidence
            .atoms
            .iter()
            .any(|atom| atom.evidence_kind == BoundaryEvidenceKind::PassingBehaviorTest)
    {
        return Err(
            "intentional-boundary behavior evidence cannot be used as its own base".to_string(),
        );
    }
    Ok(())
}

fn candidate_id(parser_unit_id: &str, production_symbol_id: &str) -> Result<String, String> {
    Ok(format!(
        "ibbc-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-behavior-candidate-v1",
            parser_unit_id,
            production_symbol_id,
        ))?
    ))
}

fn witness_id(
    candidate_id: &str,
    test_symbol_id: &str,
    relationship_kind: IntentionalBoundarySemanticTestKind,
    test_parser_unit_id: Option<&str>,
) -> Result<String, String> {
    Ok(format!(
        "ibbw-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-behavior-witness-v1",
            candidate_id,
            test_symbol_id,
            relationship_kind,
            test_parser_unit_id,
        ))?
    ))
}

pub(super) fn finish_behavior_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    mut candidates: Vec<IntentionalBoundaryBehaviorCandidate>,
    mut witnesses: Vec<IntentionalBoundaryBehaviorWitness>,
    mut executions: Vec<IntentionalBoundaryBehaviorExecution>,
) -> Result<IntentionalBoundaryBehaviorCensus, String> {
    candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    witnesses.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    executions.sort_by(|left, right| left.execution_id.cmp(&right.execution_id));
    if candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id >= pair[1].candidate_id)
        || witnesses
            .windows(2)
            .any(|pair| pair[0].witness_id >= pair[1].witness_id)
        || executions
            .windows(2)
            .any(|pair| pair[0].execution_id >= pair[1].execution_id)
    {
        return Err("intentional-boundary behavior census contains duplicate records".to_string());
    }
    let candidate_count_by_status = candidates.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<String, usize>, candidate| {
            let key = match candidate.status {
                IntentionalBoundaryBehaviorCandidateStatus::Passed { .. } => "passed",
                IntentionalBoundaryBehaviorCandidateStatus::NoResolvedBehaviorTest => {
                    "no_resolved_behavior_test"
                }
                IntentionalBoundaryBehaviorCandidateStatus::Unresolved => "unresolved",
            };
            *counts.entry(key.to_string()).or_default() += 1;
            counts
        },
    );
    let witness_count_by_status = witnesses.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<String, usize>, witness| {
            let key = match witness.outcome {
                IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. } => "passed",
                IntentionalBoundaryBehaviorWitnessOutcome::Unresolved { .. } => "unresolved",
            };
            *counts.entry(key.to_string()).or_default() += 1;
            counts
        },
    );
    let mut census = IntentionalBoundaryBehaviorCensus {
        schema_version: INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION,
        behavior_contract: BEHAVIOR_CONTRACT.to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        base_evidence_census_sha256: base_evidence.evidence_census_sha256.clone(),
        candidates,
        witnesses,
        executions,
        candidate_count_by_status,
        witness_count_by_status,
        behavior_census_sha256: String::new(),
    };
    census.behavior_census_sha256 = compute_behavior_census_sha256(&census)?;
    Ok(census)
}

pub(super) fn compute_behavior_census_sha256(
    census: &IntentionalBoundaryBehaviorCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.behavior_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.base_evidence_census_sha256,
        &census.candidates,
        &census.witnesses,
        &census.executions,
        &census.candidate_count_by_status,
        &census.witness_count_by_status,
    ))
}

pub(super) fn hash_json(value: &impl serde::Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to commit behavior-test evidence: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_behavior_tests.rs"]
mod tests;
