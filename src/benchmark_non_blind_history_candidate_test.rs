use super::non_blind_history_artifacts::RankArtifactWriter;
use super::{
    HistoricalAssessmentEvidence, HistoricalEvidenceKind, HistoricalRepositoryFacts,
    HistoricalTestExecution, HistoricalTestExecutionOutcome, HistoricalTestOutcome,
    HistoricalTestRecipeDiscovery, HistoricalTestRecipeStatus, ProvenanceArtifact,
};

pub(super) fn apply_test_execution(
    artifacts: &RankArtifactWriter,
    facts: &mut HistoricalRepositoryFacts,
    evidence: &mut Vec<HistoricalAssessmentEvidence>,
    observed_at: &str,
    side: &str,
    kind: HistoricalEvidenceKind,
    execution: HistoricalTestExecutionOutcome,
) -> Result<Option<ProvenanceArtifact>, String> {
    match execution {
        HistoricalTestExecutionOutcome::RuntimeUnavailable(reason) => {
            facts.test_outcome = Some(HistoricalTestOutcome::RuntimeUnavailable);
            record_unavailable(
                artifacts,
                evidence,
                observed_at,
                side,
                kind,
                "runtime_unavailable",
                &reason,
            )?;
            Ok(None)
        }
        HistoricalTestExecutionOutcome::SandboxUnavailable(reason) => {
            facts.test_outcome = Some(HistoricalTestOutcome::SandboxUnavailable);
            record_unavailable(
                artifacts,
                evidence,
                observed_at,
                side,
                kind,
                "sandbox_unavailable",
                &reason,
            )?;
            Ok(None)
        }
        HistoricalTestExecutionOutcome::Completed(execution) => {
            let artifact = artifacts.provenance_artifact(
                &format!("tests/{side}.json"),
                &execution.raw_result,
                format!("exact {side} preparation and test result"),
            )?;
            evidence.push(HistoricalAssessmentEvidence {
                kind,
                source: format!("hardened-sandbox:{side}"),
                observed_at: observed_at.to_string(),
                artifact_path: artifact.artifact_path.clone(),
                sha256: artifact.sha256.clone(),
            });
            let outcome = failed_test_outcome(&execution, side);
            if side == "parent" {
                facts.parent_test = Some(execution.result);
            } else {
                facts.commit_test = Some(execution.result);
            }
            facts.test_outcome = outcome;
            Ok(Some(artifact))
        }
    }
}

fn record_unavailable(
    artifacts: &RankArtifactWriter,
    evidence: &mut Vec<HistoricalAssessmentEvidence>,
    observed_at: &str,
    side: &str,
    kind: HistoricalEvidenceKind,
    outcome: &str,
    reason: &str,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "side": side,
        "outcome": outcome,
        "reason": reason,
    }))
    .map_err(|error| format!("failed to serialize historical availability evidence: {error}"))?;
    bytes.push(b'\n');
    let artifact = artifacts.provenance_artifact(
        &format!("tests/{side}-availability.json"),
        &bytes,
        format!("exact {side} historical test availability result"),
    )?;
    evidence.push(HistoricalAssessmentEvidence {
        kind,
        source: format!("hardened-sandbox:{side}:availability"),
        observed_at: observed_at.to_string(),
        artifact_path: artifact.artifact_path,
        sha256: artifact.sha256,
    });
    Ok(())
}

pub(super) fn apply_recipe(
    facts: &mut HistoricalRepositoryFacts,
    recipe: &HistoricalTestRecipeDiscovery,
) {
    facts.test_preparation = recipe.preparation_commands.clone();
    facts.test_recipe = recipe.command.clone();
    facts.test_outcome = match recipe.status {
        HistoricalTestRecipeStatus::Selected => None,
        HistoricalTestRecipeStatus::Unavailable => Some(HistoricalTestOutcome::RecipeUnavailable),
        HistoricalTestRecipeStatus::Ambiguous => Some(HistoricalTestOutcome::RecipeAmbiguous),
        HistoricalTestRecipeStatus::Changed => Some(HistoricalTestOutcome::RecipeChanged),
    };
}

fn failed_test_outcome(
    execution: &HistoricalTestExecution,
    side: &str,
) -> Option<HistoricalTestOutcome> {
    let result = &execution.result;
    if result.timed_out || result.preparation_results.iter().any(|step| step.timed_out) {
        return Some(HistoricalTestOutcome::TimedOut);
    }
    let preparation_failed = result
        .preparation_results
        .iter()
        .any(|step| step.status_code != Some(0));
    if preparation_failed || !result.test_executed || result.status_code != Some(0) {
        return Some(if side == "parent" {
            HistoricalTestOutcome::ParentFailed
        } else {
            HistoricalTestOutcome::CommitFailed
        });
    }
    None
}
