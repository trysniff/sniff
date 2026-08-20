use super::*;
use crate::types::FindingTier;
use std::collections::HashMap;

pub(super) fn corpus_adjudications(
    reviewed: &HistoricalV2ReviewedSlotArtifacts<'_>,
) -> Result<Vec<BenchmarkAdjudication>, String> {
    let reviewers = reviewed
        .audit
        .reviewers
        .iter()
        .map(|reviewer| (reviewer.reviewer_id.as_str(), reviewer))
        .collect::<HashMap<_, _>>();
    let mut adjudications = reviewed
        .audit
        .labels
        .iter()
        .map(|label| {
            let reviewer = reviewers
                .get(label.reviewer_id.as_str())
                .ok_or_else(|| "historical-v2 corpus label lost its reviewer".to_string())?;
            decision_adjudication(
                &label.reviewer_id,
                reviewer.years_experience,
                &label.decision,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    if reviewed.audit.status == HistoricalV2LabelStatus::Disputed {
        let resolver = reviewed
            .resolution
            .resolver
            .as_ref()
            .ok_or_else(|| "historical-v2 corpus dispute lost its resolver".to_string())?;
        let decision = reviewed.resolution.item.decision.as_ref().ok_or_else(|| {
            "historical-v2 corpus dispute lost its resolution decision".to_string()
        })?;
        adjudications.push(decision_adjudication(
            &resolver.resolver_id,
            resolver.years_experience,
            decision,
        )?);
    }
    adjudications.sort_by(|left, right| left.reviewer_id.cmp(&right.reviewer_id));
    Ok(adjudications)
}

fn decision_adjudication(
    reviewer_id: &str,
    years_experience: u16,
    decision: &HistoricalV2ReviewDecision,
) -> Result<BenchmarkAdjudication, String> {
    let verdict = decision
        .verdict
        .ok_or_else(|| "historical-v2 corpus adjudication has no verdict".to_string())?;
    let pattern = decision
        .pattern
        .ok_or_else(|| "historical-v2 corpus adjudication has no pattern".to_string())?;
    Ok(BenchmarkAdjudication {
        reviewer_id: reviewer_id.to_string(),
        years_experience,
        tier: if verdict == HistoricalV2ReviewerVerdict::Accept {
            FindingTier::Slop
        } else {
            FindingTier::Clean
        },
        pattern: pattern.as_str().to_string(),
        rationale: decision.rationale.clone(),
        maintainer: false,
    })
}

pub(super) fn final_review_decision<'a>(
    reviewed: &'a HistoricalV2ReviewedSlotArtifacts<'_>,
) -> Result<&'a HistoricalV2ReviewDecision, String> {
    match &reviewed.final_label.outcome {
        HistoricalV2FinalLabelOutcome::Accepted {
            basis: HistoricalV2FinalLabelBasis::ReviewerConsensus,
            ..
        } => reviewed
            .audit
            .labels
            .first()
            .map(|label| &label.decision)
            .ok_or_else(|| "historical-v2 consensus case lost its decision".to_string()),
        HistoricalV2FinalLabelOutcome::Accepted {
            basis: HistoricalV2FinalLabelBasis::DisputeResolution,
            ..
        } => reviewed
            .resolution
            .item
            .decision
            .as_ref()
            .ok_or_else(|| "historical-v2 resolved case lost its final decision".to_string()),
        _ => Err("historical-v2 corpus case is not an accepted final label".into()),
    }
}
