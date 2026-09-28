use super::super::{HistoricalV3ReviewContextSource, HistoricalV3SourceSide};
use super::{
    HistoricalV3LabelTask, HistoricalV3LabelWorksheet, HistoricalV3ReviewDecision,
    HistoricalV3Reviewer, HistoricalV3ReviewerVerdict, HistoricalV3SourceCitation,
};
use crate::product_contract::SlopPattern;
use std::collections::BTreeSet;

pub(super) fn validate_completed_worksheet(
    worksheet: &HistoricalV3LabelWorksheet,
    expected: &HistoricalV3LabelWorksheet,
) -> Result<(), String> {
    if worksheet.schema_version != expected.schema_version
        || worksheet.protocol_sha256 != expected.protocol_sha256
        || worksheet.source_bundle_sha256 != expected.source_bundle_sha256
        || worksheet.task_sha256 != expected.task_sha256
        || !immutable_task_matches(&worksheet.task, &expected.task)
    {
        return Err("historical-v3 label worksheet changed its immutable source task".to_string());
    }
    let reviewer = worksheet
        .reviewer
        .as_ref()
        .ok_or_else(|| "historical-v3 label worksheet has no reviewer".to_string())?;
    validate_reviewer(reviewer, &worksheet.task.decision)?;
    if !worksheet.task.context.resolved_context_complete
        && worksheet.task.decision.verdict != Some(HistoricalV3ReviewerVerdict::InsufficientContext)
    {
        return Err(
            "historical-v3 human review cannot conclude with missing caller or contract context"
                .to_string(),
        );
    }
    validate_decision(&worksheet.task, &worksheet.task.decision)
}

fn immutable_task_matches(left: &HistoricalV3LabelTask, right: &HistoricalV3LabelTask) -> bool {
    left.review_item_id == right.review_item_id
        && left.language == right.language
        && left.public_surface_preserved == right.public_surface_preserved
        && left.public_surface_delta_sha256 == right.public_surface_delta_sha256
        && left.simplifications == right.simplifications
        && left.methods == right.methods
        && left.context == right.context
        && left.behavior == right.behavior
}

fn validate_reviewer(
    reviewer: &HistoricalV3Reviewer,
    decision: &HistoricalV3ReviewDecision,
) -> Result<(), String> {
    require_text("historical-v3 reviewer ID", &reviewer.reviewer_id)?;
    require_text("historical-v3 reviewer affiliation", &reviewer.affiliation)?;
    require_text("historical-v3 reviewer attestation", &reviewer.attestation)?;
    if reviewer.years_experience == 0
        || !reviewer.independent_from_sniff
        || !reviewer.sniff_output_hidden
        || !reviewer.change_metadata_hidden
        || !reviewer.other_reviewer_labels_hidden
        || reviewer.model_assistance_used
    {
        return Err(
            "historical-v3 reviewer must be experienced, independent, human-only, and blind to identity, metadata, Sniff, and other labels"
                .to_string(),
        );
    }
    if !reviewer.repository_identity_hidden
        && decision.verdict != Some(HistoricalV3ReviewerVerdict::InsufficientContext)
    {
        return Err(
            "historical-v3 human review cannot conclude after source revealed repository identity"
                .to_string(),
        );
    }
    if decision.verdict != Some(HistoricalV3ReviewerVerdict::InsufficientContext)
        && (!reviewer.complete_source_context_inspected || !reviewer.behavior_evidence_inspected)
    {
        return Err("historical-v3 human review claims a conclusive verdict without inspecting source and behavior".to_string());
    }
    if (!reviewer.complete_source_context_inspected
        && (decision.before_contains_unnecessary_machinery.is_some()
            || decision.after_removes_that_machinery.is_some()
            || decision.removal_not_relocated.is_some()
            || decision.simpler_counterfactual_matches.is_some()
            || decision.public_surface_preserved.is_some()))
        || (!reviewer.behavior_evidence_inspected && decision.behavior_preserved.is_some())
    {
        return Err("historical-v3 human review claims evidence it did not inspect".to_string());
    }
    Ok(())
}

pub(super) fn validate_decision(
    task: &HistoricalV3LabelTask,
    decision: &HistoricalV3ReviewDecision,
) -> Result<(), String> {
    let verdict = decision
        .verdict
        .ok_or_else(|| "historical-v3 review has no verdict".to_string())?;
    let pattern = decision
        .pattern
        .ok_or_else(|| "historical-v3 review has no typed pattern".to_string())?;
    require_text("historical-v3 review mechanism", &decision.mechanism)?;
    require_text("historical-v3 review rationale", &decision.rationale)?;
    validate_other_pattern(pattern, &decision.other_pattern)?;
    validate_missing_evidence(&decision.missing_evidence)?;
    validate_citations(task, &decision.citations)?;

    match verdict {
        HistoricalV3ReviewerVerdict::Slop => validate_slop_decision(pattern, decision),
        HistoricalV3ReviewerVerdict::Clean => validate_clean_decision(pattern, decision),
        HistoricalV3ReviewerVerdict::IntentionalBoundary => {
            validate_boundary_decision(pattern, decision)
        }
        HistoricalV3ReviewerVerdict::Ambiguous => {
            validate_uncertain_decision(pattern, decision, false)
        }
        HistoricalV3ReviewerVerdict::InsufficientContext => {
            validate_uncertain_decision(pattern, decision, true)
        }
    }
}

fn validate_slop_decision(
    pattern: SlopPattern,
    decision: &HistoricalV3ReviewDecision,
) -> Result<(), String> {
    require_text(
        "historical-v3 simpler counterfactual",
        &decision.simpler_counterfactual,
    )?;
    let criteria = [
        decision.before_contains_unnecessary_machinery,
        decision.after_removes_that_machinery,
        decision.removal_not_relocated,
        decision.simpler_counterfactual_matches,
        decision.public_surface_preserved,
        decision.behavior_preserved,
    ];
    if pattern == SlopPattern::None
        || criteria.into_iter().any(|value| value != Some(true))
        || !decision.boundary_justification.trim().is_empty()
        || !decision.missing_evidence.is_empty()
    {
        return Err(
            "historical-v3 slop verdict requires a pattern and every evidence criterion"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_clean_decision(
    pattern: SlopPattern,
    decision: &HistoricalV3ReviewDecision,
) -> Result<(), String> {
    if pattern != SlopPattern::None
        || decision.before_contains_unnecessary_machinery != Some(false)
        || decision.after_removes_that_machinery.is_some()
        || decision.removal_not_relocated.is_some()
        || decision.simpler_counterfactual_matches.is_some()
        || decision.public_surface_preserved != Some(true)
        || decision.behavior_preserved != Some(true)
        || !decision.simpler_counterfactual.trim().is_empty()
        || !decision.boundary_justification.trim().is_empty()
        || !decision.missing_evidence.is_empty()
    {
        return Err("historical-v3 clean verdict contradicts its evidence".to_string());
    }
    Ok(())
}

fn validate_boundary_decision(
    pattern: SlopPattern,
    decision: &HistoricalV3ReviewDecision,
) -> Result<(), String> {
    require_text(
        "historical-v3 boundary justification",
        &decision.boundary_justification,
    )?;
    if pattern != SlopPattern::None
        || decision.before_contains_unnecessary_machinery != Some(false)
        || decision.after_removes_that_machinery.is_some()
        || decision.removal_not_relocated.is_some()
        || decision.simpler_counterfactual_matches.is_some()
        || decision.public_surface_preserved != Some(true)
        || decision.behavior_preserved != Some(true)
        || !decision.simpler_counterfactual.trim().is_empty()
        || !decision.missing_evidence.is_empty()
    {
        return Err(
            "historical-v3 intentional-boundary verdict contradicts its evidence".to_string(),
        );
    }
    Ok(())
}

fn validate_uncertain_decision(
    pattern: SlopPattern,
    decision: &HistoricalV3ReviewDecision,
    require_missing_criterion: bool,
) -> Result<(), String> {
    let criteria = [
        decision.before_contains_unnecessary_machinery,
        decision.after_removes_that_machinery,
        decision.removal_not_relocated,
        decision.simpler_counterfactual_matches,
        decision.public_surface_preserved,
        decision.behavior_preserved,
    ];
    if pattern != SlopPattern::None
        || decision.missing_evidence.is_empty()
        || (require_missing_criterion && criteria.into_iter().all(|value| value.is_some()))
    {
        return Err("historical-v3 uncertain verdict contradicts its evidence".to_string());
    }
    Ok(())
}

fn validate_other_pattern(pattern: SlopPattern, other: &str) -> Result<(), String> {
    match pattern {
        SlopPattern::Other => require_text("historical-v3 other pattern", other),
        _ if other.trim().is_empty() => Ok(()),
        _ => Err("historical-v3 known pattern cannot carry another pattern".to_string()),
    }
}

fn validate_missing_evidence(values: &[String]) -> Result<(), String> {
    if values.iter().any(|value| value.trim().is_empty())
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(
            "historical-v3 missing-evidence entries must be non-empty, unique, and ordered"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_citations(
    task: &HistoricalV3LabelTask,
    citations: &[HistoricalV3SourceCitation],
) -> Result<(), String> {
    if citations.is_empty() || citations.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("historical-v3 review requires ordered unique citations".to_string());
    }
    let changed_sides = citations
        .iter()
        .filter(|citation| {
            task.methods.iter().any(|method| {
                method.side == citation.side
                    && method.repository_path == citation.repository_path
                    && method.parser_unit_id == citation.parser_unit_id
            })
        })
        .map(|citation| citation.side)
        .collect::<BTreeSet<_>>();
    if !changed_sides.contains(&HistoricalV3SourceSide::Base)
        || (task
            .methods
            .iter()
            .any(|method| method.side == HistoricalV3SourceSide::Merge)
            && !changed_sides.contains(&HistoricalV3SourceSide::Merge))
    {
        return Err(
            "historical-v3 review citations do not cover the available before/after source"
                .to_string(),
        );
    }
    for citation in citations {
        validate_citation(task, citation)?;
    }
    Ok(())
}

pub(super) fn validate_citation(
    task: &HistoricalV3LabelTask,
    citation: &HistoricalV3SourceCitation,
) -> Result<(), String> {
    let method = task
        .methods
        .iter()
        .chain(
            task.context
                .sources
                .iter()
                .filter_map(|source| match source {
                    HistoricalV3ReviewContextSource::Method { method } => Some(method.as_ref()),
                    HistoricalV3ReviewContextSource::File { .. } => None,
                }),
        )
        .find(|method| {
            method.side == citation.side
                && method.repository_path == citation.repository_path
                && method.parser_unit_id == citation.parser_unit_id
        });
    let (start_line, end_line, source, source_start_line) = if let Some(method) = method {
        (
            method.start_line,
            method.end_line,
            method.source.as_str(),
            method.start_line,
        )
    } else {
        task.context
            .items
            .iter()
            .find_map(|item| {
                if item.target_symbol_id != citation.parser_unit_id || item.definition.is_none() {
                    return None;
                }
                match task.context.sources.get(item.source_index)? {
                    HistoricalV3ReviewContextSource::File {
                        side,
                        repository_path,
                        source,
                        ..
                    } if *side == citation.side && repository_path == &citation.repository_path => {
                        Some((1, source.lines().count(), source.as_str(), 1))
                    }
                    _ => None,
                }
            })
            .ok_or_else(|| "historical-v3 citation invents a review source".to_string())?
    };
    if citation.start_line < start_line
        || citation.end_line < citation.start_line
        || citation.end_line > end_line
    {
        return Err("historical-v3 citation range escapes its source".to_string());
    }
    let lines = source
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    let start = citation.start_line - source_start_line;
    let end = citation.end_line - source_start_line + 1;
    if end > lines.len() {
        return Err("historical-v3 citation exceeds its source".to_string());
    }
    let exact = lines[start..end].join("\n");
    if citation.quote != exact || citation.quote.trim().is_empty() {
        return Err("historical-v3 citation is not exact source".to_string());
    }
    Ok(())
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
