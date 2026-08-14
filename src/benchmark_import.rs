use crate::benchmark::{
    BenchmarkCorpus, BenchmarkRun, BenchmarkRunPrediction, BenchmarkUsage, BlindReviewer,
    ReviewerDisposition, validate_actual_cost_receipt, validate_frozen_corpus,
};
use crate::product_contract::SlopPattern;
use crate::types::FindingTier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[path = "benchmark_import_prepare.rs"]
mod prepare;
#[path = "benchmark_import_schema.rs"]
mod schema;

use prepare::{normalize_artifact_paths, prepare_artifacts};
pub use schema::BenchmarkRunReview;
use schema::{
    BENCHMARK_REVIEW_SCHEMA_VERSION, BlindBenchmarkCase, BlindCaseSource, OutcomeReview,
    PreparedOutcome,
};

pub fn prepare_run_review(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
    artifact_paths: &[PathBuf],
) -> Result<BenchmarkRunReview, String> {
    validate_frozen_corpus(corpus, corpus_root)?;
    if artifact_paths.is_empty() {
        return Err(
            "benchmark preparation requires at least one completed-run artifact".to_string(),
        );
    }
    let stored_artifact_paths = normalize_artifact_paths(corpus_root, artifact_paths)?;
    let resolved_artifact_paths = stored_artifact_paths
        .iter()
        .map(|path| corpus_root.join(path))
        .collect::<Vec<_>>();
    let (prepared, outcomes) = prepare_artifacts(corpus, corpus_root, &resolved_artifact_paths)?;
    let blind_cases = corpus
        .cases
        .iter()
        .map(|case| BlindBenchmarkCase {
            case_id: blind_case_id(corpus, &case.label.case_id),
            language: case.label.language.clone(),
            sources: case
                .before
                .iter()
                .map(|source| BlindCaseSource {
                    repository: source.repository.clone(),
                    revision: source.revision.clone(),
                    repository_path: source.repository_path.clone(),
                    artifact_path: source.artifact_path.clone(),
                    sha256: source.sha256.clone(),
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    if blind_cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<HashSet<_>>()
        .len()
        != blind_cases.len()
    {
        return Err("benchmark blind case identities collide".to_string());
    }
    let reviews = outcomes
        .iter()
        .map(|outcome| OutcomeReview {
            outcome_id: outcome.outcome_id.clone(),
            matched_case_id: None,
            reviewer_disposition: ReviewerDisposition::Unreviewed,
            reviewer_minutes: 0.0,
        })
        .collect();
    Ok(BenchmarkRunReview {
        schema_version: BENCHMARK_REVIEW_SCHEMA_VERSION,
        corpus_id: corpus.corpus_id.clone(),
        source_commitment_sha256: corpus.source_commitment_sha256.clone(),
        label_commitment_sha256: corpus.label_commitment_sha256.clone(),
        completed_artifact_paths: stored_artifact_paths,
        prepared,
        blind_cases,
        outcomes,
        reviews,
        actual_cost_microusd: None,
        actual_cost_provenance: String::new(),
        actual_cost_artifact_path: String::new(),
        actual_cost_artifact_sha256: String::new(),
        blind_reviewer: None,
        wall_clock_seconds: None,
    })
}

pub fn import_reviewed_run(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
    review: &BenchmarkRunReview,
) -> Result<BenchmarkRun, String> {
    if review.schema_version != BENCHMARK_REVIEW_SCHEMA_VERSION {
        return Err(format!(
            "benchmark review schema_version must be {BENCHMARK_REVIEW_SCHEMA_VERSION}"
        ));
    }
    let artifact_paths = review
        .completed_artifact_paths
        .iter()
        .map(|path| corpus_root.join(path))
        .collect::<Vec<_>>();
    let expected = prepare_run_review(corpus, corpus_root, &artifact_paths)?;
    if review.corpus_id != expected.corpus_id
        || review.source_commitment_sha256 != expected.source_commitment_sha256
        || review.label_commitment_sha256 != expected.label_commitment_sha256
        || review.prepared != expected.prepared
        || review.blind_cases != expected.blind_cases
        || review.outcomes != expected.outcomes
    {
        return Err(
            "benchmark review changed source-bound preparation fields; regenerate it from the completed artifacts"
                .to_string(),
        );
    }
    let blind_reviewer = review
        .blind_reviewer
        .as_ref()
        .ok_or_else(|| "benchmark review is missing blind reviewer provenance".to_string())?;
    validate_blind_reviewer(blind_reviewer)?;
    validate_reviewer_separation(corpus, blind_reviewer)?;
    let actual_cost_microusd = review
        .actual_cost_microusd
        .ok_or_else(|| "benchmark review is missing actual_cost_microusd".to_string())?;
    if review.actual_cost_provenance.trim().is_empty() {
        return Err("benchmark review is missing actual_cost_provenance".to_string());
    }
    validate_actual_cost_receipt(
        corpus_root,
        &review.actual_cost_artifact_path,
        &review.actual_cost_artifact_sha256,
        &review.prepared.provider,
        &review.prepared.model,
        actual_cost_microusd,
        review.actual_cost_provenance.trim(),
    )?;
    let wall_clock_seconds = review
        .wall_clock_seconds
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| "benchmark review requires positive wall_clock_seconds".to_string())?;
    let decisions = validate_reviews(&review.outcomes, &review.reviews, &review.blind_cases)?;
    let predictions = build_predictions(corpus, &review.outcomes, &decisions, &review.blind_cases)?;
    let run_id = sha256_json(&(
        &review.prepared.completed_artifact_ids,
        &review.prepared.execution_commitments_sha256,
    ))?;
    Ok(BenchmarkRun {
        run_id,
        tool_version: review.prepared.tool_version.clone(),
        source_revision: review.prepared.source_revision.clone(),
        provider: review.prepared.provider.clone(),
        model: review.prepared.model.clone(),
        prompt_contract_version: review.prepared.prompt_contract_version.clone(),
        source_commitment_sha256: review.source_commitment_sha256.clone(),
        label_commitment_sha256: review.label_commitment_sha256.clone(),
        completed_artifact_ids: review.prepared.completed_artifact_ids.clone(),
        execution_commitments_sha256: review.prepared.execution_commitments_sha256.clone(),
        cross_scan_reused_units: review.prepared.cross_scan_reused_units,
        analyzed_method_count: review.prepared.analyzed_method_count,
        covered_case_ids: corpus
            .cases
            .iter()
            .map(|case| case.label.case_id.clone())
            .collect(),
        predictions,
        usage: BenchmarkUsage {
            input_tokens: review.prepared.input_tokens,
            cached_input_tokens: review.prepared.cached_input_tokens,
            output_tokens: review.prepared.output_tokens,
            actual_cost_microusd,
        },
        actual_cost_provenance: review.actual_cost_provenance.trim().to_string(),
        actual_cost_artifact_path: review.actual_cost_artifact_path.clone(),
        actual_cost_artifact_sha256: review.actual_cost_artifact_sha256.clone(),
        blind_reviewer: blind_reviewer.clone(),
        wall_clock_seconds,
    })
}

fn blind_case_id(corpus: &BenchmarkCorpus, case_id: &str) -> String {
    let identity = format!(
        "sniffbench-blind-case-v1\n{}\n{}\n{}",
        corpus.corpus_id, corpus.label_commitment_sha256, case_id
    );
    format!("case-{:x}", Sha256::digest(identity.as_bytes()))
}

fn validate_blind_reviewer(reviewer: &BlindReviewer) -> Result<(), String> {
    if reviewer.reviewer_id.trim().is_empty()
        || reviewer.affiliation.trim().is_empty()
        || reviewer.attestation.trim().len() < 20
        || reviewer.years_experience < 3
    {
        return Err(
            "blind reviewer provenance requires identity, affiliation, at least three years of experience, and a substantive attestation"
                .to_string(),
        );
    }
    if !reviewer.independent_from_sniff || !reviewer.labels_hidden_during_review {
        return Err(
            "benchmark reviewer must attest independence from Sniff and no access to hidden labels during review"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_reviewer_separation(
    corpus: &BenchmarkCorpus,
    reviewer: &BlindReviewer,
) -> Result<(), String> {
    let reviewer_id = reviewer.reviewer_id.trim();
    if corpus.cases.iter().any(|case| {
        case.adjudications
            .iter()
            .any(|adjudication| adjudication.reviewer_id.trim() == reviewer_id)
    }) {
        return Err(format!(
            "blind reviewer {reviewer_id} also adjudicated a frozen corpus label"
        ));
    }
    Ok(())
}

fn validate_reviews<'a>(
    outcomes: &'a [PreparedOutcome],
    reviews: &'a [OutcomeReview],
    cases: &[BlindBenchmarkCase],
) -> Result<HashMap<&'a str, &'a OutcomeReview>, String> {
    let outcome_ids = outcomes
        .iter()
        .map(|outcome| outcome.outcome_id.as_str())
        .collect::<HashSet<_>>();
    let case_ids = cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<HashSet<_>>();
    let mut result = HashMap::new();
    let mut matched = HashSet::new();
    for review in reviews {
        if !outcome_ids.contains(review.outcome_id.as_str()) {
            return Err(format!(
                "review references unknown outcome {}",
                review.outcome_id
            ));
        }
        if result.insert(review.outcome_id.as_str(), review).is_some() {
            return Err(format!("review repeats outcome {}", review.outcome_id));
        }
        if !review.reviewer_minutes.is_finite() || review.reviewer_minutes < 0.0 {
            return Err(format!(
                "review {} has invalid reviewer time",
                review.outcome_id
            ));
        }
        if let Some(case_id) = review.matched_case_id.as_deref() {
            if !case_ids.contains(case_id) {
                return Err(format!("review matches unknown case {case_id}"));
            }
            if !matched.insert(case_id) {
                return Err(format!("review matches case {case_id} more than once"));
            }
        }
    }
    if result.len() != outcomes.len() {
        return Err("benchmark review does not cover every prepared outcome".to_string());
    }
    for outcome in outcomes {
        let review = result[outcome.outcome_id.as_str()];
        let finding = matches!(outcome.tier, FindingTier::Slop | FindingTier::KindaSlop);
        if finding
            && (review.reviewer_disposition == ReviewerDisposition::Unreviewed
                || review.reviewer_minutes <= 0.0)
        {
            return Err(format!(
                "finding {} requires an accepted/rejected blind review with positive reviewer time",
                outcome.outcome_id
            ));
        }
        if !finding && review.reviewer_disposition != ReviewerDisposition::Unreviewed {
            return Err(format!(
                "non-finding {} cannot carry an accepted/rejected disposition",
                outcome.outcome_id
            ));
        }
        if review.matched_case_id.is_some()
            && review.reviewer_disposition != ReviewerDisposition::Accepted
            && finding
        {
            return Err(format!(
                "finding {} can match a corpus case only when the blind reviewer accepts it",
                outcome.outcome_id
            ));
        }
        if review.reviewer_disposition == ReviewerDisposition::Rejected
            && review.matched_case_id.is_some()
        {
            return Err(format!(
                "rejected finding {} cannot match a corpus case",
                outcome.outcome_id
            ));
        }
    }
    Ok(result)
}

fn build_predictions(
    corpus: &BenchmarkCorpus,
    outcomes: &[PreparedOutcome],
    reviews: &HashMap<&str, &OutcomeReview>,
    cases: &[BlindBenchmarkCase],
) -> Result<Vec<BenchmarkRunPrediction>, String> {
    let case_ids = corpus
        .cases
        .iter()
        .map(|case| {
            (
                blind_case_id(corpus, &case.label.case_id),
                case.label.case_id.as_str(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut predictions = Vec::new();
    let mut matched = HashSet::new();
    for outcome in outcomes {
        let review = reviews[outcome.outcome_id.as_str()];
        if let Some(case_id) = review.matched_case_id.as_deref() {
            matched.insert(case_id);
        }
        if review.matched_case_id.is_none() && outcome.tier == FindingTier::Clean {
            continue;
        }
        predictions.push(BenchmarkRunPrediction {
            prediction_id: outcome.outcome_id.clone(),
            finding_fingerprint: outcome.finding_fingerprint.clone(),
            matched_case_id: review
                .matched_case_id
                .as_deref()
                .and_then(|case_id| case_ids.get(case_id).copied())
                .map(str::to_string),
            tier: outcome.tier,
            pattern: outcome.pattern.clone(),
            evidence: if matches!(outcome.tier, FindingTier::Slop | FindingTier::KindaSlop) {
                outcome.evidence.clone()
            } else {
                Vec::new()
            },
            proof_level: outcome.proof_level,
            reviewer_disposition: review.reviewer_disposition,
            reviewer_minutes: review.reviewer_minutes,
        });
    }
    for case in cases
        .iter()
        .filter(|case| !matched.contains(case.case_id.as_str()))
    {
        predictions.push(BenchmarkRunPrediction {
            prediction_id: format!("clean:{}", case.case_id),
            finding_fingerprint: None,
            matched_case_id: Some(
                case_ids
                    .get(&case.case_id)
                    .copied()
                    .ok_or_else(|| format!("unknown opaque benchmark case {}", case.case_id))?
                    .to_string(),
            ),
            tier: FindingTier::Clean,
            pattern: SlopPattern::None.as_str().to_string(),
            evidence: Vec::new(),
            proof_level: 0,
            reviewer_disposition: ReviewerDisposition::Unreviewed,
            reviewer_minutes: 0.0,
        });
    }
    predictions.sort_by(|left, right| left.prediction_id.cmp(&right.prediction_id));
    Ok(predictions)
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize benchmark identity: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
#[path = "tests/benchmark_import.rs"]
mod tests;
