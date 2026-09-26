use super::{BenchmarkSourceSeal, LabelReviewWorksheet, prepare_label_review};
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const MODEL_JUDGED_REVIEW_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelJudgedReviewer {
    pub reviewer_id: String,
    pub provider: String,
    pub model: String,
    pub model_version: String,
    pub run_id: String,
    pub prompt_sha256: String,
    pub fresh_context: bool,
    pub sniff_output_hidden: bool,
    pub other_reviews_hidden: bool,
    pub source_context_inspected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelJudgedDecision {
    pub method_id: String,
    pub tier: FindingTier,
    pub mechanism: String,
    pub evidence_artifact_path: String,
    pub exact_source_quote: String,
    pub rationale: String,
    pub missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelJudgedSubmission {
    pub schema_version: u32,
    pub source_seal_artifact_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub task_commitment_sha256: String,
    pub reviewer: ModelJudgedReviewer,
    pub decisions: Vec<ModelJudgedDecision>,
    pub submission_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelJudgedRawReview {
    pub reviewer: ModelJudgedReviewer,
    pub decisions: Vec<ModelJudgedDecision>,
}

impl ModelJudgedSubmission {
    pub fn computed_sha256(&self) -> Result<String, String> {
        hash_json(&(
            self.schema_version,
            &self.source_seal_artifact_sha256,
            &self.source_seal_commitment_sha256,
            &self.task_commitment_sha256,
            &self.reviewer,
            &self.decisions,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelJudgedMethodAgreement {
    pub method_id: String,
    pub first_tier: FindingTier,
    pub second_tier: FindingTier,
    pub agreed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelJudgedAudit {
    pub schema_version: u32,
    pub source_seal_commitment_sha256: String,
    pub submission_sha256s: [String; 2],
    pub methods: Vec<ModelJudgedMethodAgreement>,
    pub agreement_count: usize,
    pub disputed_count: usize,
    pub audit_sha256: String,
}

impl ModelJudgedAudit {
    pub fn computed_sha256(&self) -> Result<String, String> {
        hash_json(&(
            self.schema_version,
            &self.source_seal_commitment_sha256,
            &self.submission_sha256s,
            &self.methods,
            self.agreement_count,
            self.disputed_count,
        ))
    }
}

pub fn validate_model_judged_submission(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    submission: &ModelJudgedSubmission,
) -> Result<(), String> {
    let expected = prepare_label_review(seal, seal_root, source_seal_artifact_sha256)?;
    validate_submission_against_task(&expected, submission)
}

pub fn seal_model_judged_review(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    raw: ModelJudgedRawReview,
) -> Result<ModelJudgedSubmission, String> {
    let expected = prepare_label_review(seal, seal_root, source_seal_artifact_sha256)?;
    let mut submission = ModelJudgedSubmission {
        schema_version: MODEL_JUDGED_REVIEW_SCHEMA_VERSION,
        source_seal_artifact_sha256: expected.source_seal_artifact_sha256.clone(),
        source_seal_commitment_sha256: expected.source_seal_commitment_sha256.clone(),
        task_commitment_sha256: expected.task_commitment_sha256.clone(),
        reviewer: raw.reviewer,
        decisions: raw.decisions,
        submission_sha256: String::new(),
    };
    submission.submission_sha256 = submission.computed_sha256()?;
    validate_submission_against_task(&expected, &submission)?;
    Ok(submission)
}

pub fn audit_model_judged_reviews(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    first: &ModelJudgedSubmission,
    second: &ModelJudgedSubmission,
) -> Result<ModelJudgedAudit, String> {
    let expected = prepare_label_review(seal, seal_root, source_seal_artifact_sha256)?;
    validate_submission_against_task(&expected, first)?;
    validate_submission_against_task(&expected, second)?;
    if first
        .reviewer
        .reviewer_id
        .trim()
        .eq_ignore_ascii_case(second.reviewer.reviewer_id.trim())
        || first.reviewer.run_id == second.reviewer.run_id
    {
        return Err("model-judged audit requires two distinct agent runs".to_string());
    }
    let second_by_id = second
        .decisions
        .iter()
        .map(|decision| (decision.method_id.as_str(), decision))
        .collect::<HashMap<_, _>>();
    if first.decisions.len() != second.decisions.len()
        || first
            .decisions
            .iter()
            .any(|decision| !second_by_id.contains_key(decision.method_id.as_str()))
    {
        return Err("model-judged reviews cover different method sets".to_string());
    }
    let methods = first
        .decisions
        .iter()
        .map(|decision| {
            let other = second_by_id[decision.method_id.as_str()];
            ModelJudgedMethodAgreement {
                method_id: decision.method_id.clone(),
                first_tier: decision.tier,
                second_tier: other.tier,
                agreed: decision.tier == other.tier,
            }
        })
        .collect::<Vec<_>>();
    let agreement_count = methods.iter().filter(|method| method.agreed).count();
    let mut audit = ModelJudgedAudit {
        schema_version: MODEL_JUDGED_REVIEW_SCHEMA_VERSION,
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        submission_sha256s: [
            first.submission_sha256.clone(),
            second.submission_sha256.clone(),
        ],
        disputed_count: methods.len() - agreement_count,
        agreement_count,
        methods,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit.computed_sha256()?;
    Ok(audit)
}

pub fn validate_model_judged_audit(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    first: &ModelJudgedSubmission,
    second: &ModelJudgedSubmission,
    audit: &ModelJudgedAudit,
) -> Result<(), String> {
    let expected =
        audit_model_judged_reviews(seal, seal_root, source_seal_artifact_sha256, first, second)?;
    if audit != &expected {
        return Err("model-judged audit does not replay from its submissions".to_string());
    }
    Ok(())
}

fn validate_submission_against_task(
    expected: &LabelReviewWorksheet,
    submission: &ModelJudgedSubmission,
) -> Result<(), String> {
    if submission.schema_version != MODEL_JUDGED_REVIEW_SCHEMA_VERSION
        || submission.source_seal_artifact_sha256 != expected.source_seal_artifact_sha256
        || submission.source_seal_commitment_sha256 != expected.source_seal_commitment_sha256
        || submission.task_commitment_sha256 != expected.task_commitment_sha256
    {
        return Err("model-judged submission is detached from its sealed source task".to_string());
    }
    let reviewer = &submission.reviewer;
    for value in [
        &reviewer.reviewer_id,
        &reviewer.provider,
        &reviewer.model,
        &reviewer.model_version,
        &reviewer.run_id,
    ] {
        if value.trim().is_empty() {
            return Err("model-judged reviewer provenance is incomplete".to_string());
        }
    }
    require_sha256(&reviewer.prompt_sha256)?;
    if !reviewer.fresh_context
        || !reviewer.sniff_output_hidden
        || !reviewer.other_reviews_hidden
        || !reviewer.source_context_inspected
    {
        return Err("model-judged reviewer did not attest source-only isolation".to_string());
    }
    if submission.decisions.is_empty() {
        return Err("model-judged submission has no decisions".to_string());
    }
    let by_id = expected
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let mut seen = HashSet::new();
    for decision in &submission.decisions {
        if !seen.insert(decision.method_id.as_str()) {
            return Err("model-judged submission repeats a method".to_string());
        }
        let method = by_id
            .get(decision.method_id.as_str())
            .ok_or_else(|| "model-judged submission invents a method".to_string())?;
        if decision.mechanism.trim().is_empty() || decision.rationale.trim().is_empty() {
            return Err("model-judged decision lacks a mechanism or rationale".to_string());
        }
        if decision.tier == FindingTier::Unresolved && decision.missing_evidence.is_empty() {
            return Err("unresolved model judgment must state missing evidence".to_string());
        }
        let quote = decision.exact_source_quote.trim();
        let source_matches = expected.context_sources.iter().any(|context| {
            context.repository == method.repository
                && context.revision == method.revision
                && context.artifact_path == decision.evidence_artifact_path
                && context.source.contains(quote)
        });
        if quote.len() < 4 || !source_matches {
            return Err(format!(
                "model-judged method {} has no exact source quote",
                decision.method_id
            ));
        }
    }
    require_sha256(&submission.submission_sha256)?;
    if submission.submission_sha256 != submission.computed_sha256()? {
        return Err("model-judged submission commitment changed".to_string());
    }
    Ok(())
}

fn require_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("model-judged SHA-256 is not lowercase hex".to_string());
    }
    Ok(())
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("cannot commit model-judged artifact: {error}"))
}

#[cfg(test)]
#[path = "benchmark_model_judged_review_tests.rs"]
mod tests;
