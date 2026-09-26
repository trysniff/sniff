use super::{
    HistoricalV3LabelTask, HistoricalV3ReviewDecision, HistoricalV3ReviewerVerdict,
    HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs,
    validate_historical_v3_source_review_bundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HISTORICAL_V3_AGENT_REVIEW_SCHEMA_VERSION: u32 = 1;

fn deserialize_model_version<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3AgentReviewer {
    pub agent_id: String,
    pub provider: String,
    pub model: String,
    #[serde(deserialize_with = "deserialize_model_version")]
    pub model_version: Option<String>,
    pub run_id: String,
    pub prompt_sha256: String,
    pub fresh_context: bool,
    pub sniff_output_hidden: bool,
    pub repository_identity_hidden: bool,
    pub change_metadata_hidden: bool,
    pub other_reviews_hidden: bool,
    pub complete_source_context_inspected: bool,
    pub behavior_evidence_inspected: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3AgentReviewSubmission {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub review_item_id: String,
    pub reviewer: HistoricalV3AgentReviewer,
    pub decision: HistoricalV3ReviewDecision,
    pub submission_sha256: String,
}

impl HistoricalV3AgentReviewSubmission {
    pub fn computed_sha256(&self) -> Result<String, String> {
        hash_json(&(
            self.schema_version,
            &self.protocol_sha256,
            &self.source_bundle_sha256,
            &self.review_item_id,
            &self.reviewer,
            &self.decision,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3AgentReviewLabel {
    pub agent_id: String,
    pub decision: HistoricalV3ReviewDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3AgentReviewAudit {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub review_item_id: String,
    pub submission_sha256s: [String; 2],
    pub labels: [HistoricalV3AgentReviewLabel; 2],
    pub tier_agreement: bool,
    pub slop_pattern_agreement: bool,
    pub audit_sha256: String,
}

impl HistoricalV3AgentReviewAudit {
    pub fn computed_sha256(&self) -> Result<String, String> {
        hash_json(&(
            self.schema_version,
            &self.protocol_sha256,
            &self.source_bundle_sha256,
            &self.review_item_id,
            &self.submission_sha256s,
            &self.labels,
            self.tier_agreement,
            self.slop_pattern_agreement,
        ))
    }
}

pub fn seal_historical_v3_agent_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    reviewer: HistoricalV3AgentReviewer,
    decision: HistoricalV3ReviewDecision,
) -> Result<HistoricalV3AgentReviewSubmission, String> {
    let mut submission = HistoricalV3AgentReviewSubmission {
        schema_version: HISTORICAL_V3_AGENT_REVIEW_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        reviewer,
        decision,
        submission_sha256: String::new(),
    };
    submission.submission_sha256 = submission.computed_sha256()?;
    validate_historical_v3_agent_review(inputs, bundle, prompt_bytes, &submission)?;
    Ok(submission)
}

pub fn validate_historical_v3_agent_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    submission: &HistoricalV3AgentReviewSubmission,
) -> Result<(), String> {
    validate_historical_v3_source_review_bundle(inputs, bundle)?;
    if prompt_bytes.is_empty() {
        return Err("historical-v3 agent prompt is empty".to_string());
    }
    if submission.schema_version != HISTORICAL_V3_AGENT_REVIEW_SCHEMA_VERSION
        || submission.protocol_sha256 != inputs.protocol.protocol_sha256
        || submission.source_bundle_sha256 != bundle.bundle_sha256
        || submission.review_item_id != bundle.review_item_id
    {
        return Err("historical-v3 agent review changed its sealed source task".to_string());
    }
    let reviewer = &submission.reviewer;
    for value in [
        &reviewer.agent_id,
        &reviewer.provider,
        &reviewer.model,
        &reviewer.run_id,
        &reviewer.attestation,
    ] {
        if value.trim().is_empty() {
            return Err("historical-v3 agent reviewer provenance is incomplete".to_string());
        }
    }
    if reviewer
        .model_version
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("historical-v3 agent model version is empty".to_string());
    }
    require_sha256(&reviewer.prompt_sha256)?;
    if reviewer.prompt_sha256 != format!("{:x}", Sha256::digest(prompt_bytes)) {
        return Err("historical-v3 agent prompt does not match its exact bytes".to_string());
    }
    if !reviewer.fresh_context
        || !reviewer.sniff_output_hidden
        || !reviewer.repository_identity_hidden
        || !reviewer.change_metadata_hidden
        || !reviewer.other_reviews_hidden
        || !reviewer.complete_source_context_inspected
        || !reviewer.behavior_evidence_inspected
    {
        return Err(
            "historical-v3 agent review lacks source-only isolation attestations".to_string(),
        );
    }
    let task = HistoricalV3LabelTask {
        review_item_id: bundle.review_item_id.clone(),
        language: bundle.language.clone(),
        public_surface_preserved: bundle.public_surface_preserved,
        public_surface_delta_sha256: bundle.public_surface_delta_sha256.clone(),
        simplifications: bundle.simplifications.clone(),
        methods: bundle.methods.clone(),
        behavior: bundle.behavior.clone(),
        decision: HistoricalV3ReviewDecision::blank(),
    };
    super::history_v3_label_review::validate_historical_v3_review_decision(
        &task,
        &submission.decision,
    )?;
    require_sha256(&submission.submission_sha256)?;
    if submission.submission_sha256 != submission.computed_sha256()? {
        return Err("historical-v3 agent review commitment changed".to_string());
    }
    Ok(())
}

pub fn audit_historical_v3_agent_reviews(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    first: &HistoricalV3AgentReviewSubmission,
    second: &HistoricalV3AgentReviewSubmission,
) -> Result<HistoricalV3AgentReviewAudit, String> {
    validate_historical_v3_agent_review(inputs, bundle, prompt_bytes, first)?;
    validate_historical_v3_agent_review(inputs, bundle, prompt_bytes, second)?;
    if first
        .reviewer
        .agent_id
        .trim()
        .eq_ignore_ascii_case(second.reviewer.agent_id.trim())
        || first.reviewer.run_id == second.reviewer.run_id
    {
        return Err("historical-v3 agent audit repeats an agent or run".to_string());
    }
    if first.reviewer.prompt_sha256 != second.reviewer.prompt_sha256 {
        return Err("historical-v3 agent reviews used different prompts".to_string());
    }
    let tier_agreement = first.decision.verdict == second.decision.verdict;
    let slop_pattern_agreement = tier_agreement
        && first.decision.verdict == Some(HistoricalV3ReviewerVerdict::Slop)
        && first.decision.pattern == second.decision.pattern
        && first
            .decision
            .other_pattern
            .trim()
            .eq_ignore_ascii_case(second.decision.other_pattern.trim());
    let mut audit = HistoricalV3AgentReviewAudit {
        schema_version: HISTORICAL_V3_AGENT_REVIEW_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        submission_sha256s: [
            first.submission_sha256.clone(),
            second.submission_sha256.clone(),
        ],
        labels: [
            HistoricalV3AgentReviewLabel {
                agent_id: first.reviewer.agent_id.clone(),
                decision: first.decision.clone(),
            },
            HistoricalV3AgentReviewLabel {
                agent_id: second.reviewer.agent_id.clone(),
                decision: second.decision.clone(),
            },
        ],
        tier_agreement,
        slop_pattern_agreement,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit.computed_sha256()?;
    Ok(audit)
}

pub fn validate_historical_v3_agent_audit(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    first: &HistoricalV3AgentReviewSubmission,
    second: &HistoricalV3AgentReviewSubmission,
    audit: &HistoricalV3AgentReviewAudit,
) -> Result<(), String> {
    let expected = audit_historical_v3_agent_reviews(inputs, bundle, prompt_bytes, first, second)?;
    if audit != &expected {
        return Err("historical-v3 agent audit does not replay".to_string());
    }
    Ok(())
}

fn require_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("historical-v3 agent SHA-256 is invalid".to_string());
    }
    Ok(())
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("cannot commit historical-v3 agent artifact: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v3_agent_review_tests.rs"]
mod tests;
