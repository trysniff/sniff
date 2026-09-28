use super::history_v2_slot_store_support::read_limited;
use super::{
    HistoricalV3LabelTask, HistoricalV3RankIdentity, HistoricalV3ReviewDecision,
    HistoricalV3ReviewDisposition, HistoricalV3ReviewRecord, HistoricalV3ReviewerVerdict,
    HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs,
    validate_historical_v3_source_review_bundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const HISTORICAL_V3_AGENT_REVIEW_SCHEMA_VERSION: u32 = 3;
pub const HISTORICAL_V3_AGENT_ASSIGNMENT_SCHEMA_VERSION: u32 = 1;
const AGENT_PRESENTATION_CONTRACT: &str = "sniffbench-historical-v3-agent-presentation-v1";
const AGENT_SLOT_CARD_CONTRACT: &str = "sniffbench-historical-v3-agent-slot-card-v1";
const MAX_PRESENTATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SUBMISSION_BYTES: u64 = 256 * 1024 * 1024;
const MAX_AUDIT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ASSIGNMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3AgentAssignment {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub rank_sha256: String,
    pub review_item_id: String,
    pub source_bundle_sha256: String,
    pub prompt_sha256: String,
    pub agent_ids: [String; 2],
    pub assignment_sha256: String,
}

impl HistoricalV3AgentAssignment {
    pub fn computed_sha256(&self) -> Result<String, String> {
        hash_json(&(
            self.schema_version,
            &self.protocol_sha256,
            &self.rank_sha256,
            &self.review_item_id,
            &self.source_bundle_sha256,
            &self.prompt_sha256,
            &self.agent_ids,
        ))
    }
}

pub fn prepare_historical_v3_agent_assignment(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
) -> Result<HistoricalV3AgentAssignment, String> {
    validate_historical_v3_source_review_bundle(inputs, bundle)?;
    let mut assignment = HistoricalV3AgentAssignment {
        schema_version: HISTORICAL_V3_AGENT_ASSIGNMENT_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        rank_sha256: inputs.qualification.rank.rank_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        prompt_sha256: sha256(prompt_bytes),
        agent_ids: assigned_agent_ids(&inputs.qualification.rank.rank_sha256),
        assignment_sha256: String::new(),
    };
    assignment.assignment_sha256 = assignment.computed_sha256()?;
    validate_historical_v3_agent_assignment(inputs, bundle, prompt_bytes, &assignment)?;
    Ok(assignment)
}

fn assigned_agent_ids(rank_sha256: &str) -> [String; 2] {
    [1, 2].map(|slot| {
        let input = format!("sniffbench-historical-v3-agent-slot-v1\0{rank_sha256}\0{slot}");
        format!("slot-{slot}-{}", sha256(input.as_bytes()))
    })
}

pub fn validate_historical_v3_agent_assignment(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    assignment: &HistoricalV3AgentAssignment,
) -> Result<(), String> {
    validate_assignment_hashes(inputs, bundle, assignment)?;
    if assignment.prompt_sha256 != sha256(prompt_bytes) {
        return Err("historical-v3 agent assignment changed its prompt bytes".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_pending_agent_assignment(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    assignment: &HistoricalV3AgentAssignment,
) -> Result<(), String> {
    validate_assignment_hashes(inputs, bundle, assignment)
}

fn validate_assignment_hashes(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    assignment: &HistoricalV3AgentAssignment,
) -> Result<(), String> {
    let policy = inputs
        .protocol
        .model_review_policy
        .as_ref()
        .ok_or("historical-v3 agent assignment requires model-review authority")?;
    if assignment.schema_version != HISTORICAL_V3_AGENT_ASSIGNMENT_SCHEMA_VERSION
        || assignment.protocol_sha256 != inputs.protocol.protocol_sha256
        || assignment.rank_sha256 != inputs.qualification.rank.rank_sha256
        || assignment.review_item_id != bundle.review_item_id
        || assignment.source_bundle_sha256 != bundle.bundle_sha256
        || assignment.prompt_sha256 != policy.approved_prompt_sha256
        || assignment.agent_ids != assigned_agent_ids(&inputs.qualification.rank.rank_sha256)
        || assignment.assignment_sha256 != assignment.computed_sha256()?
    {
        return Err(
            "historical-v3 agent assignment is not a valid sealed two-slot task".to_string(),
        );
    }
    Ok(())
}

pub fn read_historical_v3_agent_assignment(
    path: &Path,
) -> Result<HistoricalV3AgentAssignment, String> {
    let bytes = read_limited(path, MAX_ASSIGNMENT_BYTES, "historical-v3 agent assignment")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 agent assignment: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalV3AgentModelOutput {
    reviewer: HistoricalV3AgentReviewer,
    decision: HistoricalV3ReviewDecision,
}

#[derive(Serialize)]
struct HistoricalV3AgentPresentation<'a> {
    contract: &'static str,
    prompt: &'a str,
    prompt_sha256: String,
    source_bundle: &'a HistoricalV3SourceReviewBundle,
}

#[derive(Serialize)]
struct HistoricalV3AgentSlotCard<'a> {
    contract: &'static str,
    slot: u8,
    agent_id: &'a str,
    assignment_sha256: &'a str,
    invocation_sha256: String,
}

pub fn historical_v3_agent_slot_card(
    assignment: &HistoricalV3AgentAssignment,
    invocation_bytes: &[u8],
    slot: u8,
) -> Result<String, String> {
    let index = match slot {
        1 => 0,
        2 => 1,
        _ => return Err("historical-v3 agent slot must be 1 or 2".to_string()),
    };
    serde_json::to_string(&HistoricalV3AgentSlotCard {
        contract: AGENT_SLOT_CARD_CONTRACT,
        slot,
        agent_id: &assignment.agent_ids[index],
        assignment_sha256: &assignment.assignment_sha256,
        invocation_sha256: sha256(invocation_bytes),
    })
    .map_err(|error| format!("cannot present historical-v3 agent slot: {error}"))
}

pub fn validate_historical_v3_agent_slot_card(
    assignment: &HistoricalV3AgentAssignment,
    invocation_bytes: &[u8],
    slot: u8,
    card_bytes: &[u8],
) -> Result<(), String> {
    if card_bytes != historical_v3_agent_slot_card(assignment, invocation_bytes, slot)?.as_bytes() {
        return Err(
            "historical-v3 agent slot card changed from its exact presented bytes".to_string(),
        );
    }
    Ok(())
}

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
    pub invocation_request: String,
    pub invocation_request_sha256: String,
    pub raw_response: String,
    pub raw_response_sha256: String,
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
            &self.invocation_request,
            &self.invocation_request_sha256,
            &self.raw_response,
            &self.raw_response_sha256,
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
    pub assignment_sha256: String,
    pub submission_sha256s: [String; 2],
    pub labels: [HistoricalV3AgentReviewLabel; 2],
    pub tier_agreement: bool,
    pub slop_pattern_agreement: bool,
    pub audit_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3VerifiedAgentReview {
    rank: HistoricalV3RankIdentity,
    record: HistoricalV3ReviewRecord,
    source_bundle_sha256: String,
    audit_sha256: String,
}

impl HistoricalV3VerifiedAgentReview {
    pub fn rank(&self) -> &HistoricalV3RankIdentity {
        &self.rank
    }

    pub fn record(&self) -> &HistoricalV3ReviewRecord {
        &self.record
    }

    pub fn source_bundle_sha256(&self) -> &str {
        &self.source_bundle_sha256
    }

    pub fn audit_sha256(&self) -> &str {
        &self.audit_sha256
    }
}

#[cfg(test)]
impl HistoricalV3VerifiedAgentReview {
    pub(crate) fn synthetic(
        rank: HistoricalV3RankIdentity,
        disposition: HistoricalV3ReviewDisposition,
    ) -> Self {
        Self {
            record: HistoricalV3ReviewRecord {
                stream_rank: rank.stream_rank,
                rank_sha256: rank.rank_sha256.clone(),
                language: rank.language(),
                repository_id: rank.candidate.repository_id,
                disposition,
            },
            rank,
            source_bundle_sha256: "a".repeat(64),
            audit_sha256: "b".repeat(64),
        }
    }
}

impl HistoricalV3AgentReviewAudit {
    pub fn computed_sha256(&self) -> Result<String, String> {
        hash_json(&(
            self.schema_version,
            &self.protocol_sha256,
            &self.source_bundle_sha256,
            &self.review_item_id,
            &self.assignment_sha256,
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
    raw_response: String,
) -> Result<HistoricalV3AgentReviewSubmission, String> {
    let output = parse_model_output(&raw_response)?;
    let invocation_request = canonical_invocation_request(prompt_bytes, bundle)?;
    let mut submission = HistoricalV3AgentReviewSubmission {
        schema_version: HISTORICAL_V3_AGENT_REVIEW_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        reviewer: output.reviewer,
        decision: output.decision,
        invocation_request_sha256: sha256(invocation_request.as_bytes()),
        invocation_request,
        raw_response_sha256: sha256(raw_response.as_bytes()),
        raw_response,
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
    let policy = inputs
        .protocol
        .model_review_policy
        .as_ref()
        .ok_or_else(|| {
            "historical-v3 agent review requires model-judged protocol authority".to_string()
        })?;
    if !matches!(
        inputs.protocol.schema_version,
        super::HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION
            | super::HISTORICAL_V3_PUBLIC_ID_CENSUS_PROTOCOL_SCHEMA_VERSION
    ) {
        return Err("historical-v3 agent review requires model protocol v7 or v8".to_string());
    }
    if sha256(prompt_bytes) != policy.approved_prompt_sha256 {
        return Err(
            "historical-v3 agent prompt differs from the approved protocol bytes".to_string(),
        );
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
    if submission.invocation_request.len() > MAX_PRESENTATION_BYTES
        || submission.invocation_request != canonical_invocation_request(prompt_bytes, bundle)?
        || submission.invocation_request_sha256 != sha256(submission.invocation_request.as_bytes())
    {
        return Err("historical-v3 agent invocation changed its source-only material".to_string());
    }
    require_sha256(&submission.invocation_request_sha256)?;
    if submission.raw_response_sha256 != sha256(submission.raw_response.as_bytes()) {
        return Err("historical-v3 agent raw response commitment changed".to_string());
    }
    require_sha256(&submission.raw_response_sha256)?;
    let output = parse_model_output(&submission.raw_response)?;
    if output.reviewer != submission.reviewer || output.decision != submission.decision {
        return Err("historical-v3 agent decision differs from its raw response".to_string());
    }
    if !reviewer.fresh_context
        || !reviewer.sniff_output_hidden
        || !reviewer.repository_identity_hidden
        || !reviewer.change_metadata_hidden
        || !reviewer.other_reviews_hidden
    {
        return Err(
            "historical-v3 agent review lacks source-only isolation attestations".to_string(),
        );
    }
    if submission.decision.verdict != Some(HistoricalV3ReviewerVerdict::InsufficientContext)
        && (!reviewer.complete_source_context_inspected || !reviewer.behavior_evidence_inspected)
    {
        return Err(
            "historical-v3 agent review claims a conclusive verdict without complete source and behavior inspection"
                .to_string(),
        );
    }
    if (!reviewer.complete_source_context_inspected
        && (submission
            .decision
            .before_contains_unnecessary_machinery
            .is_some()
            || submission.decision.after_removes_that_machinery.is_some()
            || submission.decision.removal_not_relocated.is_some()
            || submission.decision.simpler_counterfactual_matches.is_some()
            || submission.decision.public_surface_preserved.is_some()))
        || (!reviewer.behavior_evidence_inspected
            && submission.decision.behavior_preserved.is_some())
    {
        return Err("historical-v3 agent review claims evidence it did not inspect".to_string());
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

fn canonical_invocation_request(
    prompt_bytes: &[u8],
    bundle: &HistoricalV3SourceReviewBundle,
) -> Result<String, String> {
    let prompt = std::str::from_utf8(prompt_bytes)
        .map_err(|_| "historical-v3 agent prompt must be UTF-8".to_string())?;
    let encoded = serde_json::to_string(&HistoricalV3AgentPresentation {
        contract: AGENT_PRESENTATION_CONTRACT,
        prompt,
        prompt_sha256: sha256(prompt_bytes),
        source_bundle: bundle,
    })
    .map_err(|error| format!("cannot present historical-v3 source bundle: {error}"))?;
    if encoded.len() > MAX_PRESENTATION_BYTES {
        return Err("historical-v3 agent presentation exceeds its byte cap".to_string());
    }
    Ok(encoded)
}

pub fn historical_v3_agent_invocation_request(
    prompt_bytes: &[u8],
    bundle: &HistoricalV3SourceReviewBundle,
) -> Result<String, String> {
    if prompt_bytes.is_empty() {
        return Err("historical-v3 agent prompt is empty".to_string());
    }
    canonical_invocation_request(prompt_bytes, bundle)
}

pub fn validate_historical_v3_agent_invocation(
    protocol: &super::HistoricalV3Protocol,
    bundle: &HistoricalV3SourceReviewBundle,
    invocation_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let policy = protocol
        .model_review_policy
        .as_ref()
        .ok_or_else(|| "historical-v3 agent invocation requires model authority".to_string())?;
    let invocation = std::str::from_utf8(invocation_bytes)
        .map_err(|_| "historical-v3 agent invocation must be UTF-8".to_string())?;
    let value: serde_json::Value = serde_json::from_str(invocation)
        .map_err(|error| format!("historical-v3 agent invocation is not JSON: {error}"))?;
    let prompt = value
        .get("prompt")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "historical-v3 agent invocation has no prompt".to_string())?
        .as_bytes()
        .to_vec();
    if sha256(&prompt) != policy.approved_prompt_sha256
        || invocation != historical_v3_agent_invocation_request(&prompt, bundle)?
    {
        return Err("historical-v3 agent invocation differs from the source-only task".to_string());
    }
    Ok(prompt)
}

fn parse_model_output(raw_response: &str) -> Result<HistoricalV3AgentModelOutput, String> {
    if raw_response.is_empty() || raw_response.len() > MAX_RESPONSE_BYTES {
        return Err("historical-v3 agent response exceeds its byte cap".to_string());
    }
    serde_json::from_str(raw_response)
        .map_err(|error| format!("historical-v3 agent response is not exact JSON: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn audit_historical_v3_agent_reviews(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    assignment: &HistoricalV3AgentAssignment,
    first: &HistoricalV3AgentReviewSubmission,
    second: &HistoricalV3AgentReviewSubmission,
) -> Result<HistoricalV3AgentReviewAudit, String> {
    validate_historical_v3_agent_assignment(inputs, bundle, prompt_bytes, assignment)?;
    validate_historical_v3_agent_review(inputs, bundle, prompt_bytes, first)?;
    validate_historical_v3_agent_review(inputs, bundle, prompt_bytes, second)?;
    if first.reviewer.agent_id != assignment.agent_ids[0]
        || second.reviewer.agent_id != assignment.agent_ids[1]
    {
        return Err("historical-v3 agent submission differs from its preassigned slot".to_string());
    }
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
        assignment_sha256: assignment.assignment_sha256.clone(),
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
    assignment: &HistoricalV3AgentAssignment,
    first: &HistoricalV3AgentReviewSubmission,
    second: &HistoricalV3AgentReviewSubmission,
    audit: &HistoricalV3AgentReviewAudit,
) -> Result<(), String> {
    let expected =
        audit_historical_v3_agent_reviews(inputs, bundle, prompt_bytes, assignment, first, second)?;
    if audit != &expected {
        return Err("historical-v3 agent audit does not replay".to_string());
    }
    Ok(())
}

pub fn read_historical_v3_agent_submission(
    path: &Path,
) -> Result<HistoricalV3AgentReviewSubmission, String> {
    let bytes = read_limited(path, MAX_SUBMISSION_BYTES, "historical-v3 agent submission")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 agent submission: {error}"))
}

pub fn read_historical_v3_agent_audit(path: &Path) -> Result<HistoricalV3AgentReviewAudit, String> {
    let bytes = read_limited(path, MAX_AUDIT_BYTES, "historical-v3 agent audit")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 agent audit: {error}"))
}

pub fn verify_historical_v3_agent_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    prompt_bytes: &[u8],
    assignment: &HistoricalV3AgentAssignment,
    first: &HistoricalV3AgentReviewSubmission,
    second: &HistoricalV3AgentReviewSubmission,
    audit: &HistoricalV3AgentReviewAudit,
) -> Result<HistoricalV3VerifiedAgentReview, String> {
    validate_historical_v3_agent_audit(
        inputs,
        bundle,
        prompt_bytes,
        assignment,
        first,
        second,
        audit,
    )?;
    let verdict = audit.labels[0].decision.verdict;
    let disposition = match verdict {
        Some(HistoricalV3ReviewerVerdict::Slop) if audit.slop_pattern_agreement => {
            HistoricalV3ReviewDisposition::Accepted
        }
        Some(
            HistoricalV3ReviewerVerdict::Clean | HistoricalV3ReviewerVerdict::IntentionalBoundary,
        ) if audit.tier_agreement => HistoricalV3ReviewDisposition::Rejected,
        _ => HistoricalV3ReviewDisposition::Disputed,
    };
    let rank = inputs.qualification.rank.clone();
    Ok(HistoricalV3VerifiedAgentReview {
        record: HistoricalV3ReviewRecord {
            stream_rank: rank.stream_rank,
            rank_sha256: rank.rank_sha256.clone(),
            language: rank.language(),
            repository_id: rank.candidate.repository_id,
            disposition,
        },
        rank,
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        audit_sha256: audit.audit_sha256.clone(),
    })
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
pub(crate) mod tests;
