use super::super::history_v2_slot_store_support::read_limited;
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Protocol, HistoricalV3ReviewRecordPaths,
    HistoricalV3VerifiedAgentReview, HistoricalV3VerifiedSourceReview,
    read_historical_v3_agent_audit, read_historical_v3_agent_submission,
    validate_historical_v3_agent_invocation, validate_historical_v3_agent_review,
    verify_historical_v3_agent_review,
};
use super::plain_file_exists;

pub(super) fn replay_agent_review(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    source: &HistoricalV3VerifiedSourceReview,
    paths: &HistoricalV3ReviewRecordPaths,
) -> Result<Option<HistoricalV3VerifiedAgentReview>, String> {
    let first_exists = plain_file_exists(&paths.agent_one, "historical-v3 first agent review")?;
    let second_exists = plain_file_exists(&paths.agent_two, "historical-v3 second agent review")?;
    let audit_exists = plain_file_exists(&paths.agent_audit, "historical-v3 agent audit")?;
    let invocation_exists =
        plain_file_exists(&paths.agent_invocation, "historical-v3 agent invocation")?;
    if !invocation_exists {
        if first_exists || second_exists || audit_exists {
            return Err("historical-v3 agent review lacks its presented invocation".to_string());
        }
        return Ok(None);
    }
    if audit_exists && (!first_exists || !second_exists) {
        return Err("historical-v3 agent audit skips an independent review".to_string());
    }
    let inputs = source.inputs(protocol, collection);
    let bundle = source.bundle();
    let invocation = read_limited(
        &paths.agent_invocation,
        64 * 1024 * 1024,
        "historical-v3 agent invocation",
    )?;
    let prompt = validate_historical_v3_agent_invocation(protocol, bundle, &invocation)?;
    let first = if first_exists {
        let submission = read_historical_v3_agent_submission(&paths.agent_one)?;
        validate_historical_v3_agent_review(&inputs, bundle, &prompt, &submission)?;
        Some(submission)
    } else {
        None
    };
    let second = if second_exists {
        let submission = read_historical_v3_agent_submission(&paths.agent_two)?;
        validate_historical_v3_agent_review(&inputs, bundle, &prompt, &submission)?;
        Some(submission)
    } else {
        None
    };
    let (Some(first), Some(second)) = (first, second) else {
        return Ok(None);
    };
    if !audit_exists {
        return Ok(None);
    }
    let audit = read_historical_v3_agent_audit(&paths.agent_audit)?;
    verify_historical_v3_agent_review(&inputs, bundle, &prompt, &first, &second, &audit).map(Some)
}
