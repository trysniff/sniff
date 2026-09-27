use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Protocol, HistoricalV3ReviewRecordPaths,
    HistoricalV3VerifiedAgentReview, HistoricalV3VerifiedSourceReview,
    historical_v3_agent_prompt_from_submission, read_historical_v3_agent_audit,
    read_historical_v3_agent_submission, validate_historical_v3_agent_review,
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
    if audit_exists && (!first_exists || !second_exists) {
        return Err("historical-v3 agent audit skips an independent review".to_string());
    }
    let inputs = source.inputs(protocol, collection);
    let bundle = source.bundle();
    let first = if first_exists {
        let submission = read_historical_v3_agent_submission(&paths.agent_one)?;
        let prompt = historical_v3_agent_prompt_from_submission(&submission)?;
        validate_historical_v3_agent_review(&inputs, bundle, &prompt, &submission)?;
        Some(submission)
    } else {
        None
    };
    let second = if second_exists {
        let submission = read_historical_v3_agent_submission(&paths.agent_two)?;
        let prompt = historical_v3_agent_prompt_from_submission(&submission)?;
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
    let prompt = historical_v3_agent_prompt_from_submission(&first)?;
    verify_historical_v3_agent_review(&inputs, bundle, &prompt, &first, &second, &audit).map(Some)
}
