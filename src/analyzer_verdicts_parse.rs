use super::super::support;
use crate::types::FindingTier;

pub(crate) fn parse_result_fields(
    result: &serde_json::Value,
) -> (FindingTier, String, String, Option<bool>, Option<bool>) {
    let smelly = result
        .get("smelly")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tier = support::parse_tier(result, smelly);
    let evidence = support::parse_evidence(result);
    let reason = result
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let cohesive = result.get("cohesive").and_then(|v| v.as_bool());
    let name_accurate = result.get("name_accurate").and_then(|v| v.as_bool());
    (tier, evidence, reason, cohesive, name_accurate)
}
