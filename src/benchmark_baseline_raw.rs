use super::{
    BASELINE_RAW_OUTPUT_SCHEMA_VERSION, BenchmarkBaseline, BenchmarkBaselineRawOutput,
    BenchmarkCorpus, require_sha256,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub(super) fn validate_baseline_raw_output(
    corpus: &BenchmarkCorpus,
    baseline: &BenchmarkBaseline,
    bytes: &[u8],
) -> Result<(), String> {
    let raw: BenchmarkBaselineRawOutput = serde_json::from_slice(bytes).map_err(|error| {
        format!(
            "baseline {} raw output is invalid: {error}",
            baseline.tool_id
        )
    })?;
    if raw.schema_version != BASELINE_RAW_OUTPUT_SCHEMA_VERSION
        || raw.tool_id != baseline.tool_id
        || raw.tool_version != baseline.tool_version
        || raw.run_id != baseline.run_id
        || raw.source_commitment_sha256 != corpus.source_commitment_sha256
        || raw.cases.len() != corpus.cases.len()
    {
        return Err(format!(
            "baseline {} raw output is not bound to the complete frozen source corpus",
            baseline.tool_id
        ));
    }
    let expected_cases = corpus
        .cases
        .iter()
        .map(|case| case.label.case_id.as_str())
        .collect::<HashSet<_>>();
    let mut seen_cases = HashSet::new();
    let mut raw_findings = HashMap::new();
    for case in &raw.cases {
        if !expected_cases.contains(case.case_id.as_str())
            || !seen_cases.insert(case.case_id.as_str())
        {
            return Err(format!(
                "baseline {} raw output repeats or invents case {}",
                baseline.tool_id, case.case_id
            ));
        }
        require_sha256("baseline response_sha256", &case.response_sha256)?;
        let response = STANDARD.decode(&case.response_base64).map_err(|error| {
            format!(
                "baseline {} case {} has invalid raw response: {error}",
                baseline.tool_id, case.case_id
            )
        })?;
        if format!("{:x}", Sha256::digest(&response)) != case.response_sha256 {
            return Err(format!(
                "baseline {} case {} raw response hash changed",
                baseline.tool_id, case.case_id
            ));
        }
        let response = std::str::from_utf8(&response).map_err(|_| {
            format!(
                "baseline {} case {} raw response is not UTF-8",
                baseline.tool_id, case.case_id
            )
        })?;
        for span in &case.findings {
            let Some(quote) = response.get(span.start_byte..span.end_byte) else {
                return Err(format!(
                    "baseline {} finding {} has an invalid raw response span",
                    baseline.tool_id, span.finding_id
                ));
            };
            if quote.trim().len() < 12
                || raw_findings
                    .insert(span.finding_id.as_str(), case.case_id.as_str())
                    .is_some()
            {
                return Err(format!(
                    "baseline {} finding {} lacks unique substantial raw evidence",
                    baseline.tool_id, span.finding_id
                ));
            }
        }
    }
    if seen_cases != expected_cases || raw_findings.len() != baseline.findings.len() {
        return Err(format!(
            "baseline {} raw output does not account for every case and finding",
            baseline.tool_id
        ));
    }
    for finding in &baseline.findings {
        let Some(source_case_id) = raw_findings.get(finding.finding_id.as_str()) else {
            return Err(format!(
                "baseline {} finding {} is absent from raw output",
                baseline.tool_id, finding.finding_id
            ));
        };
        if finding
            .matched_case_id
            .as_deref()
            .is_some_and(|matched| matched != *source_case_id)
        {
            return Err(format!(
                "baseline {} finding {} is credited to another case",
                baseline.tool_id, finding.finding_id
            ));
        }
    }
    Ok(())
}
