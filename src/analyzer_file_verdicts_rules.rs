#[path = "analyzer_verdicts_rules_analysis.rs"]
mod analysis;
#[path = "analyzer_verdicts_detector.rs"]
mod detector;
#[path = "analyzer_verdicts_filename.rs"]
mod filename;
#[path = "analyzer_verdicts_rules_parse.rs"]
mod parse;
#[path = "analyzer_verdicts_versioning.rs"]
mod versioning;

pub(super) fn should_clear_detector_verdict(
    file: &crate::types::FileRecord,
    reason: &str,
    lower_reason: &str,
) -> bool {
    detector::should_clear_detector_verdict(file, reason, lower_reason)
}

pub(super) fn should_clear_analysis_verdict(
    file: &crate::types::FileRecord,
    reason: &str,
    lower_reason: &str,
) -> bool {
    analysis::should_clear_analysis_verdict(file, reason, lower_reason)
}

pub(super) fn should_clear_parsing_verdict(file: &crate::types::FileRecord, reason: &str) -> bool {
    parse::should_clear_parsing_verdict(file, reason)
}

pub(super) fn should_clear_versioning_verdict(
    file: &crate::types::FileRecord,
    reason: &str,
) -> bool {
    versioning::should_clear_versioning_verdict(file, reason)
}

pub(super) fn normalize_vague_filename_verdict(
    file: &crate::types::FileRecord,
    client: &crate::llm::LLMClient,
    reason: &str,
) -> Option<crate::types::FindingTier> {
    filename::normalize_vague_filename_verdict(file, client, reason)
}
