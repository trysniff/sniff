use crate::llm::LLMClient;
use crate::report_types::LLMVerdict;
use crate::types::FileRecord;

use super::clear::{clear_unrelated_verdict, clear_unsupported_verdict};
use super::filename::{normalize_vague_filename_verdict, strip_anchor_helper_filename_noise};

pub(crate) fn normalize_file_verdict(
    file: &FileRecord,
    client: &LLMClient,
    verdict: &mut LLMVerdict,
) {
    if clear_unrelated_verdict(file, client, verdict) {
        return;
    }

    let reason = verdict.reason.trim().to_string();
    if let Some(cleaned_reason) = strip_anchor_helper_filename_noise(file, &reason) {
        verdict.reason = cleaned_reason;
        if verdict.reason.trim().is_empty() {
            clear_unsupported_verdict(verdict);
            return;
        }
    }
    let reason = verdict.reason.trim().to_string();
    let Some(tier) = normalize_vague_filename_verdict(file, client, &reason) else {
        return;
    };

    verdict.smelly = matches!(tier, crate::types::FindingTier::KindaSlop);
    verdict.tier = tier;
    if !verdict.smelly {
        verdict.reason.clear();
        verdict.evidence.clear();
        verdict.cohesive = Some(true);
        verdict.name_accurate = Some(true);
    }
}
