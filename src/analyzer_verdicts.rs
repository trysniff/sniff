#[cfg(test)]
#[path = "analyzer_file_verdicts.rs"]
mod file_verdicts;
#[path = "analyzer_result.rs"]
mod result;

pub(crate) fn clear_unsupported_verdict(verdict: &mut crate::report_types::LLMVerdict) {
    verdict.tier = crate::types::FindingTier::Clean;
    verdict.smelly = false;
    verdict.reason.clear();
    verdict.evidence.clear();
    verdict.cohesive = Some(true);
    verdict.name_accurate = Some(true);
}

#[cfg(test)]
pub(crate) use file_verdicts::normalize_file_verdict;
pub(crate) use result::{
    IntentMethodReview, SemanticEvidence, SemanticMethodReview, build_file_verdict,
    build_semantic_method_verdict, evidence_matches_source, parse_adversarial_method_review,
    parse_intent_method_review, parse_semantic_method_review, validate_file_review,
};
