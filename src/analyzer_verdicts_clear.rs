use crate::llm::LLMClient;
use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, FindingTier};
use crate::roles::{is_presentation_surface_module, is_support_plumbing_module, is_wrapper_only_module};

use super::detector::should_clear_detector_verdict;
use super::rules::{should_clear_analysis_verdict, should_clear_parsing_verdict};
use super::versioning::should_clear_versioning_verdict;

pub(crate) fn clear_unrelated_verdict(
    file: &FileRecord,
    client: &LLMClient,
    verdict: &mut LLMVerdict,
) -> bool {
    let reason = verdict.reason.trim().to_string();
    let lower_reason = reason.to_lowercase();

    if should_clear_detector_verdict(file, &reason, &lower_reason)
        || should_clear_analysis_verdict(file, &reason, &lower_reason)
        || should_clear_parsing_verdict(file, &reason)
        || should_clear_versioning_verdict(file, &reason)
        || should_clear_support_surface_verdict(file, &lower_reason)
    {
        clear_unsupported_verdict(verdict);
        return true;
    }

    let _ = client;
    false
}

pub(crate) fn clear_unsupported_verdict(verdict: &mut LLMVerdict) {
    verdict.tier = FindingTier::Clean;
    verdict.smelly = false;
    verdict.reason.clear();
    verdict.evidence.clear();
    verdict.cohesive = Some(true);
    verdict.name_accurate = Some(true);
}

fn should_clear_support_surface_verdict(file: &FileRecord, lower_reason: &str) -> bool {
    if should_clear_wrapper_only_surface(file, lower_reason) {
        return true;
    }

    if should_clear_presentation_surface(file, lower_reason) {
        return true;
    }

    should_clear_support_plumbing_surface(file, lower_reason)
}

fn should_clear_support_plumbing_surface(file: &FileRecord, lower_reason: &str) -> bool {
    if !is_support_plumbing_module(&file.file_path) {
        return false;
    }

    let support_plumbing_noise = lower_reason.contains("copy-pasted")
        || lower_reason.contains("duplicate")
        || lower_reason.contains("overbuilt helper")
        || lower_reason.contains("helper surface")
        || lower_reason.contains("state bag")
        || lower_reason.contains("state holder")
        || lower_reason.contains("state struct")
        || lower_reason.contains("state object")
        || lower_reason.contains("unrelated fields")
        || lower_reason.contains("cabinet row")
        || lower_reason.contains("cabinet rows")
        || lower_reason.contains("row helper")
        || lower_reason.contains("upsert cabinet row")
        || lower_reason.contains("upsert reminder row")
        || lower_reason.contains("reminder upsert")
        || lower_reason.contains("surface state logic")
        || lower_reason.contains("cabinet and reminders")
        || lower_reason.contains("different domain concerns")
        || lower_reason.contains("planner")
        || lower_reason.contains("design token")
        || lower_reason.contains("design tokens")
        || lower_reason.contains("semantic color definition")
        || lower_reason.contains("semantic color palette")
        || lower_reason.contains("string constants")
        || lower_reason.contains("typography")
        || lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("name is vague")
        || lower_reason.contains("filename only mentions")
        || lower_reason.contains("mixing concerns")
        || lower_reason.contains("mild cohesion")
        || lower_reason.contains("mixin class")
        || lower_reason.contains("module-level and class-level")
        || lower_reason.contains("mixing module-level and class-level")
        || lower_reason.contains("single function defined as a module-level function");

    let strong_slop = lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("function is too big")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("too many parameters")
        || lower_reason.contains("loop-heavy control flow");

    support_plumbing_noise && !strong_slop
}

fn should_clear_presentation_surface(file: &FileRecord, lower_reason: &str) -> bool {
    if !is_presentation_surface_module(file) || file.methods.len() > 20 {
        return false;
    }

    let surface_noise = lower_reason.contains("mixes ui components")
        || lower_reason.contains("color constants object")
        || lower_reason.contains("semantic color palette")
        || lower_reason.contains("private extension functions")
        || lower_reason.contains("mild cohesion")
        || lower_reason.contains("name is vague")
        || lower_reason.contains("vague for a file")
        || lower_reason.contains("unrelated private extension functions");

    let strong_slop = lower_reason.contains("function is too big")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("too many parameters")
        || lower_reason.contains("module has sprawling helper surface")
        || lower_reason.contains("file does too much");

    surface_noise && !strong_slop
}

fn should_clear_wrapper_only_surface(file: &FileRecord, lower_reason: &str) -> bool {
    if !is_wrapper_only_module(file) || file.methods.len() > 4 {
        return false;
    }

    lower_reason.contains("copy-pasted")
        || lower_reason.contains("duplicate")
        || lower_reason.contains("overbuilt helper")
        || lower_reason.contains("helper surface")
        || lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("name is vague")
        || lower_reason.contains("filename is inaccurate")
        || lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("pass-through wrapper")
        || lower_reason.contains("trivial delegation wrapper")
        || lower_reason.contains("thin wrapper")
        || lower_reason.contains("delegates to another")
        || lower_reason.contains("hides its purpose")
        || lower_reason.contains("adds no value beyond renaming")
}
