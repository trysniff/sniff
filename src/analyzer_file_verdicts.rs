#[path = "analyzer_file_verdicts_rules.rs"]
mod rules;

use crate::llm::LLMClient;
use crate::report_types::LLMVerdict;
use crate::roles::{
    FileRole, classify_file_role, is_compatibility_shim_record, is_intentional_surface_record,
    is_module_barrel_module, is_presentation_surface_module, is_provider_facade_module,
    is_support_plumbing_module, is_wrapper_only_module,
};
use crate::types::{FileRecord, FindingTier};
use std::path::Path;

pub(crate) fn clear_unsupported_verdict(verdict: &mut LLMVerdict) {
    verdict.tier = FindingTier::Clean;
    verdict.smelly = false;
    verdict.reason.clear();
    verdict.evidence.clear();
    verdict.cohesive = Some(true);
    verdict.name_accurate = Some(true);
}

pub(crate) fn normalize_file_verdict(
    file: &FileRecord,
    client: &LLMClient,
    verdict: &mut LLMVerdict,
) {
    let reason = verdict.reason.trim().to_string();

    if let Some(cleaned_reason) = strip_anchor_helper_filename_noise(file, &reason) {
        verdict.reason = cleaned_reason;
    }

    if is_compatibility_shim_record(file) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if verdict.method_name.is_none() && is_provider_facade_module(file) {
        clear_unsupported_verdict(verdict);
        return;
    }

    let reason = verdict.reason.trim().to_string();
    let lower_reason = reason.to_lowercase();

    if should_clear_single_client_bootstrap_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_single_method_orchestration_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_intentional_surface_generic_verdict(file, &lower_reason, &verdict.evidence) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_test_surface_generic_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_support_plumbing_generic_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_module_barrel_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_presentation_surface_generic_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_clear_wrapper_only_generic_verdict(file, &lower_reason) {
        clear_unsupported_verdict(verdict);
        return;
    }

    if rules::should_clear_detector_verdict(file, &reason, &lower_reason)
        || rules::should_clear_analysis_verdict(file, &reason, &lower_reason)
        || rules::should_clear_parsing_verdict(file, &reason)
        || rules::should_clear_versioning_verdict(file, &reason)
    {
        clear_unsupported_verdict(verdict);
        return;
    }

    if should_downgrade_intentional_surface_single_method_verdict(file, &lower_reason, verdict) {
        return;
    }

    if should_downgrade_intentional_surface_small_helper_verdict(file, &lower_reason, verdict) {
        return;
    }

    let Some(tier) = rules::normalize_vague_filename_verdict(file, client, &reason) else {
        return;
    };

    verdict.smelly = matches!(tier, FindingTier::KindaSlop);
    verdict.tier = tier;
    if !verdict.smelly {
        verdict.reason.clear();
        verdict.evidence.clear();
        verdict.cohesive = Some(true);
        verdict.name_accurate = Some(true);
    }
}

fn should_clear_single_method_orchestration_verdict(file: &FileRecord, lower_reason: &str) -> bool {
    if file.methods.len() != 1 {
        return false;
    }

    if !is_intentional_surface_record(file) {
        return false;
    }

    let looks_like_size_only = lower_reason.contains("function is too big")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("too many parameters")
        || lower_reason.contains("functions vary widely")
        || lower_reason.contains("loop-heavy control flow");

    let mentions_real_slop = lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("mixes")
        || lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("helper surface")
        || lower_reason.contains("copy-pasted")
        || lower_reason.contains("duplicate")
        || lower_reason.contains("overbuilt helper")
        || lower_reason.contains("name is vague");

    looks_like_size_only && !mentions_real_slop
}

fn should_clear_single_client_bootstrap_verdict(file: &FileRecord, lower_reason: &str) -> bool {
    if file.methods.len() > 3 {
        return false;
    }

    let path = file.file_path.to_lowercase();
    if !path.contains("client") {
        return false;
    }

    (lower_reason.contains("client initialization") || lower_reason.contains("bootstrap"))
        && (lower_reason.contains("session verification")
            || lower_reason.contains("auth-storage purging")
            || lower_reason.contains("auth storage")
            || lower_reason.contains("purge"))
        && !lower_reason.contains("file does too much")
        && !lower_reason.contains("architecture sprawl")
        && !lower_reason.contains("sprawling helper surface")
}

fn should_clear_intentional_surface_generic_verdict(
    file: &FileRecord,
    lower_reason: &str,
    evidence: &str,
) -> bool {
    if !matches!(
        classify_file_role(&file.file_path),
        FileRole::Entrypoint
            | FileRole::Script
            | FileRole::Example
            | FileRole::Fixture
            | FileRole::Test
            | FileRole::Docs
            | FileRole::Generated
    ) && !is_compatibility_shim_record(file)
    {
        return false;
    }

    let generic_file_reason = lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("name is vague");

    generic_file_reason && evidence_looks_like_import_only(evidence)
}

fn should_clear_support_plumbing_generic_verdict(file: &FileRecord, lower_reason: &str) -> bool {
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

fn should_clear_module_barrel_verdict(file: &FileRecord, lower_reason: &str) -> bool {
    if !is_module_barrel_module(file) {
        return false;
    }

    lower_reason.contains("barrel")
        || lower_reason.contains("re-export")
        || lower_reason.contains("reexports")
        || lower_reason.contains("hiding intent")
        || lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("name is vague")
}

fn should_clear_presentation_surface_generic_verdict(
    file: &FileRecord,
    lower_reason: &str,
) -> bool {
    let presentation_surface = is_presentation_surface_module(file)
        || (file.methods.is_empty() && {
            let normalized = crate::roles::normalize_path(&file.file_path);
            normalized.contains("/screens/")
                || normalized.contains("/components/")
                || normalized.contains("/ui-compose/")
        });

    if !presentation_surface || file.methods.len() > 10 {
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

fn should_clear_wrapper_only_generic_verdict(file: &FileRecord, lower_reason: &str) -> bool {
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

fn should_clear_test_surface_generic_verdict(file: &FileRecord, lower_reason: &str) -> bool {
    if !matches!(classify_file_role(&file.file_path), FileRole::Test) {
        return false;
    }

    let test_surface_noise = lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("functions vary widely in size")
        || lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("name is vague")
        || lower_reason.contains("copy-pasted")
        || lower_reason.contains("duplicate")
        || lower_reason.contains("overbuilt helper");

    let strong_slop = lower_reason.contains("function is too big")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("too many parameters")
        || lower_reason.contains("loop-heavy control flow");

    test_surface_noise && !strong_slop
}

fn evidence_looks_like_import_only(evidence: &str) -> bool {
    let trimmed = evidence.trim();
    if trimmed.is_empty() {
        return true;
    }

    let first_line = trimmed
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let first_line = first_line.trim().to_lowercase();
    first_line.starts_with("import ")
        || first_line.starts_with("from ")
        || first_line.contains("from __future__ import ")
}

fn should_downgrade_intentional_surface_single_method_verdict(
    file: &FileRecord,
    lower_reason: &str,
    verdict: &mut LLMVerdict,
) -> bool {
    if verdict.method_name.is_some()
        || !matches!(
            classify_file_role(&file.file_path),
            FileRole::Entrypoint
                | FileRole::Script
                | FileRole::Example
                | FileRole::Fixture
                | FileRole::Test
        )
    {
        return false;
    }

    if !matches!(verdict.tier, FindingTier::Slop) {
        return false;
    }

    let looks_like_fallback_friction = lower_reason.contains("fallback")
        || lower_reason.contains("catch")
        || lower_reason.contains("swallow")
        || lower_reason.contains("empty object")
        || lower_reason.contains("parse error")
        || lower_reason.contains("error context");

    let looks_like_strong_slop = lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("function is too big")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("too many parameters")
        || lower_reason.contains("loop-heavy control flow");

    let looks_like_single_clause = !verdict.reason.contains(';');

    if looks_like_fallback_friction && looks_like_single_clause && !looks_like_strong_slop {
        verdict.tier = FindingTier::KindaSlop;
        verdict.smelly = true;
        return true;
    }

    false
}

fn should_downgrade_intentional_surface_small_helper_verdict(
    file: &FileRecord,
    lower_reason: &str,
    verdict: &mut LLMVerdict,
) -> bool {
    if verdict.method_name.is_some()
        || !matches!(
            classify_file_role(&file.file_path),
            FileRole::Entrypoint
                | FileRole::Script
                | FileRole::Example
                | FileRole::Fixture
                | FileRole::Test
        )
    {
        return false;
    }

    if !matches!(verdict.tier, FindingTier::Slop) {
        return false;
    }

    if file.methods.len() > 3 {
        return false;
    }

    let looks_like_helper_friction = lower_reason.contains("fallback")
        || lower_reason.contains("catch")
        || lower_reason.contains("swallow")
        || lower_reason.contains("empty object")
        || lower_reason.contains("parse error")
        || lower_reason.contains("error context")
        || lower_reason.contains("copy-pasted")
        || lower_reason.contains("duplicate")
        || lower_reason.contains("overbuilt helper")
        || lower_reason.contains("unnecessary fallback")
        || lower_reason.contains("unused")
        || lower_reason.contains("pass-through wrapper");

    let looks_like_strong_slop = lower_reason.contains("file does too much")
        || lower_reason.contains("module does too much")
        || lower_reason.contains("module mixes")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("function is too big")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("too many parameters")
        || lower_reason.contains("loop-heavy control flow")
        || lower_reason.contains("name is vague")
        || lower_reason.contains("vague filename");

    if looks_like_helper_friction && !looks_like_strong_slop {
        verdict.tier = FindingTier::KindaSlop;
        verdict.smelly = true;
        return true;
    }

    false
}

fn strip_anchor_helper_filename_noise(file: &FileRecord, reason: &str) -> Option<String> {
    if !file_has_filename_anchor_method(file) {
        return None;
    }

    let trimmed = reason.trim();
    let clauses: Vec<&str> = trimmed
        .split(';')
        .map(|clause| clause.trim())
        .filter(|clause| !clause.is_empty())
        .filter(|clause| !clause_contains_helper_filename_noise(clause))
        .collect();

    let cleaned = clauses.join("; ");
    if cleaned == trimmed {
        return None;
    }

    Some(cleaned)
}

fn file_has_filename_anchor_method(file: &FileRecord) -> bool {
    let stem = Path::new(&file.file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let tokens: Vec<&str> = stem
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| token.len() >= 3)
        .collect();

    if tokens.len() < 2 {
        return false;
    }

    file.methods.iter().any(|method| {
        let name = method.name.to_lowercase();
        tokens.iter().all(|token| name.contains(token))
    })
}

fn clause_contains_helper_filename_noise(clause: &str) -> bool {
    let lower = clause.to_lowercase();
    (lower.contains("random utility function") && lower.contains("name"))
        || lower.contains("generic random utility")
        || (lower.contains("generic random utility") && lower.contains("mild cohesion problems"))
        || lower.contains("doesn't cover the random helper")
        || lower.contains("does not cover the random helper")
        || (lower.contains("name doesn't cover") && lower.contains("helper"))
        || (lower.contains("name does not cover") && lower.contains("helper"))
        || (lower.contains("filename") && lower.contains("helper"))
}

#[cfg(test)]
#[path = "tests/analyzer_file_verdicts.rs"]
mod tests;
