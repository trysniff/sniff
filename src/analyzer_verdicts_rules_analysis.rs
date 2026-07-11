use crate::roles::{
    is_analysis_explanation_support_module, is_analysis_finding_helper_module,
    is_analysis_finding_support_module, is_analysis_finding_workspace_module,
    is_analysis_findings_facade_module, is_analysis_reexports_module, is_support_plumbing_module,
    is_utility_surface_module,
};
use crate::types::FileRecord;

fn small_analysis_helper_noise(file: &FileRecord, lower_reason: &str) -> bool {
    is_analysis_finding_helper_module(&file.file_path)
        && !file.methods.is_empty()
        && file.methods.len() <= 12
        && file.methods.iter().all(|method| method.loc <= 80)
        && (lower_reason.contains("helper surface")
            || lower_reason.contains("sprawling helper surface")
            || lower_reason.contains("too much")
            || lower_reason.contains("mixes")
            || lower_reason.contains("mixing concerns")
            || lower_reason.contains("single responsibility")
            || lower_reason.contains("functions vary widely"))
}

fn analysis_support_noise(file: &FileRecord, lower_reason: &str) -> bool {
    (is_analysis_reexports_module(&file.file_path)
        || is_analysis_finding_support_module(&file.file_path)
        || is_analysis_finding_workspace_module(&file.file_path))
        && (lower_reason.contains("filename is vague")
            || lower_reason.contains("vague filename")
            || lower_reason.contains("helper surface")
            || lower_reason.contains("sprawling helper surface")
            || lower_reason.contains("file does too much")
            || lower_reason.contains("functions vary widely")
            || lower_reason.contains("branchy control flow")
            || lower_reason.contains("control flow is tangled")
            || lower_reason.contains("name is vague")
            || lower_reason.contains("too much"))
}

fn analysis_facade_noise(file: &FileRecord, lower_reason: &str) -> bool {
    is_analysis_findings_facade_module(&file.file_path)
        && (lower_reason.contains("module does too much")
            || lower_reason.contains("module mixes public surface and orchestration")
            || lower_reason.contains("sprawling helper surface")
            || lower_reason.contains("vague facade")
            || lower_reason.contains("duplicate method body")
            || lower_reason.contains("copy-pasted method body")
            || lower_reason.contains("filename is vague")
            || lower_reason.contains("file does too much"))
}

fn explanation_support_noise(file: &FileRecord, lower_reason: &str) -> bool {
    is_analysis_explanation_support_module(&file.file_path)
        && (lower_reason.contains("trivial wrapper") || lower_reason.contains("tiny wrapper"))
}

fn support_plumbing_noise(file: &FileRecord, lower_reason: &str) -> bool {
    is_support_plumbing_module(&file.file_path)
        && (lower_reason.contains("branchy control flow")
            || lower_reason.contains("control flow is tangled")
            || lower_reason.contains("file does too much")
            || lower_reason.contains("module mixes public surface and orchestration")
            || lower_reason.contains("sprawling helper surface")
            || lower_reason.contains("copy-pasted method body")
            || lower_reason.contains("near-duplicate method body")
            || lower_reason.contains("filename is vague")
            || lower_reason.contains("name is vague")
            || lower_reason.contains("mixes"))
}

fn utility_surface_noise(file: &FileRecord, lower_reason: &str) -> bool {
    is_utility_surface_module(file)
        && (lower_reason.contains("filename is vague")
            || lower_reason.contains("vague filename")
            || lower_reason.contains("name is vague")
            || lower_reason.contains("too narrow")
            || lower_reason.contains("delegates to another module")
            || lower_reason.contains("fallback chain")
            || lower_reason.contains("message mapper"))
}

pub(crate) fn should_clear_analysis_verdict(
    file: &FileRecord,
    _reason: &str,
    lower_reason: &str,
) -> bool {
    small_analysis_helper_noise(file, lower_reason)
        || analysis_support_noise(file, lower_reason)
        || analysis_facade_noise(file, lower_reason)
        || explanation_support_noise(file, lower_reason)
        || support_plumbing_noise(file, lower_reason)
        || utility_surface_noise(file, lower_reason)
}
