pub use super::render::render_report;
use crate::slop_reason::{self, ReasonKind};

fn normalize_with_rules(reason: &str, rules: &[(&str, &str)]) -> Option<String> {
    let lower = reason.to_lowercase();
    for (needle, replacement) in rules {
        if lower.contains(needle) {
            return Some((*replacement).to_string());
        }
    }
    None
}

pub(super) fn finding_label(reason: &str) -> String {
    normalize_with_rules(
        reason,
        &[
            ("orphaned export", "orphaned export"),
            ("overbuilt helper", "overbuilt helper"),
            ("copy-pasted method body", "duplicate method body"),
            ("near-duplicate method body", "duplicate method body"),
            (
                "test mirrors production implementation",
                "test mirrors production implementation",
            ),
            ("module has broad dependency fan-out", "architecture sprawl"),
            ("module has sprawling helper surface", "architecture sprawl"),
            (
                "module mixes public surface and orchestration",
                "architecture sprawl",
            ),
            (
                "module has uneven method sizes and dependency fan-out",
                "architecture sprawl",
            ),
            ("high churn", "high churn"),
            ("rework-heavy file", "high churn"),
            (
                "generated-style marker present",
                "generated-style marker present",
            ),
            ("filename is vague", "filename is vague"),
            ("vague filename", "filename is vague"),
            ("file does too much", "file does too much"),
            ("responsibility sprawl", "file does too much"),
            (
                "functions vary widely in size",
                "functions vary widely in size",
            ),
            ("function sizes are uneven", "functions vary widely in size"),
            ("uneven function sizing", "functions vary widely in size"),
            ("function is too big", "function is too big"),
            ("sprawling function", "function is too big"),
            ("too much code", "function is too big"),
            ("bloated function", "function is too big"),
            ("control flow is tangled", "control flow is tangled"),
            ("tangled control flow", "control flow is tangled"),
            ("too many parameters", "too many parameters"),
            ("argument pile-up", "too many parameters"),
        ],
    )
    .unwrap_or_else(|| reason.to_string())
}

pub(super) fn normalize_ai_reason(reason: &str) -> String {
    normalize_with_rules(
        reason,
        &[
            ("orphaned export", "orphaned export"),
            ("overbuilt helper", "overbuilt helper"),
            ("copy-pasted method body", "duplicate method body"),
            ("near-duplicate method body", "duplicate method body"),
            (
                "test mirrors production implementation",
                "test mirrors production implementation",
            ),
            ("module has broad dependency fan-out", "architecture sprawl"),
            ("module has sprawling helper surface", "architecture sprawl"),
            (
                "module mixes public surface and orchestration",
                "architecture sprawl",
            ),
            (
                "module has uneven method sizes and dependency fan-out",
                "architecture sprawl",
            ),
            ("high churn", "high churn"),
            ("rework-heavy file", "high churn"),
            (
                "generated-style marker present",
                "generated-style marker present",
            ),
            ("filename is vague", "filename is vague"),
            ("vague filename", "filename is vague"),
            ("duplicate method body", "duplicate method body"),
            (
                "implementation-coupling",
                "test mirrors production implementation",
            ),
            (
                "mirrors production implementation",
                "test mirrors production implementation",
            ),
            ("dependency fan-out", "architecture sprawl"),
            ("architecture sprawl", "architecture sprawl"),
            ("multiple languages", "file does too much"),
            ("multiple parsing concerns", "file does too much"),
            ("file does too much", "file does too much"),
            ("responsibility sprawl", "file does too much"),
            (
                "functions vary widely in size",
                "functions vary widely in size",
            ),
            ("function sizes are uneven", "functions vary widely in size"),
            ("uneven function sizing", "functions vary widely in size"),
            ("function is too big", "function is too big"),
            ("sprawling function", "function is too big"),
            ("too much code", "function is too big"),
            ("bloated function", "function is too big"),
            ("control flow is tangled", "control flow is tangled"),
            ("tangled control flow", "control flow is tangled"),
            ("too many parameters", "too many parameters"),
            ("argument pile-up", "too many parameters"),
            ("name is vague", "name is vague"),
            ("generic or vague name", "name is vague"),
            ("vague name", "name is vague"),
        ],
    )
    .unwrap_or_else(|| reason.to_string())
}

fn truncate_snippet(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }

    let truncated: String = trimmed.chars().take(max_chars).collect();
    format!("{truncated}...")
}

pub(super) fn format_ai_finding(reason: &str, evidence: &str) -> String {
    let reason = normalize_ai_reason(reason);
    let evidence = evidence.trim();
    if evidence.is_empty() {
        return reason;
    }

    format!(
        "{} (evidence: \"{}\")",
        reason,
        truncate_snippet(&evidence.replace('\n', " "), 120)
    )
}

pub(super) fn is_supporting_only_reason(reason: &str) -> bool {
    slop_reason::is(reason, ReasonKind::SupportingOnly)
}
