use crate::llm::ResponseSchema;
use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, MethodRecord};
use std::env;
use std::fmt::Display;
use std::io::Write;

use super::verdicts::{clear_unsupported_verdict, evidence_is_exact_substring};

pub(super) fn render_template(template: &str, values: &[&dyn Display]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut remainder = template;
    for value in values {
        let Some((before, after)) = remainder.split_once("{}") else {
            rendered.push_str(remainder);
            return rendered;
        };
        rendered.push_str(before);
        rendered.push_str(&value.to_string());
        remainder = after;
    }
    rendered.push_str(remainder);
    rendered
}

pub(super) fn truncate_source(source: &str, max_chars: usize) -> String {
    if source.chars().count() <= max_chars {
        return source.to_string();
    }

    let head = max_chars / 2;
    let tail = max_chars - head;
    let head_text: String = source.chars().take(head).collect();
    let tail_text: String = source
        .chars()
        .rev()
        .take(tail)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head_text}\n...\n{tail_text}")
}

pub(super) fn review_key(file_path: &str, method_name: &str) -> String {
    format!("{}::{}", file_path, method_name)
}

pub(super) fn format_static_signals(signals: &[String]) -> String {
    if signals.is_empty() {
        "none".to_string()
    } else {
        signals
            .iter()
            .map(|s| format!("- {}", s))
            .collect::<Vec<String>>()
            .join("\n")
    }
}

fn rust_cfg_test_start_line(source: &str) -> Option<usize> {
    source
        .lines()
        .position(|line| line.trim().starts_with("#[cfg(test)]"))
        .map(|idx| idx + 1)
}

pub(crate) fn is_rust_cfg_test_method(file: &FileRecord, method: &MethodRecord) -> bool {
    if !file.file_path.ends_with(".rs") {
        return false;
    }

    let Some(cfg_test_line) = rust_cfg_test_start_line(&file.source) else {
        return false;
    };

    method.start_line > cfg_test_line
}

pub(super) fn strip_rust_cfg_test_source(source: &str) -> String {
    let Some(cfg_test_line) = rust_cfg_test_start_line(source) else {
        return source.to_string();
    };

    source
        .lines()
        .take(cfg_test_line.saturating_sub(1))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn format_method_inventory(file: &FileRecord) -> String {
    let methods: Vec<&MethodRecord> = file
        .methods
        .iter()
        .filter(|method| !is_rust_cfg_test_method(file, method))
        .collect();

    if methods.is_empty() {
        return "none".to_string();
    }

    let mut entries = methods
        .iter()
        .map(|method| (method.loc, method.name.as_str(), method.param_count))
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));

    let total = entries.len();
    let mut rendered = entries
        .into_iter()
        .take(8)
        .map(|(loc, name, param_count)| format!("- {} ({} LOC, {} params)", name, loc, param_count))
        .collect::<Vec<_>>();

    if total > 8 {
        rendered.push(format!("- ... (+{} more)", total - 8));
    }

    rendered.join("\n")
}

pub(super) fn surrounding_file_context(file: &FileRecord, method: &MethodRecord) -> String {
    let lines = file.source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return "none".to_string();
    }

    let start = method.start_line.saturating_sub(1).saturating_sub(12);
    let end = method.end_line.saturating_add(12).min(lines.len());
    let context = lines[start..end]
        .iter()
        .enumerate()
        .map(|(offset, line)| format!("{:>4}: {}", start + offset + 1, line))
        .collect::<Vec<_>>()
        .join("\n");

    truncate_source(&context, 6000)
}

pub(super) fn log_ai_review_miss(kind: &str, path: &str, name: Option<&str>) {
    let enabled = env::var("SNIFF_LOG_AI_MISSES")
        .ok()
        .map(|value| {
            let lowered = value.trim().to_lowercase();
            !lowered.is_empty() && lowered != "0" && lowered != "false"
        })
        .unwrap_or(false);
    if !enabled {
        return;
    }

    match name {
        Some(name) => {
            eprintln!("LLM review missed for {kind}: {path}::{name}");
            let _ = std::io::stderr().flush();
        }
        None => {
            eprintln!("LLM review missed for {kind}: {path}");
            let _ = std::io::stderr().flush();
        }
    }
}

pub(super) fn build_invalid_evidence_retry_prompt(
    original_prompt: &str,
    evidence: &str,
    source: &str,
) -> String {
    let evidence = evidence.trim();
    if evidence.is_empty() {
        return original_prompt.to_string();
    }

    format!(
        "{original_prompt}\n\nYour previous answer used evidence that was not an exact substring of the source: `{evidence}`. Re-evaluate the same source and return a corrected JSON object.\n\nFull source for evidence validation:\n---\n{source}\n---\n\nIf you cannot quote exact source evidence, return tier: \"clean\" and an empty reason."
    )
}

pub(super) async fn retry_invalid_evidence<F>(
    analyzer: &super::Analyzer,
    prompt: &str,
    schema: ResponseSchema,
    mut verdict: LLMVerdict,
    source: &str,
    label: &str,
    mut rebuild: F,
) -> Result<(LLMVerdict, usize, usize), String>
where
    F: FnMut(&serde_json::Value) -> LLMVerdict + Send,
{
    if !verdict.smelly || evidence_is_exact_substring(source, &verdict.evidence) {
        return Ok((verdict, 0, 0));
    }

    eprintln!("  Sniffing: retrying evidence for {label}");
    let retry_prompt = build_invalid_evidence_retry_prompt(prompt, &verdict.evidence, source);
    let (retry_result, input_tokens, output_tokens) =
        analyzer.llm_client.call(&retry_prompt, schema).await?;

    let Some(retry_result) = retry_result else {
        clear_unsupported_verdict(&mut verdict);
        return Ok((verdict, input_tokens, output_tokens));
    };

    verdict = rebuild(&retry_result);
    if clear_if_unsupported_reason(&mut verdict) {
        return Ok((verdict, input_tokens, output_tokens));
    }

    if verdict.smelly && !evidence_is_exact_substring(source, &verdict.evidence) {
        clear_unsupported_verdict(&mut verdict);
    }

    Ok((verdict, input_tokens, output_tokens))
}

pub(crate) fn reason_looks_speculative(reason: &str) -> bool {
    let lower = reason.to_lowercase();
    let markers = [
        "previous version",
        "incomplete refactor",
        "careless copy",
        "copy-paste",
        "copy pasted",
        "hardcoded debug",
        "debug path",
        "format string",
        "format string uses placeholder",
        "literal newline",
        "escaped newline",
        "hard to read",
        "fragile",
        "placeholder",
        "runtime issue",
        "speculative",
        "looks like",
        "indicates",
    ];

    markers.iter().any(|marker| lower.contains(marker))
}

pub(crate) fn reason_matches_slop_pattern(reason: &str) -> bool {
    let lower = reason.to_lowercase();
    let markers = [
        "function is too big",
        "function is too large",
        "too much code",
        "too many parameters",
        "name is vague",
        "vague name",
        "filename is vague",
        "vague filename",
        "file does too much",
        "module does too much",
        "dumping ground",
        "responsibility sprawl",
        "sprawling helper surface",
        "helper surface",
        "unrelated responsibilities",
        "too many responsibilities",
        "mixes concerns",
        "mixing concerns",
        "single function handles",
        "overbuilt helper",
        "small helper",
        "unnecessary helper",
        "wrapper",
        "delegat",
        "pass-through",
        "adds no value",
        "branchy control flow",
        "tangled control flow",
        "control flow is tangled",
        "excessive nesting",
        "loop-heavy control flow",
        "duplicate",
        "copy-pasted",
        "copy pasted",
        "repeated logic",
        "unnecessary abstraction",
        "low-value abstraction",
        "generic plumbing",
        "hides intent",
        "hidden intent",
        "boilerplate",
        "fallback chain",
        "unnecessary fallback",
        "comments restate",
        "restates the code",
    ];

    markers.iter().any(|marker| lower.contains(marker))
}

pub(crate) fn reason_is_control_flow_only(reason: &str) -> bool {
    let lower = reason.to_lowercase();
    let has_shape_marker = lower.contains("branchy control flow")
        || lower.contains("loop-heavy control flow")
        || lower.contains("excessive branching")
        || lower.contains("too many branches");
    if !has_shape_marker {
        return false;
    }

    let qualitative_markers = [
        "tangled",
        "duplicated decision",
        "unrelated",
        "hidden state",
        "hidden intent",
        "generic plumbing",
        "hard to follow",
        "hard to understand",
        "unnecessary",
    ];
    !qualitative_markers
        .iter()
        .any(|marker| lower.contains(marker))
}

pub(crate) fn reason_is_empty(reason: &str) -> bool {
    reason.trim().is_empty()
}

pub(super) fn clear_if_unsupported_reason(verdict: &mut LLMVerdict) -> bool {
    if !verdict.smelly {
        return false;
    }

    let unsupported = reason_is_empty(&verdict.reason)
        || reason_looks_speculative(&verdict.reason)
        || reason_is_control_flow_only(&verdict.reason)
        || !reason_matches_slop_pattern(&verdict.reason);
    if unsupported {
        clear_unsupported_verdict(verdict);
    }
    unsupported
}

#[cfg(test)]
mod tests {
    use super::{reason_is_control_flow_only, reason_matches_slop_pattern, render_template};

    #[test]
    fn template_interpolation_does_not_consume_braces_from_inserted_source() {
        let source = "const value = { ok: true };";
        let rendered = render_template("source={} | next={}", &[&source, &"tail"]);

        assert_eq!(rendered, "source=const value = { ok: true }; | next=tail");
    }

    #[test]
    fn reason_gate_accepts_slop_language_and_rejects_runtime_claims() {
        assert!(reason_matches_slop_pattern("file does too much"));
        assert!(reason_matches_slop_pattern("small helper adds no value"));
        assert!(!reason_matches_slop_pattern("this may cause a runtime bug"));
        assert!(reason_is_control_flow_only(
            "branchy control flow (11 branches)"
        ));
        assert!(!reason_is_control_flow_only(
            "tangled control flow hides state transitions"
        ));
    }
}
