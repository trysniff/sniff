use crate::llm::ResponseSchema;
use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, FindingTier, MethodRecord};
use std::env;
use std::fmt::Display;
use std::io::Write;

use super::verdicts::evidence_matches_source;
use super::{ReviewProgress, ReviewProgressCallback};

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

pub(super) fn strip_rust_cfg_test_source(source: &str) -> String {
    let Some(cfg_test_line) = source
        .lines()
        .position(|line| line.trim().starts_with("#[cfg(test)]"))
        .map(|idx| idx + 1)
    else {
        return source.to_string();
    };

    source
        .lines()
        .take(cfg_test_line.saturating_sub(1))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn format_method_inventory(file: &FileRecord) -> String {
    let methods: Vec<&MethodRecord> = file.methods.iter().collect();

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

pub(super) struct RetryContext<'a> {
    pub(super) source: &'a str,
    pub(super) label: &'a str,
    pub(super) on_progress: Option<&'a ReviewProgressCallback>,
}

pub(super) async fn retry_invalid_evidence<F>(
    analyzer: &super::Analyzer,
    prompt: &str,
    schema: ResponseSchema,
    mut verdict: LLMVerdict,
    retry: RetryContext<'_>,
    mut rebuild: F,
) -> Result<(LLMVerdict, usize, usize), String>
where
    F: FnMut(&serde_json::Value) -> Result<LLMVerdict, String> + Send,
{
    if !verdict.smelly || evidence_matches_source(retry.source, &verdict.evidence) {
        return Ok((verdict, 0, 0));
    }

    if let Some(callback) = retry.on_progress {
        callback(ReviewProgress::RetryingEvidence {
            label: retry.label.to_string(),
        });
    }
    let retry_prompt = build_invalid_evidence_retry_prompt(prompt, &verdict.evidence, retry.source);
    let (retry_result, input_tokens, output_tokens) =
        analyzer.llm_client.call(&retry_prompt, schema).await?;
    if let Some(callback) = retry.on_progress {
        callback(ReviewProgress::Started {
            label: retry.label.to_string(),
        });
    }

    let Some(retry_result) = retry_result else {
        mark_unresolved_evidence(&mut verdict, "the evidence repair returned no response");
        return Ok((verdict, input_tokens, output_tokens));
    };

    verdict = rebuild(&retry_result)?;
    if verdict.smelly && !evidence_matches_source(retry.source, &verdict.evidence) {
        mark_unresolved_evidence(
            &mut verdict,
            "the repaired evidence is not an exact source substring",
        );
    }

    Ok((verdict, input_tokens, output_tokens))
}

fn mark_unresolved_evidence(verdict: &mut LLMVerdict, reason: &str) {
    verdict.smelly = false;
    verdict.tier = FindingTier::Unresolved;
    verdict.evidence.clear();
    verdict.reason = format!("AI evidence could not be validated: {reason}");
}

#[cfg(test)]
mod tests {
    use super::{mark_unresolved_evidence, render_template};
    use crate::report_types::LLMVerdict;
    use crate::types::FindingTier;

    #[test]
    fn template_interpolation_does_not_consume_braces_from_inserted_source() {
        let source = "const value = { ok: true };";
        let rendered = render_template("source={} | next={}", &[&source, &"tail"]);

        assert_eq!(rendered, "source=const value = { ok: true }; | next=tail");
    }

    #[test]
    fn invalid_file_evidence_becomes_unresolved_not_clean() {
        let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: "src/app.py".to_string(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(true),
            evidence: "not in source".to_string(),
            reason: "the file is hard to follow".to_string(),
            loc: 10,
            start_line: 1,
            end_line: 10,
        };

        mark_unresolved_evidence(&mut verdict, "the quote is absent");

        assert_eq!(verdict.tier, FindingTier::Unresolved);
        assert!(!verdict.smelly);
        assert!(verdict.reason.contains("quote is absent"));
        assert!(verdict.evidence.is_empty());
    }
}
