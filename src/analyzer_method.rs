use crate::llm::ResponseSchema;
use crate::report_types::LLMVerdict;
use crate::roles::{classify_file_role, file_role_label};
use crate::types::MethodRecord;

use super::support;
use super::verdicts::build_method_verdict;
use super::{Analyzer, analyzer_prompts};

pub(super) async fn analyze_method_review(
    analyzer: &Analyzer,
    method: &MethodRecord,
    static_signals: &[String],
) -> Result<(Option<LLMVerdict>, usize, usize), String> {
    analyze_method_review_with_context(analyzer, method, static_signals, "").await
}

pub(super) async fn analyze_method_review_with_context(
    analyzer: &Analyzer,
    method: &MethodRecord,
    static_signals: &[String],
    file_context: &str,
) -> Result<(Option<LLMVerdict>, usize, usize), String> {
    let mut refs_str = String::new();
    for r in &method.references {
        refs_str.push_str(&format!("{}:{}\n{}\n---\n", r.file_path, r.line, r.snippet));
    }

    let prompt = support::render_template(
        analyzer_prompts::METHOD_REVIEW_PROMPT,
        &[
            &method.language,
            &method.file_path,
            &file_role_label(classify_file_role(&method.file_path)),
            &method.name,
            &method.loc,
            &support::format_static_signals(static_signals),
            &file_context,
            // The method itself is the semantic review unit. Do not silently
            // hide its middle when a long method contains the actual slop.
            &method.source,
            &method.real_ref_count,
            &refs_str,
        ],
    );

    let (result, mut i, mut o) = analyzer
        .llm_client
        .call(&prompt, ResponseSchema::MethodReview)
        .await?;
    let Some(result) = result else {
        support::log_ai_review_miss("method", &method.file_path, Some(&method.name));
        return Ok((None, i, o));
    };

    let mut verdict = build_method_verdict(
        &result,
        &method.file_path,
        &method.name,
        method.loc,
        method.start_line,
        method.end_line,
    );

    if support::clear_if_unsupported_reason(&mut verdict) {
        return Ok((Some(verdict), i, o));
    }

    let retry_label = format!("method {}::{}", method.file_path, method.name);
    let (verdict, retry_i, retry_o) = support::retry_invalid_evidence(
        analyzer,
        &prompt,
        ResponseSchema::MethodReview,
        verdict,
        &method.source,
        &retry_label,
        |retry_result| {
            build_method_verdict(
                retry_result,
                &method.file_path,
                &method.name,
                method.loc,
                method.start_line,
                method.end_line,
            )
        },
    )
    .await?;
    i += retry_i;
    o += retry_o;

    Ok((Some(verdict), i, o))
}
