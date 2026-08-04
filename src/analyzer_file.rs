use crate::llm::ResponseSchema;
use crate::report_types::LLMVerdict;
use crate::roles::{classify_file_role, file_role_label};
use crate::types::FileRecord;
use std::path::Path;

use super::support;
use super::verdicts::{build_file_verdict, clear_unsupported_verdict, validate_file_review};
use super::{Analyzer, ReviewProgressCallback, analyzer_prompts};

pub(super) async fn analyze_file(
    analyzer: &Analyzer,
    file: &FileRecord,
    static_signals: &[String],
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<(Option<LLMVerdict>, usize, usize), String> {
    let filename = Path::new(&file.file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let review_source = support::strip_rust_cfg_test_source(&file.source);

    let prompt = support::render_template(
        analyzer_prompts::FILE_REVIEW_PROMPT,
        &[
            &filename,
            &file.file_path,
            &file_role_label(classify_file_role(&file.file_path)),
            &support::format_method_inventory(file),
            &support::format_static_signals(static_signals),
            // File-level cohesion needs the complete source, not a head/tail
            // sample that can omit the responsibility causing the smell.
            &review_source,
        ],
    );

    let (result, mut i, mut o) = analyzer
        .llm_client
        .call(&prompt, ResponseSchema::FileReview)
        .await?;
    let Some(result) = result else {
        support::log_ai_review_miss("file", &file.file_path, None);
        return Ok((None, i, o));
    };
    validate_file_review(&result)
        .map_err(|err| format!("file {} returned an invalid verdict: {err}", file.file_path))?;

    let verdict = build_file_verdict(&result, &file.file_path);

    let mut verdict = verdict;
    if verdict.smelly && verdict.reason.trim().is_empty() {
        clear_unsupported_verdict(&mut verdict);
    }

    let retry_label = format!("file {}", file.file_path);
    let (verdict, retry_i, retry_o) = support::retry_invalid_evidence(
        analyzer,
        &prompt,
        ResponseSchema::FileReview,
        verdict,
        support::RetryContext {
            source: &review_source,
            label: &retry_label,
            on_progress,
        },
        |retry_result| {
            validate_file_review(retry_result)?;
            let mut verdict = build_file_verdict(retry_result, &file.file_path);
            if verdict.smelly && verdict.reason.trim().is_empty() {
                clear_unsupported_verdict(&mut verdict);
            }
            Ok(verdict)
        },
    )
    .await?;
    i += retry_i;
    o += retry_o;

    Ok((Some(verdict), i, o))
}
