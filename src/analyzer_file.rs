use crate::llm::ResponseSchema;
use crate::report_types::LLMVerdict;
use crate::roles::{classify_file_role, file_role_label};
use crate::types::FileRecord;
use std::path::Path;

use super::support;
use super::verdicts::{build_file_verdict, normalize_file_verdict};
use super::{Analyzer, analyzer_prompts};

pub(super) async fn analyze_file(
    analyzer: &Analyzer,
    file: &FileRecord,
    static_signals: &[String],
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

    eprintln!("  LLM review: file {}", file.file_path);
    let (result, mut i, mut o) = analyzer
        .llm_client
        .call(&prompt, ResponseSchema::FileReview)
        .await?;
    let Some(result) = result else {
        support::log_ai_review_miss("file", &file.file_path, None);
        return Ok((None, i, o));
    };

    let mut verdict = build_file_verdict(&result, &file.file_path);

    normalize_file_verdict(file, &analyzer.llm_client, &mut verdict);

    if support::clear_if_unsupported_reason(&mut verdict) {
        return Ok((Some(verdict), i, o));
    }

    let retry_label = format!("file {}", file.file_path);
    let (verdict, retry_i, retry_o) = support::retry_invalid_evidence(
        analyzer,
        &prompt,
        ResponseSchema::FileReview,
        verdict,
        &review_source,
        &retry_label,
        |retry_result| {
            let mut verdict = build_file_verdict(retry_result, &file.file_path);
            normalize_file_verdict(file, &analyzer.llm_client, &mut verdict);
            verdict
        },
    )
    .await?;
    i += retry_i;
    o += retry_o;

    Ok((Some(verdict), i, o))
}
