use crate::analyzer::{ReviewProgress, ReviewProgressCallback};
use crate::config::ResolvedConfig;
use crate::llm::LLMClient;
use crate::report_types::{LLMVerdict, StaticFlag};
use crate::types::FileRecord;
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;

use super::pipeline_roles::{build_llm_client, resolve_roles};

pub(super) struct LlmCheckInput<'a> {
    pub(super) file_records: &'a [FileRecord],
    pub(super) static_flags: &'a [StaticFlag],
    pub(super) only_files: bool,
    pub(super) bar_style: ProgressStyle,
    pub(super) llm_client: Option<Arc<LLMClient>>,
    pub(super) role_input_tokens: usize,
    pub(super) role_output_tokens: usize,
}

pub(super) async fn run_llm_checks(
    input: LlmCheckInput<'_>,
) -> Result<(Vec<LLMVerdict>, usize, usize), String> {
    let method_total = if input.only_files {
        0
    } else {
        input.file_records.iter().map(|f| f.methods.len()).sum()
    };
    let file_total = input.file_records.len();
    let llm_total = method_total + file_total;
    if llm_total == 0 {
        return Ok((
            Vec::new(),
            input.role_input_tokens,
            input.role_output_tokens,
        ));
    }

    let Some(client) = input.llm_client else {
        return Ok((
            Vec::new(),
            input.role_input_tokens,
            input.role_output_tokens,
        ));
    };

    let progress = MultiProgress::new();
    let status_line = progress.add(ProgressBar::new_spinner());
    status_line.set_style(
        ProgressStyle::default_spinner()
            .template("{msg}")
            .map_err(|err| format!("failed to build progress status style: {err}"))?,
    );
    status_line.set_message(format!("{}", "Preparing reviews".cyan().bold()));

    let pb_llm = progress.add(ProgressBar::new(llm_total as u64));
    pb_llm.set_style(input.bar_style);
    pb_llm.set_message(format!("{}", "Sniffing reviews".cyan().bold()));

    let status_line_clone = status_line.clone();
    let pb_llm_clone = pb_llm.clone();
    let on_progress: ReviewProgressCallback = Arc::new(move |event| match event {
        ReviewProgress::Started { label } => {
            status_line_clone.set_message(format!("{}", label.cyan().bold()));
        }
        ReviewProgress::RetryingEvidence { label } => {
            status_line_clone.set_message(format!(
                "{}",
                format!("retrying evidence: {label}").yellow().bold()
            ));
        }
        ReviewProgress::Completed => pb_llm_clone.inc(1),
    });

    let result = crate::analyzer::analyze_with_client(
        input.file_records,
        input.static_flags,
        client,
        input.only_files,
        Some(on_progress),
    )
    .await;
    status_line.finish_and_clear();
    pb_llm.finish_and_clear();
    let (verdicts, in_tok, out_tok) = result?;
    Ok((
        verdicts,
        in_tok + input.role_input_tokens,
        out_tok + input.role_output_tokens,
    ))
}

pub(super) struct ReviewArtifacts {
    pub(super) static_flags: Vec<StaticFlag>,
    pub(super) verdicts: Vec<LLMVerdict>,
    pub(super) in_tok: usize,
    pub(super) out_tok: usize,
    pub(super) ai_expected_reviews: usize,
}

fn ensure_ai_path(
    ai_expected_reviews: usize,
    llm_client_present: bool,
    path: &str,
    config: &ResolvedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if ai_expected_reviews > 0 && config.model.trim().is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "AI model is missing; set SNIFF_MODEL or model in sniff.config.toml before running Sniff.",
        )
        .into());
    }

    if ai_expected_reviews > 0 && !llm_client_present {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "AI config is missing for {path}; set SNIFF_API_KEY and SNIFF_ENDPOINT before running Sniff."
            ),
        )
        .into());
    }

    Ok(())
}

fn annotate_llm_preflight_error(path: &str, err: &str) -> String {
    let detail = err.strip_prefix("LLM preflight failed: ").unwrap_or(err);
    let message = format!("{path}: LLM preflight failed: {detail}");
    if err.contains("HTTP 402") || err.to_lowercase().contains("insufficient balance") {
        format!(
            "{message} (check the SNIFF_API_KEY balance or point SNIFF_ENDPOINT at a funded provider)"
        )
    } else {
        message
    }
}

pub(super) async fn preflight_llm_endpoint(
    path: &str,
    ai_expected_reviews: usize,
    llm_client: Option<&Arc<LLMClient>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if ai_expected_reviews == 0 {
        return Ok(());
    }

    let Some(client) = llm_client else {
        return Ok(());
    };

    eprintln!("Preflighting LLM endpoint...");
    if let Err(err) = client.probe().await {
        return Err(IoError::other(annotate_llm_preflight_error(path, &err)).into());
    }

    Ok(())
}

pub(super) async fn prepare_review_artifacts(
    path: &str,
    only_files: bool,
    config: &ResolvedConfig,
    file_records: &mut [FileRecord],
    bar_style: &ProgressStyle,
) -> Result<ReviewArtifacts, Box<dyn std::error::Error>> {
    let ai_expected_reviews_before_roles =
        super::stats::expected_ai_reviews_after_role_resolution(file_records, only_files);
    let llm_client = if ai_expected_reviews_before_roles > 0 {
        build_llm_client(config).map_err(IoError::other)?
    } else {
        None
    };
    ensure_ai_path(
        ai_expected_reviews_before_roles,
        llm_client.is_some(),
        path,
        config,
    )?;

    let llm_client_for_roles = llm_client.as_ref().map(Arc::clone);
    let (role_in_tok, role_out_tok, llm_client) = resolve_roles(file_records, llm_client_for_roles)
        .await
        .map_err(IoError::other)?;

    let ai_expected_reviews =
        super::stats::expected_ai_reviews_after_role_resolution(file_records, only_files);
    preflight_llm_endpoint(path, ai_expected_reviews, llm_client.as_ref()).await?;

    let (static_flags, _graph) =
        super::graph::build_static_flags(file_records, path, config).map_err(IoError::other)?;
    let (verdicts, in_tok, out_tok) = run_llm_checks(LlmCheckInput {
        file_records,
        static_flags: &static_flags,
        only_files,
        bar_style: bar_style.clone(),
        llm_client,
        role_input_tokens: role_in_tok,
        role_output_tokens: role_out_tok,
    })
    .await
    .map_err(IoError::other)?;

    Ok(ReviewArtifacts {
        static_flags,
        verdicts,
        in_tok,
        out_tok,
        ai_expected_reviews,
    })
}

#[cfg(test)]
mod tests {
    use super::annotate_llm_preflight_error;

    #[test]
    fn preflight_error_has_one_context_prefix() {
        let message = annotate_llm_preflight_error(
            "repo",
            "LLM preflight failed: LLM provider balance is insufficient: HTTP 402",
        );

        assert_eq!(message.matches("LLM preflight failed").count(), 1);
        assert!(message.contains("repo: LLM preflight failed:"));
        assert!(message.contains("HTTP 402"));
    }
}
