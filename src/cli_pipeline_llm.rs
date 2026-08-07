use crate::analyzer::{ReviewProgress, ReviewProgressCallback};
use crate::config::ResolvedConfig;
use crate::llm::LLMClient;
use crate::report_types::{LLMVerdict, MethodReviewRecord, StaticFlag};
use crate::slop_cases::SlopCase;
use crate::types::FileRecord;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::pipeline_roles::{build_llm_client, resolve_roles};

pub(super) struct LlmCheckInput<'a> {
    pub(super) file_records: &'a [FileRecord],
    pub(super) context_file_records: &'a [FileRecord],
    pub(super) static_flags: &'a [StaticFlag],
    pub(super) graph: &'a crate::symbol_graph::SymbolGraph,
    pub(super) bar_style: ProgressStyle,
    pub(super) llm_client: Option<Arc<LLMClient>>,
    pub(super) role_input_tokens: usize,
    pub(super) role_output_tokens: usize,
    pub(super) journal_path: Option<&'a Path>,
    pub(super) scan_id: Option<&'a str>,
    pub(super) budget_usd: Option<f64>,
}

const MAX_PROGRESS_LABEL_CHARS: usize = 76;

fn compact_progress_label(label: &str) -> String {
    let label = label.trim();
    if label.chars().count() <= MAX_PROGRESS_LABEL_CHARS {
        return label.to_string();
    }

    let suffix: String = label
        .chars()
        .skip(label.chars().count() - (MAX_PROGRESS_LABEL_CHARS - 3))
        .collect();
    format!("...{suffix}")
}

pub(super) async fn run_llm_checks(
    input: LlmCheckInput<'_>,
) -> Result<
    (
        Vec<LLMVerdict>,
        Vec<MethodReviewRecord>,
        Vec<SlopCase>,
        usize,
        usize,
        usize,
    ),
    String,
> {
    let method_total = super::stats::expected_method_reviews(input.file_records);
    let llm_total = method_total;
    if llm_total == 0 {
        return Ok((
            Vec::new(),
            Vec::new(),
            Vec::new(),
            input.role_input_tokens,
            input.role_output_tokens,
            0,
        ));
    }

    let Some(client) = input.llm_client else {
        return Err("LLM client unavailable for required reviews".to_string());
    };

    let progress = MultiProgress::new();
    let status_line = progress.add(ProgressBar::new_spinner());
    let status_style = ProgressStyle::default_spinner()
        .template("{msg:.cyan.bold}")
        .map_err(|err| format!("failed to build progress status style: {err}"))?;
    let retry_style = ProgressStyle::default_spinner()
        .template("{msg:.yellow.bold}")
        .map_err(|err| format!("failed to build retry status style: {err}"))?;
    status_line.set_style(status_style.clone());
    status_line.set_message("Preparing reviews");

    let pb_llm = progress.add(ProgressBar::new(llm_total as u64));
    pb_llm.set_style(input.bar_style);

    let status_line_clone = status_line.clone();
    let status_style_clone = status_style.clone();
    let retry_style_clone = retry_style.clone();
    let pb_llm_clone = pb_llm.clone();
    let on_progress: ReviewProgressCallback = Arc::new(move |event| match event {
        ReviewProgress::Started { label } => {
            status_line_clone.set_style(status_style_clone.clone());
            status_line_clone.set_message(compact_progress_label(&label));
        }
        ReviewProgress::RetryingEvidence { label } => {
            status_line_clone.set_style(retry_style_clone.clone());
            let retry_label = compact_progress_label(&format!("retrying evidence: {label}"));
            status_line_clone.set_message(retry_label);
        }
        ReviewProgress::Completed => pb_llm_clone.inc(1),
    });

    let usage_client = Arc::clone(&client);
    let result =
        crate::analyzer::analyze_with_client_and_graph_and_journal_with_context_and_records(
            crate::analyzer::AnalysisRun {
                file_records: input.file_records,
                context_file_records: input.context_file_records,
                static_flags: input.static_flags,
                with_file_reviews: false,
                graph: Some(input.graph),
                journal_path: input.journal_path,
                scan_id: input.scan_id,
                budget_usd: input.budget_usd,
            },
            Arc::clone(&client),
            Some(on_progress),
        )
        .await;
    status_line.finish_and_clear();
    pb_llm.finish_and_clear();
    let (analysis, in_tok, out_tok) = result?;
    let graph_facts = crate::synthesis::build_graph_facts(&analysis.method_records, input.graph);
    let synthesis = crate::synthesis::run_synthesis(
        &analysis.method_records,
        &graph_facts,
        Arc::clone(&client),
        input.journal_path,
        input.scan_id,
        input.budget_usd,
    )
    .await?;
    Ok((
        analysis.verdicts,
        analysis.method_records,
        synthesis.cases,
        in_tok + input.role_input_tokens + synthesis.input_tokens,
        out_tok + input.role_output_tokens + synthesis.output_tokens,
        usage_client.cached_input_tokens(),
    ))
}

pub(super) struct ReviewArtifacts {
    pub(super) static_flags: Vec<StaticFlag>,
    pub(super) verdicts: Vec<LLMVerdict>,
    pub(super) method_records: Vec<MethodReviewRecord>,
    pub(super) synthesis_cases: Vec<SlopCase>,
    pub(super) in_tok: usize,
    pub(super) out_tok: usize,
    pub(super) cached_in_tok: usize,
    pub(super) ai_expected_reviews: usize,
    pub(super) method_reviews_expected: usize,
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
        return Err(IoError::other(format!(
            "{path}: LLM client unavailable for required reviews"
        ))
        .into());
    };

    eprintln!("Preflighting LLM endpoint...");
    let timeout = preflight_timeout();
    match tokio::time::timeout(timeout, client.probe()).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return Err(IoError::other(annotate_llm_preflight_error(path, &err)).into());
        }
        Err(_) => {
            return Err(IoError::other(format!(
                "{path}: LLM preflight timed out after {}s",
                timeout.as_secs()
            ))
            .into());
        }
    }

    Ok(())
}

fn preflight_timeout() -> Duration {
    std::env::var("SNIFF_LLM_PREFLIGHT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(120))
}

pub(super) async fn prepare_review_artifacts(
    path: &str,
    config: &ResolvedConfig,
    file_records: &mut [FileRecord],
    bar_style: &ProgressStyle,
    journal_path: Option<&Path>,
    semantic_cache: &crate::semantic_cache::SemanticIndexCache,
    budget_usd: Option<f64>,
) -> Result<ReviewArtifacts, Box<dyn std::error::Error>> {
    let ai_expected_reviews_before_roles =
        super::stats::expected_ai_reviews_after_role_resolution(file_records);
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
    let scan_id = llm_client
        .as_ref()
        .map(|client| crate::review_journal::scan_id(file_records, &client.review_context_key()));
    if let (Some(journal_path), Some(scan_id), Some(client)) =
        (journal_path, scan_id.as_deref(), llm_client.as_ref())
    {
        crate::review_journal::initialize_method_stage(
            journal_path,
            scan_id,
            &client.review_context_key(),
            super::stats::expected_method_reviews(file_records),
        )
        .map_err(IoError::other)?;
    }

    let llm_client_for_roles = llm_client.as_ref().map(Arc::clone);
    let (role_in_tok, role_out_tok, llm_client) = resolve_roles(
        file_records,
        llm_client_for_roles,
        journal_path,
        scan_id.as_deref(),
        budget_usd,
    )
    .await
    .map_err(IoError::other)?;

    let ai_expected_reviews = super::stats::expected_ai_reviews_after_role_resolution(file_records);

    let production_paths = file_records
        .iter()
        .map(|file| file.file_path.clone())
        .collect::<HashSet<_>>();
    let (context_root, mut evidence_records) =
        super::io::scan_context_files_with_cache(path, config, Some(semantic_cache))
            .await
            .map_err(IoError::other)?;
    evidence_records.retain(|file| !production_paths.contains(&file.file_path));
    let (static_flags, graph) = super::graph::build_static_flags(
        file_records,
        &evidence_records,
        &context_root.to_string_lossy(),
        config,
        Some(semantic_cache),
    )
    .map_err(IoError::other)?;
    let mut context_file_records = file_records.to_vec();
    context_file_records.extend(evidence_records);
    let review_result = run_llm_checks(LlmCheckInput {
        file_records,
        context_file_records: &context_file_records,
        static_flags: &static_flags,
        graph: &graph,
        bar_style: bar_style.clone(),
        llm_client,
        role_input_tokens: role_in_tok,
        role_output_tokens: role_out_tok,
        journal_path,
        scan_id: scan_id.as_deref(),
        budget_usd,
    })
    .await
    .map_err(IoError::other);

    let (
        verdicts,
        method_records,
        synthesis_cases,
        fallback_in_tok,
        fallback_out_tok,
        fallback_cached_in_tok,
    ) = review_result?;
    let journal_usage = journal_path
        .map(crate::review_journal::summarize)
        .transpose()
        .map_err(IoError::other)?
        .filter(|summary| summary.scan_id.as_deref() == scan_id.as_deref());
    let (in_tok, out_tok, cached_in_tok) = journal_usage.map_or(
        (fallback_in_tok, fallback_out_tok, fallback_cached_in_tok),
        |summary| {
            (
                summary.input_tokens,
                summary.output_tokens,
                summary.cached_input_tokens,
            )
        },
    );

    Ok(ReviewArtifacts {
        static_flags,
        verdicts,
        method_records,
        synthesis_cases,
        in_tok,
        out_tok,
        cached_in_tok,
        ai_expected_reviews,
        method_reviews_expected: super::stats::expected_method_reviews(file_records),
    })
}

#[cfg(test)]
mod tests {
    use super::{annotate_llm_preflight_error, compact_progress_label};

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

    #[test]
    fn progress_labels_are_bounded_to_one_terminal_line() {
        let label = compact_progress_label(
            "method C:\\Users\\User\\Bumpkin\\src\\bumpkin\\analysis\\very_long_module.py::review_release_analysis",
        );

        assert_eq!(label.chars().count(), 76);
        assert!(label.starts_with("..."));
        assert!(label.ends_with("review_release_analysis"));
    }
}
