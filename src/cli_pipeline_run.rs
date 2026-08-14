use super::{env, io, llm, stats};
use crate::report_types::RunReport;
use indicatif::ProgressStyle;
use std::hash::{Hash, Hasher};
use std::io::{Error as IoError, ErrorKind};

fn build_progress_style() -> Result<ProgressStyle, String> {
    ProgressStyle::default_bar()
        .template("[{bar:18.cyan/dim}] {pos}/{len} {percent}%")
        .map_err(|err| err.to_string())
        .map(|style| style.progress_chars("=>-"))
}

fn exit_code_for_run(has_issues: bool, ai_failed_reviews: usize) -> i32 {
    if has_issues || ai_failed_reviews > 0 {
        1
    } else {
        0
    }
}

pub(super) fn source_inventory_summary(file_records: &[crate::types::FileRecord]) -> String {
    let methods = file_records
        .iter()
        .map(|file| file.methods.len())
        .sum::<usize>();
    format!(
        "Found {} supported files, {} methods.",
        file_records.len(),
        methods
    )
}

pub(super) fn report_path_for_target(target_path: &std::path::Path) -> std::path::PathBuf {
    let current_dir = std::env::current_dir()
        .ok()
        .map(|path| strip_windows_verbatim_prefix(std::fs::canonicalize(&path).unwrap_or(path)));
    let resolved_target = strip_windows_verbatim_prefix(
        std::fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf()),
    );

    if let Some(current_dir) = current_dir
        && resolved_target.starts_with(&current_dir)
    {
        return current_dir.join("sniff-report.md");
    }

    let target_root = if resolved_target.is_dir() {
        resolved_target
    } else {
        resolved_target
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    };

    if [".git", "Cargo.toml", "pyproject.toml", "package.json"]
        .iter()
        .any(|marker| target_root.join(marker).exists())
    {
        return target_root.join("sniff-report.md");
    }

    let mut candidate = target_root.clone();

    loop {
        if candidate.join(".git").exists() {
            return candidate.join("sniff-report.md");
        }

        let Some(parent) = candidate.parent() else {
            return target_root.join("sniff-report.md");
        };
        if parent == candidate {
            return target_root.join("sniff-report.md");
        }
        candidate = parent.to_path_buf();
    }
}

pub(super) fn journal_path_for_target(
    target_path: &std::path::Path,
    report_path: &std::path::Path,
) -> std::path::PathBuf {
    if target_path.is_dir() {
        return report_path.with_file_name(".sniff-journal.jsonl");
    }

    let resolved_target = std::fs::canonicalize(target_path)
        .unwrap_or_else(|_| target_path.to_path_buf())
        .to_string_lossy()
        .to_string();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    resolved_target.hash(&mut hasher);
    report_path.with_file_name(format!(".sniff-journal-{:016x}.jsonl", hasher.finish()))
}

fn format_journal_status(
    journal_path: &std::path::Path,
    summary: &crate::analyzer::JournalSummary,
) -> String {
    let remaining = summary
        .expected_units
        .saturating_sub(summary.completed_units);
    let progress = if summary.expected_units == 0 {
        "unknown".to_string()
    } else {
        format!(
            "{:.1}%",
            summary.completed_units as f64 * 100.0 / summary.expected_units as f64
        )
    };
    format!(
        "Journal: {}\nProgress: {}/{} completed ({progress})\nRemaining: {remaining} ({} retryable)\nRole metadata: {}/{} completed ({} retryable)\nFindings so far: {} slop, {} kinda slop, {} unresolved\nUsage so far: {} input, {} cached input, {} output tokens; ${:.4} estimated\nProvider: {} / {}",
        journal_path.display(),
        summary.completed_units,
        summary.expected_units,
        summary.retryable_units,
        summary.completed_role_units,
        summary.expected_role_units,
        summary.retryable_role_units,
        summary.slop,
        summary.kinda_slop,
        summary.unresolved,
        summary.input_tokens,
        summary.cached_input_tokens,
        summary.output_tokens,
        summary.estimated_cost_usd,
        summary.provider.as_deref().unwrap_or("unknown"),
        summary.model.as_deref().unwrap_or("unknown"),
    )
}

pub async fn status(path: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let target_path = std::path::Path::new(path);
    let report_path = report_path_for_target(target_path);
    let journal_path = journal_path_for_target(target_path, &report_path);
    let summary = crate::analyzer::summarize_journal(&journal_path).map_err(IoError::other)?;
    if summary.scan_id.is_none() {
        eprintln!("No Sniff journal found for {}.", target_path.display());
        return Ok(0);
    }

    eprintln!("{}", format_journal_status(&journal_path, &summary));
    Ok(0)
}

pub async fn resume(
    path: &str,
    skip_dotenv: bool,
    assume_yes: bool,
    budget_usd: Option<f64>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let target_path = std::path::Path::new(path);
    let report_path = report_path_for_target(target_path);
    let journal_path = journal_path_for_target(target_path, &report_path);
    if !journal_path.exists() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!(
                "No Sniff journal exists for {}. Start a scan with `sniff {}` first.",
                target_path.display(),
                path
            ),
        )
        .into());
    }

    run(path, skip_dotenv, assume_yes, budget_usd).await
}

fn strip_windows_verbatim_prefix(path: std::path::PathBuf) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{}", rest));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return std::path::PathBuf::from(rest);
    }
    path
}

async fn scan_target(
    path: &str,
    config: &crate::config::ResolvedConfig,
) -> Result<Vec<crate::types::FileRecord>, String> {
    io::scan_files(path, config).await
}

async fn build_run_report(
    path: &str,
    config: &crate::config::ResolvedConfig,
    file_records: &mut [crate::types::FileRecord],
    bar_style: &ProgressStyle,
    journal_path: &std::path::Path,
    budget_usd: Option<f64>,
) -> Result<(RunReport, bool), Box<dyn std::error::Error>> {
    let review = llm::prepare_review_artifacts(
        path,
        config,
        file_records,
        bar_style,
        Some(journal_path),
        budget_usd,
    )
    .await?;

    let stats = stats::generate_stats(stats::StatsInput {
        file_records,
        static_flags: &review.static_flags,
        verdicts: &review.verdicts,
        in_tok: review.in_tok,
        out_tok: review.out_tok,
        cached_in_tok: review.cached_in_tok,
        ai_expected_reviews: review.ai_expected_reviews,
        method_reviews_expected: review.method_reviews_expected,
    });

    if stats.ai_failed_reviews > 0 {
        return Err(IoError::other(format!(
            "AI review incomplete: {} of {} expected reviews did not complete for {path}. Sniff will not write the report.",
            stats.ai_failed_reviews, stats.ai_expected_reviews
        ))
        .into());
    }

    Ok(stats::build_run_report_from_parts(
        file_records,
        review.static_flags,
        review.verdicts,
        stats,
    ))
}

pub async fn run(
    path: &str,
    skip_dotenv: bool,
    assume_yes: bool,
    budget_usd: Option<f64>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let target_path = std::path::Path::new(path);
    let report_path = report_path_for_target(target_path);
    let journal_path = journal_path_for_target(target_path, &report_path);
    env::load_working_dir_env(skip_dotenv).map_err(IoError::other)?;
    env::load_target_env(target_path, skip_dotenv).map_err(IoError::other)?;
    let config = crate::config_loader::resolve_config(target_path)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    crate::roles::clear_file_role_cache();

    eprintln!("Scanning source files...");
    let mut file_records = scan_target(path, &config)
        .await
        .map_err(|err| IoError::other(format!("file scan failed: {err}")))?;

    if file_records.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "No supported source files found. Sniff currently handles Rust, Python, JavaScript/TypeScript, Go, and Kotlin.",
        )
        .into());
    }
    eprintln!("{}", source_inventory_summary(&file_records));
    let estimate = super::preflight::ScanEstimate::from_files(&file_records);
    super::preflight::print_scan_cost_summary(&estimate);
    super::preflight::confirm_expensive_scan(&estimate, assume_yes)?;
    if journal_path.exists() {
        eprintln!("Resuming completed reviews from {}", journal_path.display());
    }
    if !config.llm.endpoint.trim().is_empty() {
        eprintln!("Using LLM endpoint: {}", config.llm.endpoint.trim());
    }
    eprintln!("Preparing report...");
    let bar_style = build_progress_style()
        .map_err(|err| IoError::other(format!("failed to build progress style: {}", err)))?;
    let report_result = build_run_report(
        path,
        &config,
        &mut file_records,
        &bar_style,
        &journal_path,
        budget_usd,
    )
    .await;
    let (run_report, has_issues) = match report_result {
        Ok(report) => report,
        Err(error) if crate::review_journal::is_budget_pause(&error.to_string()) => {
            eprintln!("{error}");
            return Ok(3);
        }
        Err(error) => return Err(error),
    };

    let report_path_text = report_path.to_string_lossy().to_string();
    crate::reporter::render_report(&run_report, &config, Some(&report_path_text))
        .map_err(IoError::other)?;

    Ok(exit_code_for_run(
        has_issues,
        run_report.stats.ai_failed_reviews,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        format_journal_status, journal_path_for_target, report_path_for_target,
        source_inventory_summary, strip_windows_verbatim_prefix,
    };
    use crate::types::{FileRecord, MethodRecord};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn external_nested_target_writes_report_at_repository_root() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-report-root-{nonce}"));
        let nested = root.join("src");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();

        let report_path = report_path_for_target(&nested);
        let expected_root = strip_windows_verbatim_prefix(fs::canonicalize(&root).unwrap());

        assert_eq!(report_path, expected_root.join("sniff-report.md"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_checkpoint_is_isolated_from_directory_checkpoint() {
        let root = std::env::temp_dir().join("sniff-checkpoint-scope-test");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("module.py");
        fs::write(&target, "def run():\n    return 1\n").unwrap();
        let report = root.join("sniff-report.md");

        let path = journal_path_for_target(&target, &report);
        assert_ne!(path, root.join(".sniff-journal.jsonl"));
        assert!(
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.starts_with(".sniff-journal-") && name.ends_with(".jsonl")
                )
        );

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn source_inventory_reports_files_and_methods_before_review() {
        let method = |name: &str| MethodRecord {
            name: name.to_string(),
            file_path: "sample.ts".to_string(),
            source: format!("function {name}() {{}}"),
            loc: 1,
            param_count: 0,
            start_line: 1,
            end_line: 1,
            is_exported: false,
            language: "typescript".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        };
        let files = vec![
            FileRecord {
                file_path: "one.ts".to_string(),
                source: String::new(),
                language: "typescript".to_string(),
                methods: vec![method("one"), method("two")],
            },
            FileRecord {
                file_path: "two.ts".to_string(),
                source: String::new(),
                language: "typescript".to_string(),
                methods: vec![method("three")],
            },
        ];

        assert_eq!(
            source_inventory_summary(&files),
            "Found 2 supported files, 3 methods."
        );
    }

    #[test]
    fn journal_status_is_compact_and_reports_remaining_work() {
        let summary = crate::analyzer::JournalSummary {
            scan_id: Some("scan".to_string()),
            expected_units: 10,
            completed_units: 4,
            retryable_units: 1,
            expected_role_units: 0,
            completed_role_units: 0,
            retryable_role_units: 0,
            slop: 1,
            kinda_slop: 2,
            unresolved: 0,
            input_tokens: 100,
            cached_input_tokens: 60,
            output_tokens: 20,
            estimated_cost_usd: 0.0123,
            provider: Some("openai-compatible".to_string()),
            model: Some("test-model".to_string()),
        };

        let rendered = format_journal_status(std::path::Path::new("journal.jsonl"), &summary);

        assert!(rendered.contains("Progress: 4/10 completed (40.0%)"));
        assert!(rendered.contains("Remaining: 6 (1 retryable)"));
        assert!(rendered.contains("Usage so far: 100 input, 60 cached input, 20 output tokens"));
        assert_eq!(rendered.lines().count(), 7);
    }
}
