use super::{env, io, llm, stats};
use crate::report_types::RunReport;
use indicatif::ProgressStyle;
use std::io::{Error as IoError, ErrorKind};

fn build_progress_styles() -> Result<(ProgressStyle, ProgressStyle), String> {
    let spinner_style = ProgressStyle::default_spinner()
        .tick_chars("/|\\-")
        .template("{spinner:.cyan.bold} {msg}")
        .map_err(|err| err.to_string())?;

    let bar_style = ProgressStyle::default_bar()
        .tick_chars("/|\\-")
        .template("{spinner:.cyan.bold} {msg} [{bar:30.cyan/dim}] {percent}% {elapsed}")
        .map_err(|err| err.to_string())?
        .progress_chars("=>-");

    Ok((spinner_style, bar_style))
}

fn exit_code_for_run(has_issues: bool, ai_failed_reviews: usize) -> i32 {
    if has_issues || ai_failed_reviews > 0 {
        1
    } else {
        0
    }
}

fn report_path_for_target(target_path: &std::path::Path) -> std::path::PathBuf {
    let current_dir = std::env::current_dir().ok();
    let resolved_target = strip_windows_verbatim_prefix(
        std::fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf()),
    );

    if let Some(current_dir) = current_dir
        && resolved_target.starts_with(&current_dir)
    {
        return current_dir.join("sniff-report.md");
    }

    let mut candidate = if resolved_target.is_dir() {
        resolved_target
    } else {
        resolved_target
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    };

    loop {
        if [".git", "Cargo.toml", "pyproject.toml", "package.json"]
            .iter()
            .any(|marker| candidate.join(marker).exists())
        {
            return candidate.join("sniff-report.md");
        }

        let Some(parent) = candidate.parent() else {
            return candidate.join("sniff-report.md");
        };
        if parent == candidate {
            return candidate.join("sniff-report.md");
        }
        candidate = parent.to_path_buf();
    }
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

fn clear_previous_report(report_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::metadata(report_path) {
        Ok(metadata) if metadata.is_file() => {
            std::fs::remove_file(report_path).map_err(|err| {
                IoError::other(format!(
                    "failed to remove stale report {}: {err}",
                    report_path.display()
                ))
            })?;
        }
        Ok(_) => {
            return Err(IoError::other(format!(
                "cannot write report: {} exists and is not a file",
                report_path.display()
            ))
            .into());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(IoError::other(format!(
                "failed to inspect report {}: {err}",
                report_path.display()
            ))
            .into());
        }
    }

    Ok(())
}

async fn scan_target(
    path: &str,
    config: &crate::config::ResolvedConfig,
    spinner_style: &ProgressStyle,
) -> Result<Vec<crate::types::FileRecord>, String> {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(spinner_style.clone());
    pb.set_message("Scanning files...");

    let file_records = io::scan_files(path, config).await;
    pb.finish_and_clear();
    file_records
}

async fn build_run_report(
    path: &str,
    only_files: bool,
    config: &crate::config::ResolvedConfig,
    file_records: &mut [crate::types::FileRecord],
    bar_style: &ProgressStyle,
) -> Result<(RunReport, bool), Box<dyn std::error::Error>> {
    let review =
        llm::prepare_review_artifacts(path, only_files, config, file_records, bar_style).await?;

    let stats = stats::generate_stats(stats::StatsInput {
        file_records,
        static_flags: &review.static_flags,
        verdicts: &review.verdicts,
        in_tok: review.in_tok,
        out_tok: review.out_tok,
        ai_expected_reviews: review.ai_expected_reviews,
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
    verbose: bool,
    only_files: bool,
    skip_dotenv: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let target_path = std::path::Path::new(path);
    let report_path = report_path_for_target(target_path);
    env::load_working_dir_env(skip_dotenv).map_err(IoError::other)?;
    env::load_target_env(target_path, skip_dotenv).map_err(IoError::other)?;
    let config = crate::config_loader::resolve_config(target_path)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    crate::roles::clear_file_role_cache();
    clear_previous_report(&report_path)?;

    let (spinner_style, bar_style) = build_progress_styles()
        .map_err(|err| IoError::other(format!("failed to build progress styles: {}", err)))?;
    eprintln!("Scanning source files...");
    let mut file_records = scan_target(path, &config, &spinner_style)
        .await
        .map_err(|err| IoError::other(format!("file scan failed: {err}")))?;

    if file_records.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "No supported source files found. Sniff currently handles Rust, Python, JavaScript/TypeScript, Go, and Kotlin.",
        )
        .into());
    }
    eprintln!("Found {} supported files.", file_records.len());
    if !config.llm.endpoint.trim().is_empty() {
        eprintln!("Using LLM endpoint: {}", config.llm.endpoint.trim());
    }
    eprintln!("Preparing report...");
    let (run_report, has_issues) =
        build_run_report(path, only_files, &config, &mut file_records, &bar_style).await?;

    eprintln!("Rendering report...");
    let report_path_text = report_path.to_string_lossy().to_string();
    crate::reporter::render_report(&run_report, &config, verbose, Some(&report_path_text))
        .map_err(IoError::other)?;

    Ok(exit_code_for_run(
        has_issues,
        run_report.stats.ai_failed_reviews,
    ))
}

#[cfg(test)]
mod tests {
    use super::report_path_for_target;
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

        assert_eq!(report_path, root.join("sniff-report.md"));
        fs::remove_dir_all(root).unwrap();
    }
}
