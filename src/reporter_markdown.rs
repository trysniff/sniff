use crate::report_types::RunReport;
use std::io::Write;

use super::summary::append_footer;

pub(super) fn write_markdown_report(
    run_report: &RunReport,
    out_path: &str,
    cost_str: &str,
) -> Result<(), String> {
    let mut md_lines = vec!["# Sniff Report".to_string(), "".to_string()];
    let mut kinda_count = 0usize;
    for verdict in &run_report.file_verdicts {
        match verdict.verdict {
            crate::types::FindingTier::Slop => render_file_verdict_markdown(verdict, &mut md_lines),
            crate::types::FindingTier::KindaSlop => {
                kinda_count += 1;
            }
            crate::types::FindingTier::Clean => {}
        }
    }
    if kinda_count > 0 {
        md_lines.push("## Kinda Slop Findings".to_string());
        md_lines.push(String::new());
        md_lines.push(
            "_These are mild slop signals that did not clear the main slop threshold._".to_string(),
        );
        md_lines.push(String::new());
        for verdict in &run_report.file_verdicts {
            if verdict.verdict == crate::types::FindingTier::KindaSlop {
                render_file_verdict_markdown(verdict, &mut md_lines);
            }
        }
        md_lines.push(String::new());
    }
    append_footer(
        &mut md_lines,
        &run_report.stats,
        &run_report.file_verdicts,
        cost_str,
    );
    let mut f = std::fs::File::create(out_path)
        .map_err(|err| format!("failed to create report file {out_path}: {}", err))?;
    f.write_all(md_lines.join("\n").as_bytes())
        .map_err(|err| format!("failed to write report file {out_path}: {}", err))?;
    Ok(())
}

pub(super) fn render_file_verdict_markdown(
    verdict: &crate::report_types::FileVerdict,
    md_lines: &mut Vec<String>,
) {
    if verdict.verdict == crate::types::FindingTier::Clean {
        return;
    }

    md_lines.push(format!("## `{}`", verdict.file_path));
    md_lines.push(String::new());
    md_lines.push(format!("- **Role:** `{}`", verdict.role));
    md_lines.push(format!("- **Verdict:** `{}`", verdict.verdict.label()));

    if !verdict.top_reasons.is_empty() {
        md_lines.push("- **Top reasons:**".to_string());
        for reason in &verdict.top_reasons {
            md_lines.push(format!("  - {}", reason));
        }
    }

    if !verdict.flagged_methods.is_empty() {
        md_lines.push(format!(
            "- **Flagged methods:** {}",
            verdict
                .flagged_methods
                .iter()
                .map(|method| format!("`{}`", method))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    md_lines.push(format!(
        "- **Recommended action:** {}",
        verdict.recommended_action
    ));
    md_lines.push(String::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_types::{FileVerdict, RunReport, RunStats};
    use crate::types::FindingTier;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_report_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("sniff-markdown-report-{nanos}.md"))
            .to_string_lossy()
            .to_string()
    }

    fn verdict(file_path: &str, tier: FindingTier) -> FileVerdict {
        FileVerdict {
            file_path: file_path.to_string(),
            role: "core_library".to_string(),
            verdict: tier,
            top_reasons: vec!["reason".to_string()],
            flagged_methods: vec!["sample".to_string()],
            recommended_action: "trim the largest offender and keep the file focused".to_string(),
        }
    }

    #[test]
    fn markdown_report_shows_kinda_slop_appendix() {
        let report = RunReport {
            file_verdicts: vec![
                verdict("slop.rs", FindingTier::Slop),
                verdict("borderline.rs", FindingTier::KindaSlop),
            ],
            static_flags: vec![],
            llm_verdicts: vec![],
            stats: RunStats {
                files_scanned: 2,
                methods_analyzed: 2,
                ..RunStats::default()
            },
        };
        let out_path = temp_report_path();

        write_markdown_report(&report, &out_path, "$0.00").unwrap();
        let md = fs::read_to_string(&out_path).unwrap();
        let _ = fs::remove_file(&out_path);

        assert!(md.contains("slop.rs"));
        assert!(md.contains("borderline.rs"));
        assert!(md.contains("Kinda Slop Findings"));
        assert!(md.contains("mild slop signals"));
    }
}
