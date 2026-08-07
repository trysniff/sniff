use crate::report_types::{LLMVerdict, RunReport};
use crate::types::FindingTier;
use std::io::Write;

use super::summary::append_footer;

pub(super) fn write_markdown_report(
    run_report: &RunReport,
    out_path: &str,
    cost_str: &str,
) -> Result<(), String> {
    validate_method_report_contract(run_report)?;
    let mut md_lines = vec!["# Sniff Report".to_string(), "".to_string()];
    let method_verdicts = run_report
        .llm_verdicts
        .iter()
        .filter(|verdict| verdict.check_type == "method")
        .collect::<Vec<_>>();
    if method_verdicts.is_empty() && run_report.stats.method_reviews_expected == 0 {
        render_file_only_findings(run_report, &mut md_lines);
    } else {
        render_method_tier(
            &method_verdicts,
            FindingTier::Slop,
            "Slop Findings",
            None,
            &mut md_lines,
        );
        render_method_tier(
            &method_verdicts,
            FindingTier::KindaSlop,
            "Kinda Slop Findings",
            Some("_These are proven unnecessary, local or minor sources of friction._"),
            &mut md_lines,
        );
        render_method_tier(
            &method_verdicts,
            FindingTier::Unresolved,
            "Unresolved Reviews",
            Some(
                "_The evidence ladder could not establish a trustworthy verdict. Do not edit from these entries._",
            ),
            &mut md_lines,
        );
    }
    append_footer(
        &mut md_lines,
        &run_report.stats,
        &run_report.llm_verdicts,
        cost_str,
    );
    let mut f = std::fs::File::create(out_path)
        .map_err(|err| format!("failed to create report file {out_path}: {}", err))?;
    f.write_all(md_lines.join("\n").as_bytes())
        .map_err(|err| format!("failed to write report file {out_path}: {}", err))?;
    Ok(())
}

fn validate_method_report_contract(run_report: &RunReport) -> Result<(), String> {
    for verdict in run_report
        .llm_verdicts
        .iter()
        .filter(|verdict| verdict.check_type == "method")
    {
        let method_name = verdict
            .method_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "method report gate rejected {}:{}: missing method name",
                    verdict.file_path, verdict.start_line
                )
            })?;
        match verdict.tier {
            FindingTier::Slop | FindingTier::KindaSlop => {
                if verdict.evidence.trim().is_empty() {
                    return Err(format!(
                        "method report gate rejected {}::{method_name}: non-clean verdict has no exact source evidence",
                        verdict.file_path
                    ));
                }
                for marker in [
                    "Simplification:",
                    "Contract impact:",
                    "Dependency proof:",
                    "Necessity proof:",
                ] {
                    if !verdict.reason.contains(marker) {
                        return Err(format!(
                            "method report gate rejected {}::{method_name}: missing {marker}",
                            verdict.file_path
                        ));
                    }
                }
            }
            FindingTier::Unresolved => {
                if !verdict.reason.contains("Missing evidence:")
                    || verdict
                        .reason
                        .split_once("Missing evidence:")
                        .is_none_or(|(_, missing)| missing.trim().is_empty())
                {
                    return Err(format!(
                        "method report gate rejected {}::{method_name}: unresolved verdict has no explicit missing evidence",
                        verdict.file_path
                    ));
                }
            }
            FindingTier::Clean => {}
        }
    }
    Ok(())
}

fn render_method_tier(
    verdicts: &[&LLMVerdict],
    tier: FindingTier,
    heading: &str,
    note: Option<&str>,
    md_lines: &mut Vec<String>,
) {
    let matching = verdicts
        .iter()
        .copied()
        .filter(|verdict| verdict.tier == tier)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return;
    }

    md_lines.push(format!("## {heading}"));
    md_lines.push(String::new());
    if let Some(note) = note {
        md_lines.push(note.to_string());
        md_lines.push(String::new());
    }
    for verdict in matching {
        render_method_verdict_markdown(verdict, md_lines);
    }
}

fn render_method_verdict_markdown(verdict: &LLMVerdict, md_lines: &mut Vec<String>) {
    let method_name = verdict.method_name.as_deref().unwrap_or("<unknown>");
    md_lines.push(format!("### `{}` :: `{method_name}`", verdict.file_path));
    md_lines.push(String::new());
    md_lines.push(format!("- **Verdict:** `{}`", verdict.tier.label()));
    md_lines.push(format!(
        "- **Lines:** `{}-{}`",
        verdict.start_line, verdict.end_line
    ));
    md_lines.push(format!("- **Why:** {}", verdict.reason));
    if verdict.tier != FindingTier::Unresolved {
        md_lines.push("- **Exact evidence:**".to_string());
        md_lines.push("```text".to_string());
        md_lines.push(verdict.evidence.clone());
        md_lines.push("```".to_string());
    }
    md_lines.push(String::new());
}

fn render_file_only_findings(run_report: &RunReport, md_lines: &mut Vec<String>) {
    for (tier, heading, note) in [
        (FindingTier::Slop, "Slop Findings", None),
        (
            FindingTier::KindaSlop,
            "Kinda Slop Findings",
            Some("_These are proven unnecessary, local or minor sources of friction._"),
        ),
        (
            FindingTier::Unresolved,
            "Unresolved Reviews",
            Some(
                "_The evidence ladder could not establish a trustworthy verdict. Do not edit from these entries._",
            ),
        ),
    ] {
        let matching = run_report
            .file_verdicts
            .iter()
            .filter(|verdict| verdict.verdict == tier)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        md_lines.push(format!("## {heading}"));
        md_lines.push(String::new());
        if let Some(note) = note {
            md_lines.push(note.to_string());
            md_lines.push(String::new());
        }
        for verdict in matching {
            render_file_verdict_markdown(verdict, md_lines);
        }
    }
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

    if verdict.verdict == crate::types::FindingTier::Unresolved {
        md_lines.push(String::new());
        return;
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
    use crate::report_types::{FileVerdict, LLMVerdict, RunReport, RunStats};
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

    fn method_verdict(tier: FindingTier) -> LLMVerdict {
        LLMVerdict {
            verdict_type: "method".to_string(),
            file_path: "src/demo.py".to_string(),
            method_name: Some("demo".to_string()),
            check_type: "method".to_string(),
            smelly: matches!(tier, FindingTier::Slop | FindingTier::KindaSlop),
            tier,
            cohesive: None,
            name_accurate: None,
            evidence: "if enabled:\n    return value".to_string(),
            reason: if tier == FindingTier::Unresolved {
                "The contract is unknown. Missing evidence: external consumers".to_string()
            } else {
                "ceremonial logic: both paths agree. Simplification: return value directly. Contract impact: signature and behavior stay unchanged. Dependency proof: no caller or seam depends on the branch. Necessity proof: the branch has no distinct purpose.".to_string()
            },
            loc: 3,
            start_line: 10,
            end_line: 12,
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
            method_review_records: vec![],
            slop_cases: vec![],
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
        assert!(md.contains("proven unnecessary"));
    }

    #[test]
    fn markdown_report_does_not_turn_unresolved_into_edit_advice() {
        let report = RunReport {
            file_verdicts: vec![verdict("unknown.rs", FindingTier::Unresolved)],
            static_flags: vec![],
            llm_verdicts: vec![],
            method_review_records: vec![],
            slop_cases: vec![],
            stats: RunStats {
                files_scanned: 1,
                methods_analyzed: 1,
                ..RunStats::default()
            },
        };
        let out_path = temp_report_path();

        write_markdown_report(&report, &out_path, "$0.00").unwrap();
        let md = fs::read_to_string(&out_path).unwrap();
        let _ = fs::remove_file(&out_path);

        assert!(md.contains("evidence ladder could not establish a trustworthy verdict"));
        assert!(!md.contains("**Action:**"));
        assert!(!md.contains("**Flagged methods:**"));
        assert!(!md.contains("**Recommended action:**"));
    }

    #[test]
    fn markdown_report_renders_each_method_with_its_proof() {
        let report = RunReport {
            file_verdicts: vec![verdict("src/demo.py", FindingTier::Slop)],
            static_flags: vec![],
            llm_verdicts: vec![method_verdict(FindingTier::Slop)],
            method_review_records: vec![],
            slop_cases: vec![],
            stats: RunStats {
                files_scanned: 1,
                methods_analyzed: 1,
                method_reviews_expected: 1,
                method_reviews_completed: 1,
                ..RunStats::default()
            },
        };
        let out_path = temp_report_path();

        write_markdown_report(&report, &out_path, "$0.00").unwrap();
        let md = fs::read_to_string(&out_path).unwrap();
        let _ = fs::remove_file(&out_path);

        assert!(md.contains("## Slop Findings"));
        assert!(md.contains("`src/demo.py` :: `demo`"));
        assert!(md.contains("**Lines:** `10-12`"));
        assert!(md.contains("Simplification: return value directly"));
        assert!(md.contains("if enabled:"));
    }

    #[test]
    fn report_gate_rejects_unproven_non_clean_methods() {
        let mut unproven = method_verdict(FindingTier::KindaSlop);
        unproven.reason = "This feels mildly indirect.".to_string();
        let report = RunReport {
            file_verdicts: vec![],
            static_flags: vec![],
            llm_verdicts: vec![unproven],
            method_review_records: vec![],
            slop_cases: vec![],
            stats: RunStats {
                method_reviews_expected: 1,
                ..RunStats::default()
            },
        };
        let out_path = temp_report_path();

        let error = write_markdown_report(&report, &out_path, "$0.00").unwrap_err();

        assert!(error.contains("missing Simplification:"));
        assert!(!std::path::Path::new(&out_path).exists());
    }
}
