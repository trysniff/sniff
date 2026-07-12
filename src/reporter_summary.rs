use crate::report_types::{FileVerdict, RunStats};
use crate::types::FindingTier;

fn verdict_counts(file_verdicts: &[FileVerdict]) -> (usize, usize) {
    let kinda = file_verdicts
        .iter()
        .filter(|verdict| verdict.verdict == FindingTier::KindaSlop)
        .count();
    let slop = file_verdicts
        .iter()
        .filter(|verdict| verdict.verdict == FindingTier::Slop)
        .count();
    (kinda, slop)
}

pub(super) fn append_footer(
    md_lines: &mut Vec<String>,
    s: &RunStats,
    file_verdicts: &[FileVerdict],
    cost_str: &str,
) {
    let (kinda, slop) = verdict_counts(file_verdicts);
    md_lines.extend(vec![
        "---".to_string(),
        format!(
            "**Scanned:** {} files, {} methods",
            s.files_scanned, s.methods_analyzed
        ),
        format!(
            "**AI coverage:** {} of {} expected reviews completed, {} missed",
            s.ai_reviews, s.ai_expected_reviews, s.ai_failed_reviews
        ),
        format!("**Slop findings:** {} slop | {} kinda slop", slop, kinda),
        "**Note:** verdict counts come from final merged file verdicts, not raw signals."
            .to_string(),
        format!("**Est. Cost:** {}", cost_str),
    ]);
}

pub(super) fn print_summary(
    s: &RunStats,
    file_verdicts: &[FileVerdict],
    cost_str: &str,
    out: Option<&str>,
) {
    let (kinda, slop) = verdict_counts(file_verdicts);
    println!("Report written to {}", out.unwrap_or("sniff-report.md"));
    println!("Findings: {} Slop, {} Kinda Slop", slop, kinda);

    let affected = file_verdicts
        .iter()
        .filter(|verdict| verdict.verdict != FindingTier::Clean)
        .collect::<Vec<_>>();
    if affected.is_empty() {
        println!("Affected files: none");
    } else {
        println!("Affected files:");
        for verdict in affected {
            let methods = if verdict.flagged_methods.is_empty() {
                "file-level".to_string()
            } else {
                verdict.flagged_methods.join(", ")
            };
            println!("  {}: {}", verdict.file_path, methods);
        }
    }

    println!(
        "Scanned: {} files, {} methods | AI: {}/{} | Est. cost: {}",
        s.files_scanned, s.methods_analyzed, s.ai_reviews, s.ai_expected_reviews, cost_str
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_types::FileVerdict;
    use crate::types::FindingTier;

    fn verdict(file_path: &str, tier: FindingTier) -> FileVerdict {
        FileVerdict {
            file_path: file_path.to_string(),
            role: "core_library".to_string(),
            verdict: tier,
            top_reasons: vec![],
            flagged_methods: vec![],
            recommended_action: "trim the largest offender and keep the file focused".to_string(),
        }
    }

    #[test]
    fn footer_counts_final_verdicts() {
        let mut lines = Vec::new();
        let stats = RunStats {
            files_scanned: 3,
            methods_analyzed: 7,
            ai_reviews: 3,
            ai_expected_reviews: 3,
            ai_failed_reviews: 0,
            ..RunStats::default()
        };
        let file_verdicts = vec![
            verdict("a.rs", FindingTier::Clean),
            verdict("b.rs", FindingTier::KindaSlop),
            verdict("c.rs", FindingTier::Slop),
        ];

        append_footer(&mut lines, &stats, &file_verdicts, "$0.00");

        assert!(
            lines
                .iter()
                .any(|line| line.contains("**Slop findings:** 1 slop | 1 kinda slop")),
            "unexpected footer lines: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line
                .contains("**AI coverage:** 3 of 3 expected reviews completed, 0 missed")),
            "unexpected footer lines: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .all(|line| !line.contains("AI Reviews") && !line.contains("AI Failures")),
            "unexpected AI bookkeeping in footer lines: {lines:?}"
        );
    }
}
