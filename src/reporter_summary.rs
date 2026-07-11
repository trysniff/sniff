use crate::report_types::{FileVerdict, RunStats};
use crate::types::FindingTier;
use colored::Colorize;

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

pub(super) fn print_summary(s: &RunStats, file_verdicts: &[FileVerdict], cost_str: &str) {
    let (kinda, slop) = verdict_counts(file_verdicts);
    println!(
        "\n{}",
        "--------------------------------------------------------".dimmed()
    );
    println!(
        "{}",
        format!(
            "  {} files - {} methods",
            s.files_scanned, s.methods_analyzed
        )
        .dimmed()
    );
    println!(
        "{}",
        format!(
            "  ai coverage: {} of {} expected reviews completed, {} missed",
            s.ai_reviews, s.ai_expected_reviews, s.ai_failed_reviews
        )
        .dimmed()
    );
    println!(
        "{}",
        format!("  slop findings: {} slop - {} kinda slop", slop, kinda).dimmed()
    );
    println!("{}", format!("  estimated cost: {}", cost_str).dimmed());
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
