use crate::report_types::{LLMVerdict, RunStats};
use crate::types::FindingTier;

fn verdict_counts(verdicts: &[LLMVerdict]) -> (usize, usize, usize) {
    let method_verdicts = verdicts
        .iter()
        .filter(|verdict| verdict.check_type == "method")
        .collect::<Vec<_>>();
    let kinda = method_verdicts
        .iter()
        .filter(|verdict| verdict.tier == FindingTier::KindaSlop)
        .count();
    let slop = method_verdicts
        .iter()
        .filter(|verdict| verdict.tier == FindingTier::Slop)
        .count();
    let unresolved = method_verdicts
        .iter()
        .filter(|verdict| verdict.tier == FindingTier::Unresolved)
        .count();
    (kinda, slop, unresolved)
}

pub(super) fn append_footer(
    md_lines: &mut Vec<String>,
    s: &RunStats,
    verdicts: &[LLMVerdict],
    cost_str: &str,
) {
    let (kinda, slop, unresolved) = verdict_counts(verdicts);
    let unresolved_summary = if unresolved == 0 {
        "**Unresolved reviews:** 0".to_string()
    } else {
        format!(
            "**Unresolved reviews:** {} (evidence was insufficient; this is not a clean result)",
            unresolved
        )
    };
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
        format!(
            "**Method review coverage:** {} of {} methods completed, {} missed",
            s.method_reviews_completed, s.method_reviews_expected, s.method_review_failures
        ),
        format!("**Slop findings:** {} slop | {} kinda slop", slop, kinda),
        unresolved_summary,
        "**Note:** verdict counts come from exhaustive AI method reviews, not static signals or file-level summaries.".to_string(),
        format!("**Est. Cost:** {}", cost_str),
    ]);
}

pub(super) fn print_summary(
    s: &RunStats,
    verdicts: &[LLMVerdict],
    cost_str: &str,
    out: Option<&str>,
) {
    let (kinda, slop, unresolved) = verdict_counts(verdicts);
    println!("Report written to {}", out.unwrap_or("sniff-report.md"));
    println!(
        "Findings: {} Slop, {} Kinda Slop, {} Unresolved",
        slop, kinda, unresolved
    );

    println!(
        "Scanned: {} files, {} methods | AI methods: {}/{} | Est. cost: {}",
        s.files_scanned,
        s.methods_analyzed,
        s.method_reviews_completed,
        s.method_reviews_expected,
        cost_str
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_types::LLMVerdict;
    use crate::types::FindingTier;

    fn verdict(file_path: &str, tier: FindingTier) -> LLMVerdict {
        LLMVerdict {
            verdict_type: "method".to_string(),
            file_path: file_path.to_string(),
            method_name: Some("sample".to_string()),
            check_type: "method".to_string(),
            smelly: matches!(tier, FindingTier::Slop | FindingTier::KindaSlop),
            tier,
            cohesive: None,
            name_accurate: None,
            evidence: String::new(),
            reason: String::new(),
            loc: 1,
            start_line: 1,
            end_line: 1,
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
        let verdicts = vec![
            verdict("a.rs", FindingTier::Clean),
            verdict("b.rs", FindingTier::KindaSlop),
            verdict("c.rs", FindingTier::Slop),
        ];

        append_footer(&mut lines, &stats, &verdicts, "$0.00");

        assert!(
            lines
                .iter()
                .any(|line| line.contains("**Slop findings:** 1 slop | 1 kinda slop")),
            "unexpected footer lines: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line == "**Unresolved reviews:** 0"),
            "unexpected unresolved summary: {lines:?}"
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

    #[test]
    fn footer_warns_only_when_reviews_are_unresolved() {
        let mut lines = Vec::new();
        append_footer(
            &mut lines,
            &RunStats::default(),
            &[verdict("a.rs", FindingTier::Unresolved)],
            "$0.00",
        );

        assert!(lines.iter().any(|line| {
            line == "**Unresolved reviews:** 1 (evidence was insufficient; this is not a clean result)"
        }));
    }
}
