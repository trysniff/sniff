use colored::Colorize;

pub(super) fn render_console_report(run_report: &crate::report_types::RunReport, verbose: bool) {
    for verdict in &run_report.file_verdicts {
        render_file_verdict_console(verdict, verbose);
    }
}

pub(super) fn render_file_verdict_console(
    verdict: &crate::report_types::FileVerdict,
    verbose: bool,
) {
    if !should_render_file_verdict_console(verdict, verbose) {
        return;
    }

    println!(
        "{}",
        format!(
            "{}  [{}] {}",
            verdict.file_path,
            verdict.role,
            verdict.verdict.label()
        )
        .bold()
    );

    if verdict.verdict == crate::types::FindingTier::Clean {
        println!("  {}", "clean".green());
        if verbose {
            println!("  {}", "clean items remain short by default".dimmed());
        }
        return;
    }

    if !verdict.top_reasons.is_empty() {
        println!("  {}", "Top reasons:".dimmed());
        for reason in &verdict.top_reasons {
            println!("    - {}", reason);
        }
    }

    if !verdict.flagged_methods.is_empty() {
        println!(
            "  {} {}",
            "Methods:".dimmed(),
            verdict.flagged_methods.join(", ")
        );
    }

    println!(
        "  {} {}",
        "Recommended:".dimmed(),
        verdict.recommended_action
    );
}

pub(super) fn should_render_file_verdict_console(
    verdict: &crate::report_types::FileVerdict,
    verbose: bool,
) -> bool {
    match verdict.verdict {
        crate::types::FindingTier::Slop => true,
        crate::types::FindingTier::KindaSlop => verbose,
        crate::types::FindingTier::Clean => verbose,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_types::FileVerdict;
    use crate::types::FindingTier;

    fn verdict(tier: FindingTier) -> FileVerdict {
        FileVerdict {
            file_path: "sample.rs".to_string(),
            role: "core_library".to_string(),
            verdict: tier,
            top_reasons: vec![],
            flagged_methods: vec![],
            recommended_action: "trim the largest offender and keep the file focused".to_string(),
        }
    }

    #[test]
    fn console_filters_kindaslop_by_default() {
        assert!(should_render_file_verdict_console(
            &verdict(FindingTier::Slop),
            false
        ));
        assert!(!should_render_file_verdict_console(
            &verdict(FindingTier::KindaSlop),
            false
        ));
        assert!(!should_render_file_verdict_console(
            &verdict(FindingTier::Clean),
            false
        ));
    }

    #[test]
    fn console_shows_borderline_entries_in_verbose_mode() {
        assert!(should_render_file_verdict_console(
            &verdict(FindingTier::Slop),
            true
        ));
        assert!(should_render_file_verdict_console(
            &verdict(FindingTier::KindaSlop),
            true
        ));
        assert!(should_render_file_verdict_console(
            &verdict(FindingTier::Clean),
            true
        ));
    }
}
