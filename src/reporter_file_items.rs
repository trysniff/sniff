use super::ReportItem;
use super::helpers::{finding_label, format_ai_finding, is_supporting_only_reason};
use crate::types::FindingTier;
use colored::Colorize;

fn should_render_item(item: &ReportItem, out: bool, verbose: bool) -> bool {
    if matches!(item.tier(), FindingTier::KindaSlop) && (out || !verbose) {
        return false;
    }
    !(matches!(item.tier(), FindingTier::Clean) && !verbose)
}

fn render_static_item(
    item: &ReportItem,
    flag: &crate::report_types::StaticFlag,
    out: bool,
    md_lines: &mut Vec<String>,
) -> bool {
    let visible_reasons: Vec<&String> = flag
        .reasons
        .iter()
        .filter(|reason| !is_supporting_only_reason(reason))
        .collect();
    if visible_reasons.is_empty() {
        return false;
    }

    for reason in visible_reasons {
        let label = finding_label(reason);
        if out {
            md_lines.push(format!("- [{}] {}", item.tier().label(), label));
        } else {
            println!("  {}  [{}] {}", "!".yellow(), item.tier().label(), label);
        }
    }
    true
}

fn render_ai_item(
    item: &ReportItem,
    verdict: &crate::report_types::LLMVerdict,
    out: bool,
    verbose: bool,
    md_lines: &mut Vec<String>,
) -> bool {
    if verdict.smelly {
        let finding = format_ai_finding(&verdict.reason, &verdict.evidence);
        if out {
            md_lines.push(format!("- [{}] {}", item.tier().label(), finding));
        } else {
            println!("  {}  [{}] {}", "!".yellow(), item.tier().label(), finding);
        }
        return true;
    }

    if verbose && !out {
        println!("  {}  file is clean", "OK".green());
    }
    false
}

pub(super) fn render_file_items(
    file_items: &[&ReportItem],
    out: bool,
    verbose: bool,
    md_lines: &mut Vec<String>,
) {
    let mut rendered_any = false;
    for item in file_items {
        if !should_render_item(item, out, verbose) {
            continue;
        }
        match item {
            ReportItem::Static(flag) => {
                rendered_any |= render_static_item(item, flag, out, md_lines);
            }
            ReportItem::Verdict(verdict) => {
                rendered_any |= render_ai_item(item, verdict, out, verbose, md_lines);
            }
        }
    }

    if !rendered_any && verbose && !out {
        println!("  {}  no core slop signals", "OK".green());
    }
}
