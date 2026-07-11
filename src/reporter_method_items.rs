use super::ReportItem;
use super::helpers::{finding_label, format_ai_finding, is_supporting_only_reason};
use crate::types::FindingTier;

#[path = "reporter_emit.rs"]
mod emit;

fn group_method_items<'a>(
    method_items: &'a [&'a ReportItem],
) -> std::collections::HashMap<String, Vec<&'a ReportItem>> {
    let mut m_data: std::collections::HashMap<String, Vec<&ReportItem>> =
        std::collections::HashMap::new();
    for item in method_items {
        if let Some(name) = item.method_name() {
            m_data.entry(name.to_string()).or_default().push(item);
        }
    }
    m_data
}

fn method_span(items: &[&ReportItem]) -> (usize, usize) {
    let start_line = items
        .iter()
        .map(|item| match item {
            ReportItem::Static(f) => f.start_line,
            ReportItem::Verdict(v) => v.start_line,
        })
        .min()
        .unwrap_or(0);

    let end_line = items
        .iter()
        .map(|item| match item {
            ReportItem::Static(f) => f.end_line,
            ReportItem::Verdict(v) => v.end_line,
        })
        .max()
        .unwrap_or(0);

    (start_line, end_line)
}

fn collect_method_reasons(items: &[&ReportItem]) -> Vec<(String, String)> {
    let mut reasons = Vec::new();
    for item in items {
        match item {
            ReportItem::Static(f) => {
                for r in &f.reasons {
                    reasons.push((item.tier().label().to_string(), finding_label(r)));
                }
            }
            ReportItem::Verdict(v) => {
                if v.smelly {
                    reasons.push((item.tier().label().to_string(), format_ai_finding(&v.reason, &v.evidence)));
                }
            }
        }
    }
    reasons
}

pub(super) fn render_method_items(
    method_items: &[&ReportItem],
    out: bool,
    verbose: bool,
    md_lines: &mut Vec<String>,
) {
    let m_data = group_method_items(method_items);
    let mut keys: Vec<&String> = m_data.keys().collect();
    keys.sort();

    for name in keys {
        let items = &m_data[name];
        let tier = items
            .first()
            .map(|item| item.tier())
            .unwrap_or(FindingTier::Clean);
        if matches!(tier, FindingTier::KindaSlop) && (out || !verbose) {
            continue;
        }
        if matches!(tier, FindingTier::Clean) && !verbose {
            continue;
        }
        let (start_line, end_line) = method_span(items);
        let reasons = collect_method_reasons(items)
            .into_iter()
            .filter(|(_, reason)| !is_supporting_only_reason(reason))
            .collect::<Vec<_>>();
        if reasons.is_empty() {
            continue;
        }
        emit::emit_method_reasons(emit::MethodRender {
            name,
            start_line,
            end_line,
            reasons: &reasons,
            mode: emit::RenderMode {
                out,
                verbose,
                md_lines,
            },
        });
    }
}
