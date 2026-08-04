use crate::config::ResolvedConfig;
use crate::report_types::RunReport;

use super::cost::calculate_cost;
use super::markdown::write_markdown_report;
use super::summary::print_summary;

pub fn render_report(
    run_report: &RunReport,
    config: &ResolvedConfig,
    out: Option<&str>,
) -> Result<(), String> {
    let cost_str = calculate_cost(&run_report.stats, config);

    if let Some(out_path) = out {
        write_markdown_report(run_report, out_path, &cost_str)?;
    }

    print_summary(&run_report.stats, &run_report.llm_verdicts, &cost_str, out);
    Ok(())
}
