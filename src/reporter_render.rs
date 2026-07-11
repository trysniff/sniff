use crate::config::ResolvedConfig;
use crate::report_types::RunReport;

use super::console::render_console_report;
use super::cost::calculate_cost;
use super::markdown::write_markdown_report;
use super::summary::print_summary;

pub fn render_report(
    run_report: &RunReport,
    config: &ResolvedConfig,
    verbose: bool,
    out: Option<&str>,
) -> Result<(), String> {
    let cost_str = calculate_cost(&run_report.stats, config);
    render_console_report(run_report, verbose);

    if let Some(out_path) = out {
        write_markdown_report(run_report, out_path, &cost_str)?;
    }

    print_summary(&run_report.stats, &run_report.file_verdicts, &cost_str);
    Ok(())
}
