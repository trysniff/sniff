#[path = "scorer_name_utils.rs"]
mod name_utils;

use crate::config::ResolvedConfig;
use crate::language_adapter::LanguageAdapter;
use crate::types::MethodRecord;

pub(crate) fn is_generic(
    method_name: &str,
    config: &ResolvedConfig,
    adapter: &LanguageAdapter,
) -> bool {
    name_utils::is_generic(method_name, config, adapter)
}

pub(crate) fn score_method_reasons(
    method: &MethodRecord,
    config: &ResolvedConfig,
    adapter: &LanguageAdapter,
) -> Vec<String> {
    let mut m_reasons = Vec::new();

    if method.loc > config.thresholds.max_loc {
        m_reasons.push(format!(
            "function is too big ({} LOC > {})",
            method.loc, config.thresholds.max_loc
        ));
    }
    if method.nesting_depth > config.thresholds.max_nesting {
        m_reasons.push(format!(
            "control flow is tangled (nesting {} > {})",
            method.nesting_depth, config.thresholds.max_nesting
        ));
    }
    if method.param_count > config.thresholds.max_params {
        m_reasons.push(format!(
            "too many parameters ({} params > {})",
            method.param_count, config.thresholds.max_params
        ));
    }
    if is_generic(&method.name, config, adapter) {
        m_reasons.push("name is vague".to_string());
    }

    let (branch_lines, loop_lines) = super::control_flow::control_flow_line_counts(&method.source);
    if branch_lines >= 3 && loop_lines >= 2 {
        let tangled_cutoff = (config.thresholds.max_loc / 4).max(12);
        if method.loc <= tangled_cutoff {
            m_reasons.push(format!(
                "control flow is tangled ({} branches, {} loops)",
                branch_lines, loop_lines
            ));
        } else {
            m_reasons.push(format!("branchy control flow ({} branches)", branch_lines));
            m_reasons.push(format!("loop-heavy control flow ({} loops)", loop_lines));
        }
    } else {
        if branch_lines >= 3 {
            m_reasons.push(format!("branchy control flow ({} branches)", branch_lines));
        }
        if loop_lines >= 2 {
            m_reasons.push(format!("loop-heavy control flow ({} loops)", loop_lines));
        }
    }

    m_reasons
}
