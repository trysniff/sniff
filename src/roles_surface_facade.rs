use crate::roles::file_name;
use crate::types::{FileRecord, MethodRecord};

pub fn is_detector_facade_module(file: &FileRecord) -> bool {
    let normalized = crate::roles::normalize_path(&file.file_path);
    let name = file_name(&normalized);
    let looks_like_detector = name.ends_with("_detector.py")
        || name.ends_with("_finder.py")
        || name.ends_with("_pipeline.py");
    looks_like_detector
        && file.methods.len() == 1
        && file
            .methods
            .iter()
            .all(|method| method.name.starts_with("run_") || method.name.starts_with("detect_"))
}

pub fn is_thin_wrapper_export(method: &MethodRecord) -> bool {
    let source = method.source.trim();
    if source.is_empty() || method.loc > 30 {
        return false;
    }

    let lowered = source.to_lowercase();
    let has_import = lowered.contains("from ") || lowered.contains(" import ");
    let has_return = lowered.contains("return ");
    let returns_alias = lowered.contains("return _");
    let has_control_flow = lowered.contains("if ")
        || lowered.contains("match ")
        || lowered.contains("for ")
        || lowered.contains("while ");

    has_import && has_return && returns_alias && !has_control_flow
}

pub fn is_call_like_delegation_expression(expr: &str) -> bool {
    let lowered = expr.to_lowercase();
    if lowered.is_empty()
        || lowered.contains(" if ")
        || lowered.contains(" for ")
        || lowered.contains(" while ")
        || lowered.contains(" match ")
        || lowered.contains(" try ")
        || lowered.contains(" except ")
        || lowered.contains(" catch ")
        || lowered.contains(" lambda ")
        || lowered.contains("buildstring")
        || lowered.contains("buildlist")
        || lowered.contains("buildmap")
        || lowered.contains("buildset")
        || lowered.contains("apply {")
        || lowered.contains("also {")
        || lowered.contains("let {")
        || lowered.contains("run {")
        || lowered.contains("with(")
        || expr.contains('{')
        || expr.contains('}')
    {
        return false;
    }

    expr.contains('(') || expr.contains("::")
}

pub fn is_thin_delegation_method(method: &MethodRecord) -> bool {
    let source = method.source.trim();
    if source.is_empty() || method.loc > 50 {
        return false;
    }

    let meaningful_lines: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("\"\"\"")
                && !line.starts_with("'''")
        })
        .collect();

    if meaningful_lines.len() == 1 {
        let line = meaningful_lines[0].trim();
        if let Some(return_expr) = line.strip_prefix("return ") {
            return is_call_like_delegation_expression(return_expr.trim().trim_end_matches(';'));
        }

        if let Some(eq_index) = line.rfind('=') {
            let Some(fun_index) = line.find("fun ") else {
                return false;
            };
            let Some(close_paren_index) = line.rfind(')') else {
                return false;
            };
            if eq_index < close_paren_index && eq_index > fun_index {
                let expression = line[eq_index + 1..].trim().trim_end_matches(';');
                return is_call_like_delegation_expression(expression);
            }
        }

        return false;
    }

    if let Some(return_line) = meaningful_lines
        .iter()
        .rev()
        .find(|line| line.trim_start().starts_with("return "))
        .copied()
        && let Some(return_expr) = return_line.strip_prefix("return ")
        && is_call_like_delegation_expression(return_expr.trim().trim_end_matches(';'))
    {
        return true;
    }

    let lowered = source.to_lowercase();
    if lowered.contains("fun ")
        && let Some(eq_index) = source.rfind('=')
    {
        let expression = source[eq_index + 1..].replace('\n', " ");
        if is_call_like_delegation_expression(expression.trim().trim_end_matches(';')) {
            return true;
        }
    }

    false
}
