use crate::report_types::StaticFlag;
use crate::types::{FindingTier, MethodRecord};

pub(crate) fn make_method_flag(
    method: &MethodRecord,
    reason: String,
    tier: FindingTier,
    gate: &str,
) -> StaticFlag {
    StaticFlag {
        flag_type: "method".to_string(),
        file_path: method.file_path.clone(),
        method_name: Some(method.name.clone()),
        reasons: vec![reason],
        tier,
        gate: gate.to_string(),
        loc: method.loc,
        start_line: method.start_line,
        end_line: method.end_line,
    }
}

pub(crate) fn make_file_flag(
    file_path: &str,
    reason: String,
    tier: FindingTier,
    gate: &str,
) -> StaticFlag {
    StaticFlag {
        flag_type: "file".to_string(),
        file_path: file_path.to_string(),
        method_name: None,
        reasons: vec![reason],
        tier,
        gate: gate.to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    }
}
