use crate::report_types::StaticFlag;
use crate::roles::FileRole;
use crate::types::FindingTier;

use super::similarity_duplicates::{PreparedMethod, best_previous_match};
use super::similarity_utils::make_method_flag;

pub(crate) fn test_coupling_flags(prepared: &[PreparedMethod<'_>]) -> Vec<StaticFlag> {
    let mut flags = Vec::new();
    for i in 0..prepared.len() {
        let current = &prepared[i];
        if !matches!(current.role, FileRole::Test) || current.method.loc < 4 {
            continue;
        }

        if let Some((j, sim, exact)) = best_previous_match(prepared, i, 0.90) {
            flags.push(build_test_coupling_flag(current, &prepared[j], sim, exact));
        }
    }
    flags
}

fn build_test_coupling_flag(
    current: &PreparedMethod<'_>,
    other: &PreparedMethod<'_>,
    sim: f64,
    exact: bool,
) -> StaticFlag {
    let reason = if exact {
        format!(
            "test mirrors production implementation (matches {}::{})",
            other.method.file_path, other.method.name
        )
    } else {
        format!(
            "test mirrors production implementation ({:.0}% match with {}::{})",
            sim * 100.0,
            other.method.file_path,
            other.method.name
        )
    };
    make_method_flag(
        current.method,
        reason,
        FindingTier::KindaSlop,
        "test_coupling",
    )
}
