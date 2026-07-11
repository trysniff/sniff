use crate::report_types::StaticFlag;
use crate::roles::{FileRole, is_protocol_surface_module, is_wrapper_only_module};
use crate::types::{FileRecord, FindingTier, MethodRecord};

use super::similarity_text;
use super::similarity_tokens;
use super::similarity_utils::make_method_flag;

pub(crate) struct PreparedMethod<'a> {
    pub method: &'a MethodRecord,
    pub role: FileRole,
    pub normalized: String,
    pub shingles: std::collections::HashSet<String>,
}

pub(crate) fn best_previous_match(
    prepared: &[PreparedMethod<'_>],
    i: usize,
    min_similarity: f64,
) -> Option<(usize, f64, bool)> {
    let current = &prepared[i];
    (0..i)
        .filter_map(|j| {
            let other = &prepared[j];
            let (sim, exact) = similarity_text::similarity_for_pair(
                &current.normalized,
                &current.shingles,
                &current.method.language,
                other.method,
                other.role,
                &other.normalized,
                &other.shingles,
            )?;
            (sim >= min_similarity).then_some((j, sim, exact))
        })
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

pub(crate) fn build_prepared_methods<'a>(
    file_records: &'a [FileRecord],
) -> Vec<PreparedMethod<'a>> {
    let mut prepared = Vec::new();
    for file in file_records {
        if is_wrapper_only_module(file) {
            continue;
        }
        if is_protocol_surface_module(file) {
            continue;
        }
        let role = crate::roles::classify_file_role(&file.file_path);
        for method in &file.methods {
            let tokens = similarity_tokens::normalize_identifier_tokens(&method.source);
            let normalized = tokens.join(" ");
            let shingles = similarity_text::shingles(&tokens, 5);
            prepared.push(PreparedMethod {
                method,
                role,
                normalized,
                shingles,
            });
        }
    }
    prepared.sort_by(|a, b| {
        a.method
            .file_path
            .cmp(&b.method.file_path)
            .then_with(|| a.method.start_line.cmp(&b.method.start_line))
            .then_with(|| a.method.name.cmp(&b.method.name))
    });
    prepared
}

pub(crate) fn duplicate_flags(prepared: &[PreparedMethod<'_>]) -> Vec<StaticFlag> {
    prepared
        .iter()
        .enumerate()
        .filter(|(_, current)| {
            super::super::similarity_roles::is_comparable_method(current.method, current.role)
        })
        .filter_map(|(i, current)| {
            let (j, sim, exact) = best_previous_match(prepared, i, 0.88)?;
            Some(build_duplicate_flag(current, &prepared[j], sim, exact))
        })
        .collect()
}

fn build_duplicate_flag(
    current: &PreparedMethod<'_>,
    other: &PreparedMethod<'_>,
    sim: f64,
    exact: bool,
) -> StaticFlag {
    let reason = if exact {
        format!(
            "copy-pasted method body (matches {}::{})",
            other.method.file_path, other.method.name
        )
    } else {
        format!(
            "near-duplicate method body ({:.0}% match with {}::{})",
            sim * 100.0,
            other.method.file_path,
            other.method.name
        )
    };
    make_method_flag(
        current.method,
        reason,
        FindingTier::KindaSlop,
        "duplication",
    )
}
