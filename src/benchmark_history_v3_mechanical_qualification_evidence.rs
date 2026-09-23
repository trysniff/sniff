use super::super::{
    HistoricalV3Language, HistoricalV3MechanicalEvidence, HistoricalV3MechanicalPolicy,
    HistoricalV3SemanticSnapshot, HistoricalV3SimplificationKind, HistoricalV3SourceSide,
    HistoricalV3SourceSnapshot,
};
use super::methods::method_evidence;
use super::paths::changed_paths;
use super::roles::roles;
use super::surface::surface_delta;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn build_evidence(
    policy: &HistoricalV3MechanicalPolicy,
    base: &HistoricalV3SourceSnapshot,
    merge: &HistoricalV3SourceSnapshot,
    base_semantic: &HistoricalV3SemanticSnapshot,
    merge_semantic: &HistoricalV3SemanticSnapshot,
) -> Result<HistoricalV3MechanicalEvidence, String> {
    let changed_paths = changed_paths(policy, base, merge, base_semantic, merge_semantic)?;
    let changed_path_set = changed_paths
        .iter()
        .map(|path| path.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut methods = method_evidence(
        policy,
        base,
        merge,
        base_semantic,
        merge_semantic,
        &changed_path_set,
    )?;
    for path in &changed_paths {
        methods.non_production_roles.extend(roles(&path.base_roles));
        methods
            .non_production_roles
            .extend(roles(&path.merge_roles));
    }

    let base_changed_production_method_count = methods
        .changed
        .iter()
        .filter(|method| method.side == HistoricalV3SourceSide::Base)
        .count();
    let merge_changed_production_method_count = methods
        .changed
        .iter()
        .filter(|method| method.side == HistoricalV3SourceSide::Merge)
        .count();
    let base_changed_production_non_whitespace_lines =
        changed_method_lines(&methods.changed, HistoricalV3SourceSide::Base, "base")?;
    let merge_changed_production_non_whitespace_lines =
        changed_method_lines(&methods.changed, HistoricalV3SourceSide::Merge, "merge")?;
    let mut simplifications = Vec::new();
    if merge_changed_production_non_whitespace_lines < base_changed_production_non_whitespace_lines
    {
        simplifications.push(HistoricalV3SimplificationKind::ProductionLineReduction);
    }
    if merge_changed_production_method_count < base_changed_production_method_count
        && merge_changed_production_non_whitespace_lines
            <= base_changed_production_non_whitespace_lines
    {
        simplifications.push(HistoricalV3SimplificationKind::ProductionMethodConsolidation);
    }
    let formatting_only = !changed_paths.is_empty()
        && changed_paths.iter().all(|path| {
            path.base_syntax_sha256.is_some()
                && path.base_syntax_sha256 == path.merge_syntax_sha256
                && path.change == super::super::HistoricalV3PathChangeKind::Modified
        });
    let public_surface = surface_delta(base_semantic, merge_semantic)?;
    let mut evidence = HistoricalV3MechanicalEvidence {
        changed_paths,
        base_production_method_count: methods.base_production_count,
        merge_production_method_count: methods.merge_production_count,
        production_method_minimum: policy.production_method_minimum,
        production_method_maximum: policy.production_method_maximum,
        changed_methods: methods.changed,
        unresolved_changed_methods: methods.unresolved,
        base_changed_production_non_whitespace_lines,
        merge_changed_production_non_whitespace_lines,
        base_changed_production_method_count,
        merge_changed_production_method_count,
        simplifications,
        formatting_only,
        non_production_roles: methods.non_production_roles.into_iter().collect(),
        public_surface,
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = evidence_sha256(&evidence)?;
    Ok(evidence)
}

pub(super) fn evidence_sha256(evidence: &HistoricalV3MechanicalEvidence) -> Result<String, String> {
    let mut committed = evidence.clone();
    committed.evidence_sha256.clear();
    json_sha256(&committed)
}

pub(super) fn language_name(language: HistoricalV3Language) -> &'static str {
    match language {
        HistoricalV3Language::Go => "go",
        HistoricalV3Language::JavaScript => "javascript",
        HistoricalV3Language::Kotlin => "kotlin",
        HistoricalV3Language::Python => "python",
        HistoricalV3Language::Rust => "rust",
        HistoricalV3Language::TypeScript => "typescript",
    }
}

fn changed_method_lines(
    methods: &[super::super::HistoricalV3ChangedMethod],
    side: HistoricalV3SourceSide,
    label: &str,
) -> Result<usize, String> {
    methods
        .iter()
        .filter(|method| method.side == side)
        .try_fold(0_usize, |total, method| {
            total
                .checked_add(method.non_whitespace_line_count)
                .ok_or_else(|| format!("historical-v3 {label} production line count overflowed"))
        })
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 mechanical evidence: {error}"))
}
