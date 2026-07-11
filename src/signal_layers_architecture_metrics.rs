use crate::config::ResolvedConfig;
use crate::types::FileRecord;
use std::collections::HashSet;

use super::similarity;

pub(crate) struct ArchitectureMetrics {
    outbound_files: HashSet<String>,
    method_locs: Vec<usize>,
    exported_methods: usize,
    total_external_refs: usize,
}

impl ArchitectureMetrics {
    fn from_file(file: &FileRecord) -> Self {
        let method_locs = file.methods.iter().map(|method| method.loc).collect();
        let exported_methods = file
            .methods
            .iter()
            .filter(|method| method.is_exported)
            .count();

        let (outbound_files, total_external_refs) = file
            .methods
            .iter()
            .flat_map(|method| method.references.iter())
            .filter_map(|reference| {
                let normalized = similarity::normalize_path(&reference.file_path);
                if normalized != similarity::normalize_path(&file.file_path) {
                    Some(normalized)
                } else {
                    None
                }
            })
            .fold(
                (HashSet::new(), 0usize),
                |(mut outbound_files, total_external_refs), normalized| {
                    outbound_files.insert(normalized);
                    (outbound_files, total_external_refs + 1)
                },
            );

        Self {
            outbound_files,
            method_locs,
            exported_methods,
            total_external_refs,
        }
    }

    fn max_loc(&self) -> usize {
        self.method_locs.iter().copied().max().unwrap_or(0)
    }

    fn loc_range(&self) -> (usize, usize, f64) {
        let max_loc = self.max_loc();
        let min_loc = self
            .method_locs
            .iter()
            .copied()
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let spread = if min_loc > 0 {
            max_loc as f64 / min_loc as f64
        } else {
            0.0
        };
        (min_loc, max_loc, spread)
    }

    fn single_method_reason(&self, method_count: usize) -> Option<String> {
        if method_count < 4 && method_count > 0 && self.max_loc() > 100 {
            return Some(format!(
                "module is dominated by one oversized method ({} LOC)",
                self.max_loc()
            ));
        }
        None
    }
}

fn add_architecture_fanout_reason(
    reasons: &mut Vec<String>,
    metrics: &ArchitectureMetrics,
    method_count: usize,
    config: &ResolvedConfig,
) {
    if metrics.outbound_files.len() >= 5
        && method_count >= config.thresholds.max_methods_per_file / 2
        && (metrics.exported_methods >= 4 || method_count >= 10)
    {
        reasons.push(format!(
            "module has broad dependency fan-out ({} outbound files)",
            metrics.outbound_files.len()
        ));
    }
}

fn add_architecture_surface_reason(reasons: &mut Vec<String>, metrics: &ArchitectureMetrics) {
    if metrics.exported_methods >= 4 && metrics.total_external_refs >= 8 {
        reasons.push(format!(
            "module mixes public surface and orchestration ({} exported methods, {} external references)",
            metrics.exported_methods,
            metrics.total_external_refs
        ));
    }
}

fn add_architecture_sprawl_reason(
    reasons: &mut Vec<String>,
    metrics: &ArchitectureMetrics,
    method_count: usize,
    min_loc: usize,
    max_loc: usize,
    spread: f64,
) {
    if method_count >= 10 && metrics.exported_methods >= 4 && spread >= 2.5 {
        reasons.push(format!(
            "module has sprawling helper surface ({} exported methods, {}-{} LOC spread)",
            metrics.exported_methods, min_loc, max_loc
        ));
    }
    if spread >= 8.0 && metrics.outbound_files.len() >= 3 && method_count >= 6 {
        reasons.push(format!(
            "module has uneven method sizes and dependency fan-out ({}-{} LOC, {} outbound files)",
            min_loc,
            max_loc,
            metrics.outbound_files.len()
        ));
    }
}

pub(crate) fn architecture_reasons(file: &FileRecord, config: &ResolvedConfig) -> Vec<String> {
    let metrics = ArchitectureMetrics::from_file(file);
    let method_count = file.methods.len();
    let mut reasons = Vec::new();

    if let Some(reason) = metrics.single_method_reason(method_count) {
        reasons.push(reason);
        return reasons;
    }

    let (min_loc, max_loc, spread) = metrics.loc_range();

    add_architecture_fanout_reason(&mut reasons, &metrics, method_count, config);
    add_architecture_surface_reason(&mut reasons, &metrics);
    add_architecture_sprawl_reason(
        &mut reasons,
        &metrics,
        method_count,
        min_loc,
        max_loc,
        spread,
    );
    reasons
}
