use super::{
    HistoricalDiffHunk, HistoricalRevisionSide, HistoricalV2ChangedMethod,
    HistoricalV2ChangedMethodResolutionFailure, HistoricalV2SemanticMethodStatus,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SourceFile, HistoricalV2SourceMethod,
    HistoricalV2SourceRole, HistoricalV2SourceRoleDecision, HistoricalV2SourceSnapshotCensus,
    HistoricalV2UnresolvedChangedMethod,
};
use std::collections::BTreeMap;

pub(super) fn production_method_count(
    source: &HistoricalV2SourceSnapshotCensus,
    roles: &BTreeMap<String, HistoricalV2SourceRoleDecision>,
) -> Result<usize, String> {
    source
        .source_files
        .iter()
        .filter(|file| {
            roles
                .get(&file.repository_path)
                .map(|decision| decision.role)
                == Some(HistoricalV2SourceRole::Production)
        })
        .try_fold(0_usize, |total, file| {
            total
                .checked_add(file.methods.len())
                .ok_or_else(|| "historical-v2 production method count overflowed".to_string())
        })
}

pub(super) fn checked_add_lines(
    total: usize,
    file: Option<&HistoricalV2SourceFile>,
) -> Result<usize, String> {
    total
        .checked_add(file.map_or(0, |file| file.non_whitespace_lines))
        .ok_or_else(|| "historical-v2 production line count overflowed".to_string())
}

pub(super) fn collect_side_methods(
    side: HistoricalRevisionSide,
    path: &str,
    file: Option<&HistoricalV2SourceFile>,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    hunks: &[HistoricalDiffHunk],
    changed: &mut BTreeMap<(HistoricalRevisionSide, String), HistoricalV2ChangedMethod>,
    unresolved: &mut BTreeMap<
        (HistoricalRevisionSide, String),
        HistoricalV2UnresolvedChangedMethod,
    >,
) {
    let Some(file) = file else {
        return;
    };
    for method in &file.methods {
        if !method_overlaps_hunks(side, method, hunks) {
            continue;
        }
        let key = (side, method.parser_unit_id.clone());
        let semantic = semantic
            .methods
            .iter()
            .find(|semantic| semantic.parser_unit_id == method.parser_unit_id);
        match semantic.map(|semantic| (&semantic.indexer, &semantic.status)) {
            Some((indexer, HistoricalV2SemanticMethodStatus::Resolved { symbol_id, .. })) => {
                changed.insert(
                    key,
                    HistoricalV2ChangedMethod {
                        side,
                        language: file.language.clone(),
                        repository_path: path.to_string(),
                        parser_unit_id: method.parser_unit_id.clone(),
                        symbol_name: method.symbol_name.clone(),
                        start_line: method.start_line,
                        end_line: method.end_line,
                        source_sha256: method.source_sha256.clone(),
                        indexer: *indexer,
                        compiler_symbol_id: symbol_id.clone(),
                    },
                );
            }
            Some((_, HistoricalV2SemanticMethodStatus::CompilerExcluded { reason })) => {
                unresolved.insert(
                    key,
                    unresolved_method(
                        side,
                        path,
                        method,
                        HistoricalV2ChangedMethodResolutionFailure::CompilerExcluded {
                            reason: reason.clone(),
                        },
                    ),
                );
            }
            Some((
                _,
                HistoricalV2SemanticMethodStatus::Unresolved {
                    reason,
                    raw_target,
                    detail,
                },
            )) => {
                unresolved.insert(
                    key,
                    unresolved_method(
                        side,
                        path,
                        method,
                        HistoricalV2ChangedMethodResolutionFailure::Unresolved {
                            reason: *reason,
                            raw_target: raw_target.clone(),
                            detail: detail.clone(),
                        },
                    ),
                );
            }
            None => {
                unresolved.insert(
                    key,
                    unresolved_method(
                        side,
                        path,
                        method,
                        HistoricalV2ChangedMethodResolutionFailure::MissingSemanticMethod,
                    ),
                );
            }
        }
    }
}

fn unresolved_method(
    side: HistoricalRevisionSide,
    path: &str,
    method: &HistoricalV2SourceMethod,
    failure: HistoricalV2ChangedMethodResolutionFailure,
) -> HistoricalV2UnresolvedChangedMethod {
    HistoricalV2UnresolvedChangedMethod {
        side,
        repository_path: path.to_string(),
        parser_unit_id: method.parser_unit_id.clone(),
        symbol_name: method.symbol_name.clone(),
        failure,
    }
}

pub(super) fn method_overlaps_hunks(
    side: HistoricalRevisionSide,
    method: &HistoricalV2SourceMethod,
    hunks: &[HistoricalDiffHunk],
) -> bool {
    hunks.iter().any(|hunk| {
        let (start, count) = match side {
            HistoricalRevisionSide::Parent => (hunk.parent_start, hunk.parent_count),
            HistoricalRevisionSide::Commit => (hunk.commit_start, hunk.commit_count),
        };
        if count == 0 {
            return false;
        }
        let end = start.saturating_add(count - 1);
        method.start_line <= end && start <= method.end_line
    })
}
