use super::history_v2_source_census_exclusion::seal_source_census_exclusion;
use super::intentional_boundary_inventory::read_intentional_boundary_git_blob;
use super::{
    BoundaryGitEntryKind, HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2SourceCensus, HistoricalV2SourceCensusExclusion,
    HistoricalV2SourceCensusFailureEvidence, HistoricalV2SourceFile, HistoricalV2SourceMethod,
    HistoricalV2SourceSnapshotCensus, HistoricalV2SourceSnapshotSide, HistoricalV2StageResult,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensus,
    census_intentional_boundary_repository, inventory_intentional_boundary_repository,
    validate_historical_v2_materialization,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const SOURCE_CENSUS_CONTRACT: &str = "sniffbench-historical-v2-source-census-v1";
pub(super) const PARSER_ERROR_LIMIT: usize = 4 * 1024;
type SourceCensusStageResult =
    HistoricalV2StageResult<HistoricalV2SourceCensus, HistoricalV2SourceCensusExclusion>;

pub fn census_historical_v2_sources(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
) -> Result<HistoricalV2SourceCensus, String> {
    match census_historical_v2_sources_typed(materialization, roots)
        .map_err(|error| error.detail)?
    {
        HistoricalV2StageResult::Completed(census) => Ok(census),
        HistoricalV2StageResult::Excluded(exclusion) => Err(format!(
            "historical-v2 source census excluded: {:?}",
            exclusion.reasons
        )),
    }
}

pub fn census_historical_v2_sources_typed(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
) -> Result<SourceCensusStageResult, HistoricalV2SlotStageError> {
    validate_historical_v2_materialization(materialization, roots).map_err(invalid)?;
    let base_inventory = inventory_intentional_boundary_repository(
        &materialization.canonical_repository,
        &materialization.base_revision,
        &roots.base_root,
    )
    .map_err(infrastructure)?;
    let patched_inventory = inventory_intentional_boundary_repository(
        &materialization.canonical_repository,
        &materialization.patched_commit_oid,
        &roots.patched_root,
    )
    .map_err(infrastructure)?;
    let mut failures = inspect_snapshot_sources(
        HistoricalV2SourceSnapshotSide::Base,
        &roots.base_root,
        &base_inventory,
    )?;
    failures.extend(inspect_snapshot_sources(
        HistoricalV2SourceSnapshotSide::Patched,
        &roots.patched_root,
        &patched_inventory,
    )?);
    if !failures.is_empty() {
        let exclusion =
            seal_source_census_exclusion(&materialization.materialization_sha256, failures)
                .map_err(|error| infrastructure(error.detail))?;
        return Ok(HistoricalV2StageResult::Excluded(exclusion));
    }
    let base_parser_census = census_intentional_boundary_repository(
        &materialization.canonical_repository,
        &materialization.base_revision,
        &roots.base_root,
        &base_inventory,
    )
    .map_err(infrastructure)?;
    let patched_parser_census = census_intentional_boundary_repository(
        &materialization.canonical_repository,
        &materialization.patched_commit_oid,
        &roots.patched_root,
        &patched_inventory,
    )
    .map_err(infrastructure)?;

    let mut census = HistoricalV2SourceCensus {
        schema_version: HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION,
        source_census_contract: SOURCE_CENSUS_CONTRACT.to_string(),
        canonical_repository: materialization.canonical_repository.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        base: project_snapshot(&roots.base_root, &base_inventory, &base_parser_census)
            .map_err(infrastructure)?,
        patched: project_snapshot(
            &roots.patched_root,
            &patched_inventory,
            &patched_parser_census,
        )
        .map_err(infrastructure)?,
        source_census_sha256: String::new(),
    };
    census.source_census_sha256 = source_census_sha256(&census).map_err(infrastructure)?;
    Ok(HistoricalV2StageResult::Completed(census))
}

pub fn validate_historical_v2_source_census(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    census: &HistoricalV2SourceCensus,
) -> Result<(), String> {
    let expected = match census_historical_v2_sources_typed(materialization, roots)
        .map_err(|error| error.detail)?
    {
        HistoricalV2StageResult::Completed(census) => census,
        HistoricalV2StageResult::Excluded(_) => {
            return Err("historical-v2 source census claims completion for excluded source".into());
        }
    };
    if census != &expected {
        return Err("historical-v2 source census changed".to_string());
    }
    Ok(())
}

fn inspect_snapshot_sources(
    side: HistoricalV2SourceSnapshotSide,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<Vec<HistoricalV2SourceCensusFailureEvidence>, HistoricalV2SlotStageError> {
    let mut failures = Vec::new();
    for entry in &inventory.tracked_entries {
        if entry.kind == BoundaryGitEntryKind::Gitlink {
            failures.push(
                HistoricalV2SourceCensusFailureEvidence::RepositoryContainsGitlink {
                    side,
                    revision: inventory.revision.clone(),
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                },
            );
            continue;
        }
        let extension = Path::new(&entry.repository_path)
            .extension()
            .and_then(|value| value.to_str());
        let Some(adapter) = extension.and_then(crate::languages::get_adapter) else {
            continue;
        };
        if !matches!(
            entry.kind,
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
        ) {
            failures.push(
                HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
                    side,
                    revision: inventory.revision.clone(),
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                    entry_kind: entry.kind,
                },
            );
            continue;
        }
        let expected_length = entry.byte_length.ok_or_else(|| {
            infrastructure(format!(
                "historical-v2 source has no committed byte length: {}",
                entry.repository_path
            ))
        })?;
        let bytes = read_intentional_boundary_git_blob(root, &entry.object_id, expected_length)
            .map_err(infrastructure)?;
        let source_sha256 = sha256(&bytes);
        if let Err(error) = std::str::from_utf8(&bytes) {
            failures.push(
                HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
                    side,
                    revision: inventory.revision.clone(),
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                    byte_length: expected_length,
                    source_sha256,
                    language: adapter.name,
                    valid_up_to: error.valid_up_to(),
                    error_length: error.error_len(),
                },
            );
            continue;
        }
        if let Err(error) = crate::parser::parse_source_checked(&entry.repository_path, &bytes) {
            let (retained_parser_error, parser_error_truncated) = retain_error(&error);
            failures.push(
                HistoricalV2SourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
                    side,
                    revision: inventory.revision.clone(),
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                    byte_length: expected_length,
                    source_sha256,
                    language: adapter.name,
                    parser_error_sha256: sha256(error.as_bytes()),
                    retained_parser_error,
                    parser_error_truncated,
                },
            );
        }
    }
    Ok(failures)
}

fn retain_error(error: &str) -> (String, bool) {
    if error.len() <= PARSER_ERROR_LIMIT {
        return (error.to_string(), false);
    }
    let mut end = PARSER_ERROR_LIMIT;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    (error[..end].to_string(), true)
}

fn project_snapshot(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    parser_census: &IntentionalBoundarySourceCensus,
) -> Result<HistoricalV2SourceSnapshotCensus, String> {
    if inventory.revision != parser_census.revision
        || inventory.inventory_sha256 != parser_census.inventory_sha256
        || inventory.tracked_entries.len() != parser_census.tracked_entry_count
    {
        return Err("historical-v2 source snapshot inputs disagree".to_string());
    }
    let mut source_files = Vec::with_capacity(parser_census.source_files.len());
    let mut method_counts_by_language = BTreeMap::<String, usize>::new();
    for source in &parser_census.source_files {
        let entry = inventory
            .tracked_entries
            .iter()
            .find(|entry| entry.repository_path == source.repository_path)
            .ok_or_else(|| {
                format!(
                    "historical-v2 source disappeared from Git inventory: {}",
                    source.repository_path
                )
            })?;
        if entry.object_id != source.object_id || entry.byte_length != Some(source.byte_length) {
            return Err(format!(
                "historical-v2 source Git identity changed: {}",
                source.repository_path
            ));
        }
        let bytes =
            read_intentional_boundary_git_blob(root, &source.object_id, source.byte_length)?;
        if sha256(&bytes) != source.source_sha256 {
            return Err(format!(
                "historical-v2 source bytes changed: {}",
                source.repository_path
            ));
        }
        let methods = source
            .methods
            .iter()
            .map(|method| {
                Ok(HistoricalV2SourceMethod {
                    parser_unit_id: method_unit_id(
                        &source.repository_path,
                        &method.symbol_name,
                        method.start_line,
                        method.end_line,
                        &method.source_sha256,
                    )?,
                    symbol_name: method.symbol_name.clone(),
                    start_line: method.start_line,
                    end_line: method.end_line,
                    source_sha256: method.source_sha256.clone(),
                    is_exported: method.is_exported,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        *method_counts_by_language
            .entry(source.language.clone())
            .or_default() += methods.len();
        source_files.push(HistoricalV2SourceFile {
            repository_path: source.repository_path.clone(),
            object_id: source.object_id.clone(),
            byte_length: source.byte_length,
            source_sha256: source.source_sha256.clone(),
            non_whitespace_lines: non_whitespace_lines(&bytes)?,
            language: source.language.clone(),
            methods,
        });
    }
    let method_count = method_counts_by_language
        .values()
        .try_fold(0_usize, |total, count| {
            total
                .checked_add(*count)
                .ok_or_else(|| "historical-v2 source method count overflowed".to_string())
        })?;
    if source_files.len() != parser_census.source_file_count
        || method_count != parser_census.method_count
    {
        return Err("historical-v2 source snapshot count changed".to_string());
    }
    let mut snapshot = HistoricalV2SourceSnapshotCensus {
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        parser_census_sha256: parser_census.census_sha256.clone(),
        tracked_entry_count: inventory.tracked_entries.len(),
        source_file_count: source_files.len(),
        source_files,
        method_counts_by_language,
        method_count,
        snapshot_census_sha256: String::new(),
    };
    snapshot.snapshot_census_sha256 = snapshot_census_sha256(&snapshot)?;
    Ok(snapshot)
}

fn non_whitespace_lines(bytes: &[u8]) -> Result<usize, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "historical-v2 supported source is not UTF-8".to_string())?;
    Ok(source
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn method_unit_id(
    repository_path: &str,
    symbol_name: &str,
    start_line: usize,
    end_line: usize,
    source_sha256: &str,
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-method-v1",
        repository_path,
        symbol_name,
        start_line,
        end_line,
        source_sha256,
    ))
    .map(|hash| format!("h2m-v1:{hash}"))
}

fn snapshot_census_sha256(value: &HistoricalV2SourceSnapshotCensus) -> Result<String, String> {
    hash_json(&(
        &value.revision,
        &value.inventory_sha256,
        &value.parser_census_sha256,
        value.tracked_entry_count,
        &value.source_files,
        value.source_file_count,
        &value.method_counts_by_language,
        value.method_count,
    ))
}

fn source_census_sha256(value: &HistoricalV2SourceCensus) -> Result<String, String> {
    hash_json(&(
        value.schema_version,
        &value.source_census_contract,
        &value.canonical_repository,
        &value.materialization_sha256,
        &value.base,
        &value.patched,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 source census: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SourceCensus,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn infrastructure(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SourceCensus,
        kind: HistoricalV2SlotStageErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_history_v2_source_census_tests.rs"]
mod tests;
