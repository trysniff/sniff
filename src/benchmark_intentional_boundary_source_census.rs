use super::{
    BoundaryGitEntryKind, IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensusFailureEvidence,
    read_intentional_boundary_git_blob, read_intentional_boundary_git_blob_typed,
    validate_intentional_boundary_repository_inventory_typed,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION: u32 = 1;
const SOURCE_CENSUS_CONTRACT: &str = "sniffbench-intentional-boundary-source-census-v1";
pub(super) const INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT: &str =
    "sniff-supported-source-extensions-v1:go,js,jsx,kt,kts,py,rs,ts,tsx";
pub(super) const INTENTIONAL_BOUNDARY_PARSER_ERROR_LIMIT: usize = 4 * 1024;
type SourceFailureEvidence = IntentionalBoundarySourceCensusFailureEvidence;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryMethodCensusEntry {
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub is_exported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceFile {
    pub repository_path: String,
    pub object_id: String,
    pub byte_length: u64,
    pub source_sha256: String,
    pub language: String,
    pub methods: Vec<IntentionalBoundaryMethodCensusEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceCensus {
    pub schema_version: u32,
    pub census_contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub tracked_entry_count: usize,
    pub source_files: Vec<IntentionalBoundarySourceFile>,
    pub source_file_count: usize,
    pub method_count: usize,
    pub census_sha256: String,
}

pub(super) enum IntentionalBoundarySourceInspection {
    Completed(IntentionalBoundarySourceCensus),
    Excluded(Vec<SourceFailureEvidence>),
}

pub fn census_intentional_boundary_repository(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundarySourceCensus, String> {
    match inspect_intentional_boundary_repository_sources_typed(
        repository, revision, root, inventory,
    )
    .map_err(|error| error.detail)?
    {
        IntentionalBoundarySourceInspection::Completed(census) => Ok(census),
        IntentionalBoundarySourceInspection::Excluded(failures) => Err(format!(
            "intentional-boundary source census rejected unsupported project shape: {failures:?}"
        )),
    }
}

pub(super) fn inspect_intentional_boundary_repository_sources_typed(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundarySourceInspection, IntentionalBoundaryInventoryError> {
    validate_intentional_boundary_repository_inventory_typed(
        repository, revision, root, inventory,
    )?;

    let mut source_files = Vec::new();
    let mut failures = Vec::new();
    for entry in &inventory.tracked_entries {
        if entry.kind == BoundaryGitEntryKind::Gitlink {
            failures.push(SourceFailureEvidence::RepositoryContainsGitlink {
                repository_path: entry.repository_path.clone(),
                object_id: entry.object_id.clone(),
            });
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
            failures.push(SourceFailureEvidence::SupportedSourceIsNotRegularBlob {
                repository_path: entry.repository_path.clone(),
                object_id: entry.object_id.clone(),
                entry_kind: entry.kind,
            });
            continue;
        }
        let expected_length = entry.byte_length.ok_or_else(|| {
            invalid(format!(
                "intentional-boundary source has no committed byte length: {}",
                entry.repository_path
            ))
        })?;
        let committed_bytes =
            read_intentional_boundary_git_blob_typed(root, &entry.object_id, expected_length)?;
        let worktree_bytes =
            fs::read(root.join(Path::new(&entry.repository_path))).map_err(|error| {
                failed(format!(
                    "failed to read intentional-boundary source {}: {error}",
                    entry.repository_path
                ))
            })?;
        if worktree_bytes != committed_bytes {
            return Err(invalid(format!(
                "intentional-boundary source bytes differ from committed Git blob: {}",
                entry.repository_path
            )));
        }
        let source_sha256 = sha256(&committed_bytes);
        if let Err(error) = std::str::from_utf8(&committed_bytes) {
            failures.push(SourceFailureEvidence::SupportedSourceIsNotUtf8 {
                repository_path: entry.repository_path.clone(),
                object_id: entry.object_id.clone(),
                byte_length: expected_length,
                source_sha256,
                language: adapter.name,
                valid_up_to: error.valid_up_to(),
                error_length: error.error_len(),
            });
            continue;
        }
        let parsed =
            match crate::parser::parse_source_checked(&entry.repository_path, &committed_bytes) {
                Ok(parsed) => parsed,
                Err(error) => {
                    let (retained_parser_error, parser_error_truncated) = retain_error(&error);
                    let failure = SourceFailureEvidence::SupportedSourceCannotBeParsed {
                        repository_path: entry.repository_path.clone(),
                        object_id: entry.object_id.clone(),
                        byte_length: expected_length,
                        source_sha256,
                        language: adapter.name,
                        parser_error_sha256: sha256(error.as_bytes()),
                        retained_parser_error,
                        parser_error_truncated,
                    };
                    failures.push(failure);
                    continue;
                }
            };
        if parsed.language != adapter.name {
            return Err(invalid(format!(
                "intentional-boundary parser language changed for {}",
                entry.repository_path
            )));
        }
        let mut parser_unit_ids = BTreeSet::new();
        let methods = parsed
            .methods
            .into_iter()
            .map(|method| {
                let source_sha256 = sha256(method.source.as_bytes());
                let parser_unit_id = method_unit_id(
                    &entry.repository_path,
                    &method.name,
                    method.start_line,
                    method.end_line,
                    &source_sha256,
                )
                .map_err(invalid)?;
                if !parser_unit_ids.insert(parser_unit_id.clone()) {
                    return Err(invalid(format!(
                        "intentional-boundary parser repeated unit identity {parser_unit_id}"
                    )));
                }
                Ok(IntentionalBoundaryMethodCensusEntry {
                    parser_unit_id,
                    symbol_name: method.name,
                    start_line: method.start_line,
                    end_line: method.end_line,
                    source_sha256,
                    is_exported: method.is_exported,
                })
            })
            .collect::<Result<Vec<_>, IntentionalBoundaryInventoryError>>()?;
        source_files.push(IntentionalBoundarySourceFile {
            repository_path: entry.repository_path.clone(),
            object_id: entry.object_id.clone(),
            byte_length: expected_length,
            source_sha256,
            language: adapter.name,
            methods,
        });
    }
    failures.sort_by(|left, right| failure_key(left).cmp(&failure_key(right)));
    if !failures.is_empty() {
        return Ok(IntentionalBoundarySourceInspection::Excluded(failures));
    }
    source_files.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    let method_count = source_files.iter().try_fold(0_usize, |total, file| {
        total
            .checked_add(file.methods.len())
            .ok_or_else(|| invalid("intentional-boundary source method count overflowed"))
    })?;
    let mut census = IntentionalBoundarySourceCensus {
        schema_version: INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION,
        census_contract: SOURCE_CENSUS_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        tracked_entry_count: inventory.tracked_entries.len(),
        source_file_count: source_files.len(),
        method_count,
        source_files,
        census_sha256: String::new(),
    };
    census.census_sha256 = compute_census_sha256(&census).map_err(invalid)?;
    Ok(IntentionalBoundarySourceInspection::Completed(census))
}

pub fn validate_intentional_boundary_source_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundarySourceCensus,
) -> Result<(), String> {
    let expected = census_intentional_boundary_repository(repository, revision, root, inventory)?;
    if census != &expected {
        return Err("intentional-boundary source census changed".to_string());
    }
    Ok(())
}

pub(super) fn intentional_boundary_file_records(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundarySourceCensus,
) -> Result<Vec<crate::types::FileRecord>, String> {
    let mut records = Vec::with_capacity(census.source_files.len());
    for source_file in &census.source_files {
        let inventory_entry = inventory
            .tracked_entries
            .iter()
            .find(|entry| entry.repository_path == source_file.repository_path)
            .ok_or_else(|| {
                format!(
                    "intentional-boundary census source disappeared from inventory: {}",
                    source_file.repository_path
                )
            })?;
        if inventory_entry.object_id != source_file.object_id
            || inventory_entry.byte_length != Some(source_file.byte_length)
        {
            return Err(format!(
                "intentional-boundary census source changed its Git identity: {}",
                source_file.repository_path
            ));
        }
        let bytes = read_intentional_boundary_git_blob(
            root,
            &source_file.object_id,
            source_file.byte_length,
        )?;
        let absolute_path = root.join(Path::new(&source_file.repository_path));
        let absolute_path = absolute_path.to_str().ok_or_else(|| {
            format!(
                "intentional-boundary source path is not UTF-8: {}",
                source_file.repository_path
            )
        })?;
        let record = crate::parser::parse_source_checked(absolute_path, &bytes)?;
        if record.language != source_file.language
            || record.methods.len() != source_file.methods.len()
        {
            return Err(format!(
                "intentional-boundary semantic input changed its parser census: {}",
                source_file.repository_path
            ));
        }
        for (method, expected) in record.methods.iter().zip(&source_file.methods) {
            let source_sha256 = sha256(method.source.as_bytes());
            let parser_unit_id = method_unit_id(
                &source_file.repository_path,
                &method.name,
                method.start_line,
                method.end_line,
                &source_sha256,
            )?;
            if parser_unit_id != expected.parser_unit_id
                || method.name != expected.symbol_name
                || method.start_line != expected.start_line
                || method.end_line != expected.end_line
                || source_sha256 != expected.source_sha256
                || method.is_exported != expected.is_exported
            {
                return Err(format!(
                    "intentional-boundary semantic input changed method identity {}",
                    expected.parser_unit_id
                ));
            }
        }
        records.push(record);
    }
    Ok(records)
}

fn compute_census_sha256(census: &IntentionalBoundarySourceCensus) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.census_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        census.tracked_entry_count,
        &census.source_files,
        census.source_file_count,
        census.method_count,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary source census: {error}"))?;
    Ok(sha256(&bytes))
}

fn method_unit_id(
    repository_path: &str,
    symbol_name: &str,
    start_line: usize,
    end_line: usize,
    source_sha256: &str,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        "sniffbench-intentional-boundary-method-v1",
        repository_path,
        symbol_name,
        start_line,
        end_line,
        source_sha256,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary method identity: {error}"))?;
    Ok(format!("ibm-v1:{}", sha256(&bytes)))
}

fn failure_key(failure: &SourceFailureEvidence) -> (&str, u8) {
    match failure {
        SourceFailureEvidence::RepositoryContainsGitlink {
            repository_path, ..
        } => (repository_path, 0),
        SourceFailureEvidence::SupportedSourceIsNotRegularBlob {
            repository_path, ..
        } => (repository_path, 1),
        SourceFailureEvidence::SupportedSourceIsNotUtf8 {
            repository_path, ..
        } => (repository_path, 2),
        SourceFailureEvidence::SupportedSourceCannotBeParsed {
            repository_path, ..
        } => (repository_path, 3),
    }
}

fn retain_error(error: &str) -> (String, bool) {
    if error.len() <= INTENTIONAL_BOUNDARY_PARSER_ERROR_LIMIT {
        return (error.to_string(), false);
    }
    let mut end = INTENTIONAL_BOUNDARY_PARSER_ERROR_LIMIT;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    (error[..end].to_string(), true)
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryInventoryError {
    IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn failed(detail: impl Into<String>) -> IntentionalBoundaryInventoryError {
    IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_source_census_tests.rs"]
mod tests;
