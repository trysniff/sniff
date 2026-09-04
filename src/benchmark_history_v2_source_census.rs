use super::history_v2_source_census_exclusion::seal_source_census_exclusion;
use super::intentional_boundary_inventory::{
    read_intentional_boundary_git_blobs, supported_source_git_blob_requests,
};
use super::{
    BoundaryGitEntryKind, HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2PublicSurfaceCoverage, HistoricalV2SlotStage,
    HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind, HistoricalV2SourceByteRange,
    HistoricalV2SourceCensus, HistoricalV2SourceCensusExclusion,
    HistoricalV2SourceCensusFailureEvidence, HistoricalV2SourceFile,
    HistoricalV2SourceIdentifierPositions, HistoricalV2SourceMethod, HistoricalV2SourcePosition,
    HistoricalV2SourcePositionRange, HistoricalV2SourcePublicBindingKind,
    HistoricalV2SourcePublicDeclaration, HistoricalV2SourcePublicNamespace,
    HistoricalV2SourcePublicReexport, HistoricalV2SourcePublicReexportKind,
    HistoricalV2SourcePublicSymbolKind, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, HistoricalV2SourceSnapshotSide, HistoricalV2StageResult,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensus,
    census_intentional_boundary_repository, inventory_intentional_boundary_repository,
    validate_historical_v2_materialization,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const SOURCE_CENSUS_CONTRACT: &str = "sniffbench-historical-v2-source-census-v7";
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
    let inventory_repository = format!("github.com/{}", materialization.canonical_repository);
    let base_inventory = inventory_intentional_boundary_repository(
        &inventory_repository,
        &materialization.base_revision,
        &roots.base_root,
    )
    .map_err(infrastructure)?;
    let patched_inventory = inventory_intentional_boundary_repository(
        &inventory_repository,
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
        &inventory_repository,
        &materialization.base_revision,
        &roots.base_root,
        &base_inventory,
    )
    .map_err(infrastructure)?;
    let patched_parser_census = census_intentional_boundary_repository(
        &inventory_repository,
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
    let requests = supported_source_git_blob_requests(inventory).map_err(infrastructure)?;
    let mut blobs = read_intentional_boundary_git_blobs(root, &requests)
        .map_err(infrastructure)?
        .into_iter();
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
        let bytes = blobs.next().ok_or_else(|| {
            infrastructure("historical-v2 source blob batch ended before its inventory")
        })?;
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
    if blobs.next().is_some() {
        return Err(infrastructure(
            "historical-v2 source blob batch exceeded its inventory",
        ));
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
    let mut public_declaration_count = 0_usize;
    let mut public_reexport_count = 0_usize;
    let requests = parser_census
        .source_files
        .iter()
        .map(|source| (source.object_id.as_str(), source.byte_length))
        .collect::<Vec<_>>();
    let blobs = read_intentional_boundary_git_blobs(root, &requests)?;
    for (source, bytes) in parser_census.source_files.iter().zip(blobs) {
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
        let (public_surface_coverage, public_declarations, public_reexports) =
            source_public_declarations(&source.repository_path, &source.language, &bytes)?;
        public_declaration_count = public_declaration_count
            .checked_add(public_declarations.len())
            .ok_or_else(|| "historical-v2 public declaration count overflowed".to_string())?;
        public_reexport_count = public_reexport_count
            .checked_add(public_reexports.len())
            .ok_or_else(|| "historical-v2 public re-export count overflowed".to_string())?;
        source_files.push(HistoricalV2SourceFile {
            repository_path: source.repository_path.clone(),
            object_id: source.object_id.clone(),
            byte_length: source.byte_length,
            source_sha256: source.source_sha256.clone(),
            non_whitespace_lines: non_whitespace_lines(&bytes)?,
            language: source.language.clone(),
            semantic_coverage: source_semantic_coverage(&source.repository_path, &bytes),
            methods,
            public_surface_coverage,
            public_declarations,
            public_reexports,
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
        public_declaration_count,
        public_reexport_count,
        snapshot_census_sha256: String::new(),
    };
    snapshot.snapshot_census_sha256 = snapshot_census_sha256(&snapshot)?;
    Ok(snapshot)
}

pub(super) fn source_public_declarations(
    repository_path: &str,
    language: &str,
    source: &[u8],
) -> Result<
    (
        HistoricalV2PublicSurfaceCoverage,
        Vec<HistoricalV2SourcePublicDeclaration>,
        Vec<HistoricalV2SourcePublicReexport>,
    ),
    String,
> {
    if !matches!(language, "go" | "typescript" | "javascript") {
        return Ok((
            HistoricalV2PublicSurfaceCoverage::UnsupportedLanguage,
            Vec::new(),
            Vec::new(),
        ));
    }
    let surface =
        crate::source_public_surface::census_source_public_surface(repository_path, source)?;
    let source_text = std::str::from_utf8(source)
        .map_err(|_| "historical-v2 public-surface source is not UTF-8".to_string())?;
    let declarations = surface
        .declarations
        .into_iter()
        .map(|declaration| {
            let binding = match declaration.binding {
                crate::source_public_surface::SourcePublicBindingKind::Definition => {
                    HistoricalV2SourcePublicBindingKind::Definition
                }
                crate::source_public_surface::SourcePublicBindingKind::Reference => {
                    HistoricalV2SourcePublicBindingKind::Reference
                }
                crate::source_public_surface::SourcePublicBindingKind::Unsupported => {
                    return Err(format!(
                        "historical-v2 public surface has an unsupported exposure in {repository_path}: {}",
                        declaration.name
                    ));
                }
            };
            let kind = match declaration.kind {
                crate::source_public_surface::SourcePublicSymbolKind::CompilerDefined => {
                    HistoricalV2SourcePublicSymbolKind::CompilerDefined
                }
                crate::source_public_surface::SourcePublicSymbolKind::Module => {
                    HistoricalV2SourcePublicSymbolKind::Module
                }
                crate::source_public_surface::SourcePublicSymbolKind::Callable => {
                    HistoricalV2SourcePublicSymbolKind::Callable
                }
                crate::source_public_surface::SourcePublicSymbolKind::Method => {
                    HistoricalV2SourcePublicSymbolKind::Method
                }
                crate::source_public_surface::SourcePublicSymbolKind::Type => {
                    HistoricalV2SourcePublicSymbolKind::Type
                }
                crate::source_public_surface::SourcePublicSymbolKind::Field => {
                    HistoricalV2SourcePublicSymbolKind::Field
                }
                crate::source_public_surface::SourcePublicSymbolKind::Variable => {
                    HistoricalV2SourcePublicSymbolKind::Variable
                }
                crate::source_public_surface::SourcePublicSymbolKind::Constant => {
                    HistoricalV2SourcePublicSymbolKind::Constant
                }
            };
            let exposed_identifier = HistoricalV2SourceByteRange {
                start: declaration.exposed_identifier.start,
                end: declaration.exposed_identifier.end,
            };
            let exposed_identifier_positions =
                identifier_positions(source_text, exposed_identifier)?;
            let identifier = HistoricalV2SourceByteRange {
                start: declaration.compiler_anchor.start,
                end: declaration.compiler_anchor.end,
            };
            let identifier_positions = identifier_positions(source_text, identifier)?;
            let namespace = match declaration.namespace {
                crate::source_public_surface::SourcePublicNamespace::Module => {
                    HistoricalV2SourcePublicNamespace::Module
                }
                crate::source_public_surface::SourcePublicNamespace::InstanceMember => {
                    HistoricalV2SourcePublicNamespace::InstanceMember
                }
                crate::source_public_surface::SourcePublicNamespace::StaticMember => {
                    HistoricalV2SourcePublicNamespace::StaticMember
                }
            };
            let package_path = Path::new(repository_path)
                .parent()
                .map(|path| path.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let surface_unit_id = hash_json(&(
                "sniffbench-historical-v2-public-surface-v3",
                language,
                package_path,
                declaration.name.as_str(),
                declaration.owner.as_deref(),
                namespace,
                kind,
            ))
            .map(|hash| format!("h2s-v3:{hash}"))?;
            let declaration_unit_id = hash_json(&(
                "sniffbench-historical-v2-public-declaration-v3",
                surface_unit_id.as_str(),
                repository_path,
                exposed_identifier,
                identifier,
                binding,
                declaration.source_module.as_deref(),
            ))
            .map(|hash| format!("h2d-v3:{hash}"))?;
            Ok(HistoricalV2SourcePublicDeclaration {
                surface_unit_id,
                declaration_unit_id,
                name: declaration.name,
                target_name: declaration.target_name,
                owner: declaration.owner,
                namespace,
                kind,
                binding,
                source_module: declaration.source_module,
                exposed_identifier,
                exposed_identifier_positions,
                identifier,
                identifier_positions,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let reexports = surface
        .reexports
        .into_iter()
        .map(|reexport| {
            let kind = match reexport.kind {
                crate::source_public_surface::SourcePublicReexportKind::Wildcard => {
                    HistoricalV2SourcePublicReexportKind::Wildcard
                }
                crate::source_public_surface::SourcePublicReexportKind::Namespace => {
                    HistoricalV2SourcePublicReexportKind::Namespace
                }
            };
            let directive = HistoricalV2SourceByteRange {
                start: reexport.directive.start,
                end: reexport.directive.end,
            };
            let exposed_identifier =
                reexport
                    .exposed_identifier
                    .map(|range| HistoricalV2SourceByteRange {
                        start: range.start,
                        end: range.end,
                    });
            let identifier = HistoricalV2SourceByteRange {
                start: reexport.compiler_anchor.start,
                end: reexport.compiler_anchor.end,
            };
            let identifier_positions = identifier_positions(source_text, identifier)?;
            let reexport_unit_id = hash_json(&(
                "sniffbench-historical-v2-public-reexport-v1",
                language,
                repository_path,
                kind,
                reexport.name.as_deref(),
                reexport.source_module.as_str(),
                directive,
                exposed_identifier,
                identifier,
            ))
            .map(|hash| format!("h2r-v1:{hash}"))?;
            Ok(HistoricalV2SourcePublicReexport {
                reexport_unit_id,
                kind,
                name: reexport.name,
                source_module: reexport.source_module,
                directive,
                exposed_identifier,
                identifier,
                identifier_positions,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((
        HistoricalV2PublicSurfaceCoverage::Complete,
        declarations,
        reexports,
    ))
}

fn identifier_positions(
    source: &str,
    range: HistoricalV2SourceByteRange,
) -> Result<HistoricalV2SourceIdentifierPositions, String> {
    if range.start >= range.end
        || range.end > source.len()
        || !source.is_char_boundary(range.start)
        || !source.is_char_boundary(range.end)
    {
        return Err("historical-v2 public declaration has an invalid byte range".to_string());
    }
    Ok(HistoricalV2SourceIdentifierPositions {
        utf8: position_range(source, range, |text| text.len())?,
        utf16: position_range(source, range, |text| text.encode_utf16().count())?,
        utf32: position_range(source, range, |text| text.chars().count())?,
    })
}

fn position_range(
    source: &str,
    range: HistoricalV2SourceByteRange,
    character_count: impl Fn(&str) -> usize,
) -> Result<HistoricalV2SourcePositionRange, String> {
    Ok(HistoricalV2SourcePositionRange {
        start: source_position(source, range.start, &character_count)?,
        end: source_position(source, range.end, &character_count)?,
    })
}

fn source_position(
    source: &str,
    offset: usize,
    character_count: &impl Fn(&str) -> usize,
) -> Result<HistoricalV2SourcePosition, String> {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let character = character_count(&source[line_start..offset]);
    Ok(HistoricalV2SourcePosition {
        line_zero_based: u32::try_from(line)
            .map_err(|_| "historical-v2 public declaration line exceeds u32".to_string())?,
        character_zero_based: u32::try_from(character)
            .map_err(|_| "historical-v2 public declaration column exceeds u32".to_string())?,
    })
}

pub(super) fn source_semantic_coverage(
    repository_path: &str,
    source: &[u8],
) -> HistoricalV2SourceSemanticCoverage {
    let normalized = repository_path.replace('\\', "/").to_ascii_lowercase();
    let segments = normalized.split('/').collect::<Vec<_>>();
    let name = segments.last().copied().unwrap_or_default();
    if has_segment(
        &segments,
        &["vendor", "vendored", "third_party", "node_modules"],
    ) {
        HistoricalV2SourceSemanticCoverage::VendoredPath
    } else if has_generated_marker(source) {
        HistoricalV2SourceSemanticCoverage::GeneratedHeader
    } else if has_segment(&segments, &["generated", "gen"])
        || name.contains(".generated.")
        || name.starts_with("generated.")
        || is_minified_javascript(name)
    {
        HistoricalV2SourceSemanticCoverage::GeneratedPath
    } else {
        HistoricalV2SourceSemanticCoverage::Required
    }
}

fn has_segment(segments: &[&str], expected: &[&str]) -> bool {
    segments
        .iter()
        .any(|segment| expected.iter().any(|expected| segment == expected))
}

fn is_minified_javascript(name: &str) -> bool {
    [".min.js", ".min.mjs", ".min.cjs"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn has_generated_marker(source: &[u8]) -> bool {
    let prefix = &source[..source.len().min(16 * 1024)];
    let text = String::from_utf8_lossy(prefix).to_ascii_lowercase();
    text.lines().take(40).any(|line| {
        let line = line.trim_start();
        let Some(comment) = ["//", "#", "/*", "*", "<!--"]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        else {
            return false;
        };
        let comment = comment.trim_start();
        [
            "code generated by",
            "do not edit this file",
            "do not edit manually",
            "this file is generated",
            "this file was generated",
            "automatically generated",
            "@generated",
        ]
        .iter()
        .any(|marker| comment.contains(marker))
    })
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
        value.public_declaration_count,
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
