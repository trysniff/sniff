use crate::semantic_index::{
    RepositoryPath, SEMANTIC_INDEX_FORMAT_VERSION, SemanticDocument, SemanticImportEdge,
    SemanticIndex, SemanticIndexProvenance, SemanticLocation, SemanticOccurrence,
    SemanticResolution, SemanticUnresolvedEdge,
};
use protobuf::Message;
use scip::types::{Document, Index, Metadata, Occurrence};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::Path;

#[path = "semantic_index_scip_ranges.rs"]
mod ranges;
#[path = "semantic_index_scip_symbols.rs"]
mod symbols;

const MAX_SCIP_INDEX_BYTES: u64 = 512 * 1024 * 1024;

pub fn ingest_scip_file(
    repository_root: &Path,
    index_path: &Path,
) -> Result<SemanticIndex, String> {
    ingest_scip_file_with_expected_languages(repository_root, index_path, None, None)
}

pub(crate) fn ingest_scip_file_with_expected_languages(
    repository_root: &Path,
    index_path: &Path,
    expected_languages: Option<&BTreeMap<RepositoryPath, String>>,
    missing_position_encoding: Option<crate::semantic_index::SemanticPositionEncoding>,
) -> Result<SemanticIndex, String> {
    let file = File::open(index_path).map_err(|error| {
        format!(
            "failed to open SCIP index {}: {error}",
            index_path.display()
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to inspect SCIP index {}: {error}",
            index_path.display()
        )
    })?;
    if metadata.len() > MAX_SCIP_INDEX_BYTES {
        return Err(format!(
            "SCIP index exceeds the {} byte safety limit: {}",
            MAX_SCIP_INDEX_BYTES,
            index_path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    read_bounded(file.take(MAX_SCIP_INDEX_BYTES + 1), &mut bytes, index_path)?;
    ingest_scip_bytes_with_expected_languages(
        repository_root,
        &bytes,
        expected_languages,
        missing_position_encoding,
    )
}

pub fn ingest_scip_bytes(repository_root: &Path, bytes: &[u8]) -> Result<SemanticIndex, String> {
    ingest_scip_bytes_with_expected_languages(repository_root, bytes, None, None)
}

fn ingest_scip_bytes_with_expected_languages(
    repository_root: &Path,
    bytes: &[u8],
    expected_languages: Option<&BTreeMap<RepositoryPath, String>>,
    missing_position_encoding: Option<crate::semantic_index::SemanticPositionEncoding>,
) -> Result<SemanticIndex, String> {
    if bytes.len() as u64 > MAX_SCIP_INDEX_BYTES {
        return Err(format!(
            "SCIP index exceeds the {} byte safety limit",
            MAX_SCIP_INDEX_BYTES
        ));
    }
    let root = std::fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve SCIP repository root {}: {error}",
            repository_root.display()
        )
    })?;
    if !root.is_dir() {
        return Err(format!(
            "SCIP repository root is not a directory: {}",
            root.display()
        ));
    }
    let source = Index::parse_from_bytes(bytes)
        .map_err(|error| format!("failed to decode SCIP protobuf: {error}"))?;
    ingest_index(&root, source, expected_languages, missing_position_encoding)
}

fn read_bounded(mut reader: Take<File>, bytes: &mut Vec<u8>, path: &Path) -> Result<(), String> {
    reader
        .read_to_end(bytes)
        .map_err(|error| format!("failed to read SCIP index {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_SCIP_INDEX_BYTES {
        return Err(format!(
            "SCIP index exceeds the {} byte safety limit: {}",
            MAX_SCIP_INDEX_BYTES,
            path.display()
        ));
    }
    Ok(())
}

fn ingest_index(
    repository_root: &Path,
    source: Index,
    expected_languages: Option<&BTreeMap<RepositoryPath, String>>,
    missing_position_encoding: Option<crate::semantic_index::SemanticPositionEncoding>,
) -> Result<SemanticIndex, String> {
    let metadata = source
        .metadata
        .as_ref()
        .ok_or_else(|| "SCIP index is missing required metadata".to_string())?;
    let mut index = empty_index(repository_root, metadata)?;

    for information in &source.external_symbols {
        if is_known_malformed_python_external_symbol(metadata, information) {
            record_provider_diagnostic(
                &mut index,
                format!(
                    "scip-python emitted document-local external symbol {:?}; the declaration was discarded and references remain document-scoped",
                    information.symbol
                ),
            );
            continue;
        }
        symbols::ingest_symbol_information(&mut index, information, None, true)?;
    }
    for document in &source.documents {
        ingest_document(
            &mut index,
            document,
            expected_languages,
            missing_position_encoding,
            is_scip_python(metadata),
        )?;
    }
    Ok(index)
}

fn empty_index(repository_root: &Path, metadata: &Metadata) -> Result<SemanticIndex, String> {
    if metadata.version.value() != 0 {
        return Err(format!(
            "SCIP metadata uses unsupported protocol version {}",
            metadata.version.value()
        ));
    }
    let tool = metadata
        .tool_info
        .as_ref()
        .ok_or_else(|| "SCIP metadata is missing indexer tool information".to_string())?;
    if tool.name.trim().is_empty() {
        return Err("SCIP metadata has an empty indexer tool name".to_string());
    }
    Ok(SemanticIndex {
        format_version: SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: repository_root.to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: tool.name.clone(),
            tool_version: (!tool.version.trim().is_empty()).then(|| tool.version.clone()),
            arguments: tool.arguments.clone(),
            source_text_encoding: ranges::metadata_text_encoding(metadata)?,
            diagnostics: Vec::new(),
        },
        documents: BTreeMap::new(),
        symbols: BTreeMap::new(),
        relationships: BTreeSet::new(),
        imports: BTreeSet::new(),
        calls: BTreeSet::new(),
        test_relationships: BTreeSet::new(),
        unresolved_edges: BTreeSet::<SemanticUnresolvedEdge>::new(),
    })
}

fn is_known_malformed_python_external_symbol(
    metadata: &Metadata,
    information: &scip::types::SymbolInformation,
) -> bool {
    is_scip_python(metadata) && information.symbol.starts_with("local ")
}

fn is_scip_python(metadata: &Metadata) -> bool {
    metadata
        .tool_info
        .as_ref()
        .is_some_and(|tool| tool.name == "scip-python")
}

fn is_malformed_python_local_identity(python_provider: bool, raw: &str) -> bool {
    python_provider && raw.starts_with("local ") && scip::symbol::parse_symbol(raw).is_err()
}

fn record_provider_diagnostic(index: &mut SemanticIndex, diagnostic: String) {
    if !index.provenance.diagnostics.contains(&diagnostic) {
        index.provenance.diagnostics.push(diagnostic);
    }
}

fn ingest_document(
    index: &mut SemanticIndex,
    document: &Document,
    expected_languages: Option<&BTreeMap<RepositoryPath, String>>,
    missing_position_encoding: Option<crate::semantic_index::SemanticPositionEncoding>,
    python_provider: bool,
) -> Result<(), String> {
    let path = ranges::normalize_repository_path(&document.relative_path)?;
    let language = if document.language.trim().is_empty() {
        expected_languages
            .and_then(|languages| languages.get(&path))
            .filter(|language| !language.trim().is_empty())
            .cloned()
            .ok_or_else(|| format!("SCIP document {} has no language", path.0))?
    } else {
        document.language.clone()
    };
    if index.documents.contains_key(&path) {
        return Err(format!("SCIP index contains duplicate document {}", path.0));
    }
    let encoding = match ranges::position_encoding(document) {
        Ok(encoding) => encoding,
        Err(error) if document.position_encoding.value() == 0 => {
            missing_position_encoding.ok_or(error)?
        }
        Err(error) => return Err(error),
    };

    for information in &document.symbols {
        if is_malformed_python_local_identity(python_provider, &information.symbol) {
            record_provider_diagnostic(
                index,
                format!(
                    "scip-python emitted malformed local symbol {:?}; the declaration was discarded",
                    information.symbol
                ),
            );
            continue;
        }
        symbols::ingest_symbol_information(index, information, Some(&path), false)?;
    }

    let mut occurrences = Vec::with_capacity(document.occurrences.len());
    for occurrence in &document.occurrences {
        occurrences.push(ingest_occurrence(
            index,
            &path,
            occurrence,
            python_provider,
        )?);
    }
    index.documents.insert(
        path.clone(),
        SemanticDocument {
            path,
            language,
            position_encoding: encoding,
            embedded_text: (!document.text.is_empty()).then(|| document.text.clone()),
            occurrences,
        },
    );
    Ok(())
}

fn ingest_occurrence(
    index: &mut SemanticIndex,
    document: &RepositoryPath,
    occurrence: &Occurrence,
    python_provider: bool,
) -> Result<SemanticOccurrence, String> {
    let range = ranges::occurrence_range(occurrence)?;
    let roles = ranges::occurrence_roles(occurrence.symbol_roles)?;
    if occurrence.symbol.is_empty() && !roles.is_empty() {
        return Err(format!(
            "SCIP occurrence in {} has symbol roles but no symbol",
            document.0
        ));
    }

    let symbol = if occurrence.symbol.is_empty() {
        None
    } else if is_malformed_python_local_identity(python_provider, &occurrence.symbol) {
        record_provider_diagnostic(
            index,
            format!(
                "scip-python emitted malformed local occurrence {:?} in {}; the reference was left unresolved",
                occurrence.symbol, document.0
            ),
        );
        None
    } else {
        let id = symbols::stable_symbol_id(&occurrence.symbol, Some(document))?;
        let is_definition = roles
            .contains(&crate::semantic_index::SemanticOccurrenceRole::Definition)
            || roles.contains(&crate::semantic_index::SemanticOccurrenceRole::ForwardDefinition);
        symbols::ensure_placeholder(
            index,
            id.clone(),
            occurrence.symbol.clone(),
            if is_definition {
                crate::semantic_index::SemanticSymbolOrigin::Repository
            } else {
                crate::semantic_index::SemanticSymbolOrigin::Unknown
            },
        );
        if is_definition {
            let symbol = index.symbols.get_mut(&id).ok_or_else(|| {
                format!("internal error: missing semantic symbol identity {}", id.0)
            })?;
            if symbol.origin == crate::semantic_index::SemanticSymbolOrigin::External {
                return Err(format!(
                    "SCIP symbol {} is both external and defined in the repository",
                    occurrence.symbol
                ));
            }
            symbol.origin = crate::semantic_index::SemanticSymbolOrigin::Repository;
            symbol.definitions.insert(SemanticLocation {
                document: document.clone(),
                range,
            });
        }
        if roles.contains(&crate::semantic_index::SemanticOccurrenceRole::Import) {
            index.imports.insert(SemanticImportEdge {
                document: document.clone(),
                range,
                target: SemanticResolution::Resolved { value: id.clone() },
                reexport: SemanticResolution::Unresolved {
                    reason: crate::semantic_index::SemanticUnresolvedReason::MissingIndexerFact,
                    raw_target: Some(occurrence.symbol.clone()),
                    detail: "SCIP import roles do not encode whether the import is re-exported"
                        .to_string(),
                },
            });
        }
        Some(id)
    };

    Ok(SemanticOccurrence {
        range,
        symbol,
        roles,
        override_documentation: occurrence.override_documentation.clone(),
    })
}

#[cfg(test)]
#[path = "tests/semantic_index_scip.rs"]
mod tests;
