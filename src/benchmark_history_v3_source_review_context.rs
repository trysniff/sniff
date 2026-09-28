use super::super::{
    HistoricalV3ChangedMethod, HistoricalV3MechanicalQualification, HistoricalV3SemanticCensus,
    HistoricalV3SemanticSnapshot, HistoricalV3SourceCensus, HistoricalV3SourceSide,
    HistoricalV3SourceSnapshot, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOccurrenceRole,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution,
};
use super::{
    HistoricalV3ReviewContext, HistoricalV3ReviewContextGap, HistoricalV3ReviewContextGapReason,
    HistoricalV3ReviewContextItem, HistoricalV3ReviewContextRole, HistoricalV3ReviewContextSource,
    HistoricalV3ReviewMethod,
};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CONTEXT_SOURCES_PER_SIDE: usize = 4;
const MAX_CONTEXT_SOURCE_BYTES: usize = 64 * 1024;
const MAX_SINGLE_METHOD_BYTES: usize = 8 * 1024;
const MAX_SINGLE_METHOD_LINES: usize = 100;
const MAX_CONTEXT_FILE_BYTES: u64 = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ContextKey {
    side: HistoricalV3SourceSide,
    anchor_parser_unit_id: String,
    role: HistoricalV3ReviewContextRole,
    target_symbol_id: String,
    target_parser_unit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Selection {
    Method {
        key: ContextKey,
        parser_unit_id: String,
    },
    File {
        key: ContextKey,
        definition: IntentionalBoundarySemanticRange,
    },
    Gap(HistoricalV3ReviewContextGap),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SourceKey {
    Method(HistoricalV3SourceSide, String),
    File(HistoricalV3SourceSide, String),
}

pub(super) fn build_context(
    qualification: &HistoricalV3MechanicalQualification,
    sources: &HistoricalV3SourceCensus,
    semantics: &HistoricalV3SemanticCensus,
    base_records: &[FileRecord],
    merge_records: &[FileRecord],
) -> Result<HistoricalV3ReviewContext, String> {
    let selections = selections(qualification, sources, semantics)?;
    let mut items = Vec::new();
    let mut source_pool = Vec::new();
    let mut source_indexes = BTreeMap::new();
    let mut gaps = Vec::new();
    for selection in selections {
        match selection {
            Selection::Gap(gap) => gaps.push(gap),
            selection => {
                let source_key = selection_source_key(&selection);
                let source_index = if let Some(&index) = source_indexes.get(&source_key) {
                    index
                } else {
                    let source = build_context_source(
                        &selection,
                        sources,
                        semantics,
                        base_records,
                        merge_records,
                    )?;
                    let index = source_pool.len();
                    source_pool.push(source);
                    source_indexes.insert(source_key, index);
                    index
                };
                if let Selection::File { definition, .. } = &selection {
                    require_definition_range(&source_pool[source_index], definition)?;
                }
                items.push(selection_item(&selection, source_index));
            }
        }
    }
    if source_pool.iter().map(context_source_bytes).sum::<usize>() > MAX_CONTEXT_SOURCE_BYTES {
        return Err("historical-v3 reviewer context exceeds the source byte cap".to_string());
    }
    let resolved_context_complete = gaps.is_empty();
    Ok(HistoricalV3ReviewContext {
        sources: source_pool,
        items,
        gaps,
        resolved_context_complete,
    })
}

pub(super) fn validate_context(
    context: &HistoricalV3ReviewContext,
    qualification: &HistoricalV3MechanicalQualification,
    sources: &HistoricalV3SourceCensus,
    semantics: &HistoricalV3SemanticCensus,
) -> Result<(), String> {
    let selections = selections(qualification, sources, semantics)?;
    let mut expected_items = Vec::new();
    let mut expected_sources = Vec::new();
    let mut source_indexes = BTreeMap::new();
    let mut expected_gaps = Vec::new();
    for selection in selections {
        match selection {
            Selection::Gap(gap) => expected_gaps.push(gap),
            selection => {
                let source_key = selection_source_key(&selection);
                let source_index = if let Some(&index) = source_indexes.get(&source_key) {
                    index
                } else {
                    let index = expected_sources.len();
                    expected_sources.push(selection.clone());
                    source_indexes.insert(source_key, index);
                    index
                };
                if let Selection::File { definition, .. } = &selection {
                    let source = context.sources.get(source_index).ok_or_else(|| {
                        "historical-v3 reviewer contract source disappeared".to_string()
                    })?;
                    require_definition_range(source, definition)?;
                }
                expected_items.push(selection_item(&selection, source_index));
            }
        }
    }
    if context.gaps != expected_gaps
        || context.resolved_context_complete != context.gaps.is_empty()
        || context.items != expected_items
        || context.sources.len() != expected_sources.len()
    {
        return Err("historical-v3 reviewer context selection changed".to_string());
    }
    if context
        .sources
        .iter()
        .map(context_source_bytes)
        .sum::<usize>()
        > MAX_CONTEXT_SOURCE_BYTES
    {
        return Err("historical-v3 reviewer context exceeds the source byte cap".to_string());
    }
    for (source, selection) in context.sources.iter().zip(expected_sources) {
        validate_context_source(source, &selection, sources, semantics)?;
    }
    Ok(())
}

fn selections(
    qualification: &HistoricalV3MechanicalQualification,
    sources: &HistoricalV3SourceCensus,
    semantics: &HistoricalV3SemanticCensus,
) -> Result<Vec<Selection>, String> {
    let mut keys = BTreeSet::new();
    let mut gaps = Vec::new();
    for changed in &qualification.evidence.changed_methods {
        let (source, semantic) = match changed.side {
            HistoricalV3SourceSide::Base => (&sources.base, &semantics.base),
            HistoricalV3SourceSide::Merge => (&sources.merge, &semantics.merge),
        };
        let anchor = semantic
            .semantic_census
            .methods
            .iter()
            .find(|method| method.parser_unit_id == changed.parser_unit_id)
            .ok_or_else(|| "historical-v3 reviewer context anchor disappeared".to_string())?;
        let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } = &anchor.status
        else {
            gaps.push(gap(
                changed,
                HistoricalV3ReviewContextRole::ContractDefinition,
                None,
                HistoricalV3ReviewContextGapReason::Unresolved,
            ));
            continue;
        };
        let anchor_id = &symbol.symbol_id;
        let mut callers_by_symbol =
            BTreeMap::<&str, Vec<&IntentionalBoundarySemanticMethod>>::new();
        for method in &semantic.semantic_census.methods {
            if let Some(symbol_id) = resolved_id(method) {
                callers_by_symbol.entry(symbol_id).or_default().push(method);
            }
        }
        for method in &semantic.semantic_census.methods {
            for call in &method.calls {
                if !matches!(&call.callee,
                    IntentionalBoundarySemanticResolution::Resolved { value } if value == anchor_id)
                    || &call.caller == anchor_id
                {
                    continue;
                }
                let mut found = false;
                if let Some(callers) = callers_by_symbol.get(call.caller.as_str()) {
                    for caller in callers {
                        if !source_has_method(source, caller) {
                            continue;
                        }
                        found = true;
                        keys.insert(ContextKey {
                            side: changed.side,
                            anchor_parser_unit_id: changed.parser_unit_id.clone(),
                            role: HistoricalV3ReviewContextRole::DirectCaller,
                            target_symbol_id: call.caller.clone(),
                            target_parser_unit_id: Some(caller.parser_unit_id.clone()),
                        });
                    }
                }
                if !found {
                    gaps.push(gap(
                        changed,
                        HistoricalV3ReviewContextRole::DirectCaller,
                        Some(call.caller.clone()),
                        HistoricalV3ReviewContextGapReason::NoVerifiableSource,
                    ));
                }
            }
        }
        let mut contracts = BTreeSet::new();
        if let Some(IntentionalBoundarySemanticResolution::Resolved { value }) = &symbol.owner {
            contracts.insert(value.clone());
        } else if matches!(
            &symbol.owner,
            Some(IntentionalBoundarySemanticResolution::Unresolved { .. })
        ) {
            gaps.push(gap(
                changed,
                HistoricalV3ReviewContextRole::ContractDefinition,
                None,
                HistoricalV3ReviewContextGapReason::Unresolved,
            ));
        }
        for relation in &anchor.relationships {
            if !matches!(
                relation.kind,
                IntentionalBoundarySemanticRelationshipKind::Implementation
                    | IntentionalBoundarySemanticRelationshipKind::TypeDefinition
                    | IntentionalBoundarySemanticRelationshipKind::Definition
                    | IntentionalBoundarySemanticRelationshipKind::Override
            ) {
                continue;
            }
            if &relation.source == anchor_id {
                contracts.insert(relation.target.clone());
            }
            if &relation.target == anchor_id {
                contracts.insert(relation.source.clone());
            }
        }
        for target_symbol_id in contracts {
            if target_symbol_id != *anchor_id {
                keys.insert(ContextKey {
                    side: changed.side,
                    anchor_parser_unit_id: changed.parser_unit_id.clone(),
                    role: HistoricalV3ReviewContextRole::ContractDefinition,
                    target_symbol_id,
                    target_parser_unit_id: None,
                });
            }
        }
    }
    let mut selected = Vec::new();
    let mut per_side = BTreeMap::new();
    let mut seen_sources = BTreeSet::new();
    for key in keys {
        let (source, semantic) = match key.side {
            HistoricalV3SourceSide::Base => (&sources.base, &semantics.base),
            HistoricalV3SourceSide::Merge => (&sources.merge, &semantics.merge),
        };
        let candidates = semantic
            .semantic_census
            .methods
            .iter()
            .filter(|method| {
                if let Some(parser_unit_id) = &key.target_parser_unit_id {
                    &method.parser_unit_id == parser_unit_id
                } else {
                    resolved_id(method) == Some(key.target_symbol_id.as_str())
                }
            })
            .filter(|method| source_has_method(source, method))
            .collect::<Vec<_>>();
        if candidates.len() > 1 {
            gaps.push(key_gap(
                &key,
                HistoricalV3ReviewContextGapReason::Unresolved,
            ));
            continue;
        }
        let method = candidates.first().copied();
        if let Some(method) = method {
            let lines = source
                .source_census
                .source_files
                .iter()
                .find(|file| file.repository_path == method.repository_path)
                .and_then(|file| {
                    file.methods
                        .iter()
                        .find(|fact| fact.parser_unit_id == method.parser_unit_id)
                })
                .map(|_| method.end_line.saturating_sub(method.start_line) + 1)
                .unwrap_or(usize::MAX);
            let source_key = SourceKey::Method(key.side, method.parser_unit_id.clone());
            if lines > MAX_SINGLE_METHOD_LINES
                || !claim_source_slot(&source_key, &mut seen_sources, &mut per_side)
            {
                gaps.push(key_gap(&key, HistoricalV3ReviewContextGapReason::OverLimit));
            } else {
                selected.push(Selection::Method {
                    key: key.clone(),
                    parser_unit_id: method.parser_unit_id.clone(),
                });
            }
        } else if key.role != HistoricalV3ReviewContextRole::ContractDefinition {
            gaps.push(key_gap(
                &key,
                HistoricalV3ReviewContextGapReason::NoVerifiableSource,
            ));
            continue;
        }
        if key.role == HistoricalV3ReviewContextRole::ContractDefinition {
            let definitions = semantic
                .semantic_census
                .source_references
                .iter()
                .filter(|reference| {
                    reference
                        .roles
                        .contains(&IntentionalBoundarySemanticOccurrenceRole::Definition)
                        || reference
                            .roles
                            .contains(&IntentionalBoundarySemanticOccurrenceRole::ForwardDefinition)
                })
                .filter_map(|reference| match &reference.target {
                    IntentionalBoundarySemanticResolution::Resolved { value }
                        if value.symbol_id == key.target_symbol_id
                            && value.origin
                                == super::super::IntentionalBoundarySemanticOrigin::Repository =>
                    {
                        Some(reference.location.clone())
                    }
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if definitions.is_empty() && method.is_none() {
                gaps.push(key_gap(
                    &key,
                    HistoricalV3ReviewContextGapReason::NoVerifiableSource,
                ));
            }
            for definition in definitions {
                if method.is_some_and(|method| {
                    definition.repository_path == method.repository_path
                        && definition.start_line_zero_based as usize + 1 >= method.start_line
                        && (definition.end_line_zero_based as usize) < method.end_line
                }) {
                    continue;
                }
                let file = source
                    .source_census
                    .source_files
                    .iter()
                    .find(|file| file.repository_path == definition.repository_path);
                let Some(file) = file else {
                    gaps.push(key_gap(
                        &key,
                        HistoricalV3ReviewContextGapReason::NoVerifiableSource,
                    ));
                    continue;
                };
                let source_key = SourceKey::File(key.side, file.repository_path.clone());
                if file.byte_length > MAX_CONTEXT_FILE_BYTES
                    || !claim_source_slot(&source_key, &mut seen_sources, &mut per_side)
                {
                    gaps.push(key_gap(&key, HistoricalV3ReviewContextGapReason::OverLimit));
                    continue;
                }
                selected.push(Selection::File {
                    key: key.clone(),
                    definition,
                });
            }
        }
    }
    gaps.sort_by_key(|gap| {
        (
            gap.side,
            gap.anchor_parser_unit_id.clone(),
            gap.role,
            gap.target_symbol_id.clone(),
            gap.reason,
        )
    });
    gaps.dedup();
    selected.extend(gaps.into_iter().map(Selection::Gap));
    Ok(selected)
}

fn claim_source_slot(
    key: &SourceKey,
    seen: &mut BTreeSet<SourceKey>,
    per_side: &mut BTreeMap<HistoricalV3SourceSide, usize>,
) -> bool {
    if seen.contains(key) {
        return true;
    }
    let side = match key {
        SourceKey::Method(side, _) | SourceKey::File(side, _) => *side,
    };
    let count = per_side.entry(side).or_default();
    if *count >= MAX_CONTEXT_SOURCES_PER_SIDE {
        return false;
    }
    *count += 1;
    seen.insert(key.clone());
    true
}

fn context_source_bytes(source: &HistoricalV3ReviewContextSource) -> usize {
    match source {
        HistoricalV3ReviewContextSource::Method { method } => method.source.len(),
        HistoricalV3ReviewContextSource::File { source, .. } => source.len(),
    }
}

fn require_definition_range(
    context_source: &HistoricalV3ReviewContextSource,
    definition: &IntentionalBoundarySemanticRange,
) -> Result<(), String> {
    let HistoricalV3ReviewContextSource::File {
        repository_path,
        source,
        ..
    } = context_source
    else {
        return Err("historical-v3 contract definition has no file source".to_string());
    };
    if repository_path != &definition.repository_path {
        return Err("historical-v3 contract definition changed its file".to_string());
    }
    let lines = source
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    let start = lines.get(definition.start_line_zero_based as usize);
    let end = lines.get(definition.end_line_zero_based as usize);
    if start.is_none_or(|line| {
        !encoding_independent_offset(line, definition.start_character_zero_based as usize)
    }) || end.is_none_or(|line| {
        !encoding_independent_offset(line, definition.end_character_zero_based as usize)
    }) || definition.end_line_zero_based < definition.start_line_zero_based
        || (definition.end_line_zero_based == definition.start_line_zero_based
            && definition.end_character_zero_based <= definition.start_character_zero_based)
    {
        return Err("historical-v3 contract definition range escapes frozen source".to_string());
    }
    Ok(())
}

fn encoding_independent_offset(line: &str, offset: usize) -> bool {
    line.get(..offset).is_some_and(str::is_ascii)
}

fn selection_source_key(selection: &Selection) -> SourceKey {
    match selection {
        Selection::Method {
            key,
            parser_unit_id,
        } => SourceKey::Method(key.side, parser_unit_id.clone()),
        Selection::File { key, definition } => {
            SourceKey::File(key.side, definition.repository_path.clone())
        }
        Selection::Gap(_) => unreachable!("gaps have no source"),
    }
}

fn selection_item(selection: &Selection, source_index: usize) -> HistoricalV3ReviewContextItem {
    let (key, definition) = match selection {
        Selection::Method { key, .. } => (key, None),
        Selection::File { key, definition } => (key, Some(definition.clone())),
        Selection::Gap(_) => unreachable!("gaps have no source"),
    };
    HistoricalV3ReviewContextItem {
        anchor_parser_unit_id: key.anchor_parser_unit_id.clone(),
        role: key.role,
        target_symbol_id: key.target_symbol_id.clone(),
        source_index,
        definition,
    }
}

fn build_context_source(
    selection: &Selection,
    sources: &HistoricalV3SourceCensus,
    semantics: &HistoricalV3SemanticCensus,
    base_records: &[FileRecord],
    merge_records: &[FileRecord],
) -> Result<HistoricalV3ReviewContextSource, String> {
    match selection {
        Selection::Method {
            key,
            parser_unit_id,
        } => {
            let (source, semantic, records) = match key.side {
                HistoricalV3SourceSide::Base => (&sources.base, &semantics.base, base_records),
                HistoricalV3SourceSide::Merge => (&sources.merge, &semantics.merge, merge_records),
            };
            Ok(HistoricalV3ReviewContextSource::Method {
                method: Box::new(context_method(
                    parser_unit_id,
                    key.side,
                    source,
                    semantic,
                    records,
                )?),
            })
        }
        Selection::File { key, definition } => {
            let (source, records) = match key.side {
                HistoricalV3SourceSide::Base => (&sources.base, base_records),
                HistoricalV3SourceSide::Merge => (&sources.merge, merge_records),
            };
            context_file(key, definition, source, records)
        }
        Selection::Gap(_) => unreachable!("gaps have no source"),
    }
}

fn context_file(
    key: &ContextKey,
    definition: &IntentionalBoundarySemanticRange,
    source: &HistoricalV3SourceSnapshot,
    records: &[FileRecord],
) -> Result<HistoricalV3ReviewContextSource, String> {
    let index = source
        .source_census
        .source_files
        .iter()
        .position(|file| file.repository_path == definition.repository_path)
        .ok_or_else(|| "historical-v3 reviewer contract file disappeared".to_string())?;
    let file = &source.source_census.source_files[index];
    let record = records
        .get(index)
        .ok_or_else(|| "historical-v3 reviewer contract source disappeared".to_string())?;
    if record.source.len() as u64 != file.byte_length
        || file.byte_length > MAX_CONTEXT_FILE_BYTES
        || sha256(record.source.as_bytes()) != file.source_sha256
    {
        return Err(
            "historical-v3 reviewer contract file does not match source census".to_string(),
        );
    }
    Ok(HistoricalV3ReviewContextSource::File {
        side: key.side,
        repository_path: file.repository_path.clone(),
        source_sha256: file.source_sha256.clone(),
        source: record.source.clone(),
    })
}

fn validate_context_source(
    context_source: &HistoricalV3ReviewContextSource,
    selection: &Selection,
    sources: &HistoricalV3SourceCensus,
    semantics: &HistoricalV3SemanticCensus,
) -> Result<(), String> {
    let key = match selection {
        Selection::Method { key, .. } | Selection::File { key, .. } => key,
        Selection::Gap(_) => {
            return Err("historical-v3 reviewer context selection changed".to_string());
        }
    };
    let (source, semantic) = match key.side {
        HistoricalV3SourceSide::Base => (&sources.base, &semantics.base),
        HistoricalV3SourceSide::Merge => (&sources.merge, &semantics.merge),
    };
    match (selection, context_source) {
        (
            Selection::Method { parser_unit_id, .. },
            HistoricalV3ReviewContextSource::Method { method },
        ) => {
            if method.side != key.side || method.parser_unit_id != *parser_unit_id {
                return Err("historical-v3 reviewer context method anchor changed".to_string());
            }
            let expected = semantic
                .semantic_census
                .methods
                .iter()
                .find(|fact| fact.parser_unit_id == *parser_unit_id)
                .ok_or_else(|| "historical-v3 reviewer context method disappeared".to_string())?;
            let file = source
                .source_census
                .source_files
                .iter()
                .find(|file| file.repository_path == expected.repository_path)
                .ok_or_else(|| "historical-v3 reviewer context file disappeared".to_string())?;
            let parsed = file
                .methods
                .iter()
                .find(|fact| fact.parser_unit_id == *parser_unit_id)
                .ok_or_else(|| "historical-v3 reviewer context source disappeared".to_string())?;
            if method.repository_path != expected.repository_path
                || method.symbol_name != expected.symbol_name
                || method.start_line != expected.start_line
                || method.end_line != expected.end_line
                || method.source_sha256 != parsed.source_sha256
                || sha256(method.source.as_bytes()) != parsed.source_sha256
                || method.semantic != *expected
                || method.language != file.language
                || method.source.len() > MAX_SINGLE_METHOD_BYTES
            {
                return Err("historical-v3 reviewer context source changed".to_string());
            }
        }
        (
            Selection::File { definition, .. },
            HistoricalV3ReviewContextSource::File {
                side,
                repository_path,
                source_sha256,
                source: text,
            },
        ) => {
            let file = source
                .source_census
                .source_files
                .iter()
                .find(|file| file.repository_path == definition.repository_path)
                .ok_or_else(|| "historical-v3 reviewer contract file disappeared".to_string())?;
            if *side != key.side
                || repository_path != &file.repository_path
                || source_sha256 != &file.source_sha256
                || text.len() as u64 != file.byte_length
                || file.byte_length > MAX_CONTEXT_FILE_BYTES
                || sha256(text.as_bytes()) != file.source_sha256
            {
                return Err("historical-v3 reviewer contract source changed".to_string());
            }
        }
        _ => return Err("historical-v3 reviewer context source kind changed".to_string()),
    }
    Ok(())
}

fn context_method(
    parser_unit_id: &str,
    side: HistoricalV3SourceSide,
    source: &HistoricalV3SourceSnapshot,
    semantic: &HistoricalV3SemanticSnapshot,
    records: &[FileRecord],
) -> Result<HistoricalV3ReviewMethod, String> {
    let method = semantic
        .semantic_census
        .methods
        .iter()
        .find(|method| method.parser_unit_id == parser_unit_id)
        .ok_or_else(|| "historical-v3 reviewer context semantic method disappeared".to_string())?;
    let index = source
        .source_census
        .source_files
        .iter()
        .position(|file| file.repository_path == method.repository_path)
        .ok_or_else(|| "historical-v3 reviewer context file disappeared".to_string())?;
    let file = &source.source_census.source_files[index];
    let method_index = file
        .methods
        .iter()
        .position(|fact| fact.parser_unit_id == parser_unit_id)
        .ok_or_else(|| "historical-v3 reviewer context parsed method disappeared".to_string())?;
    let record = records
        .get(index)
        .ok_or_else(|| "historical-v3 reviewer context record disappeared".to_string())?;
    let parsed = record
        .methods
        .get(method_index)
        .ok_or_else(|| "historical-v3 reviewer context source disappeared".to_string())?;
    if parsed.start_line != method.start_line
        || parsed.end_line != method.end_line
        || parsed.name != method.symbol_name
        || sha256(parsed.source.as_bytes()) != file.methods[method_index].source_sha256
        || parsed.source.len() > MAX_SINGLE_METHOD_BYTES
    {
        return Err("historical-v3 reviewer context source does not match census".to_string());
    }
    Ok(HistoricalV3ReviewMethod {
        side,
        language: parsed.language.clone(),
        repository_path: method.repository_path.clone(),
        parser_unit_id: parser_unit_id.to_string(),
        symbol_name: method.symbol_name.clone(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: file.methods[method_index].source_sha256.clone(),
        source: parsed.source.clone(),
        semantic: method.clone(),
    })
}

fn source_has_method(
    source: &HistoricalV3SourceSnapshot,
    method: &IntentionalBoundarySemanticMethod,
) -> bool {
    source
        .source_census
        .source_files
        .iter()
        .find(|file| file.repository_path == method.repository_path)
        .is_some_and(|file| {
            file.methods
                .iter()
                .any(|fact| fact.parser_unit_id == method.parser_unit_id)
        })
}

fn resolved_id(method: &IntentionalBoundarySemanticMethod) -> Option<&str> {
    match &method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => Some(&symbol.symbol_id),
        _ => None,
    }
}

fn gap(
    changed: &HistoricalV3ChangedMethod,
    role: HistoricalV3ReviewContextRole,
    target_symbol_id: Option<String>,
    reason: HistoricalV3ReviewContextGapReason,
) -> HistoricalV3ReviewContextGap {
    HistoricalV3ReviewContextGap {
        side: changed.side,
        anchor_parser_unit_id: changed.parser_unit_id.clone(),
        role,
        target_symbol_id,
        reason,
    }
}

fn key_gap(
    key: &ContextKey,
    reason: HistoricalV3ReviewContextGapReason,
) -> HistoricalV3ReviewContextGap {
    HistoricalV3ReviewContextGap {
        side: key.side,
        anchor_parser_unit_id: key.anchor_parser_unit_id.clone(),
        role: key.role,
        target_symbol_id: (!key.target_symbol_id.is_empty()).then(|| key.target_symbol_id.clone()),
        reason,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_positions_fail_closed_without_a_recorded_encoding() {
        let source = HistoricalV3ReviewContextSource::File {
            side: HistoricalV3SourceSide::Base,
            repository_path: "src/contract.rs".to_string(),
            source_sha256: sha256("type Name\n".as_bytes()),
            source: "type Name\n".to_string(),
        };
        let mut definition = IntentionalBoundarySemanticRange {
            repository_path: "src/contract.rs".to_string(),
            start_line_zero_based: 0,
            start_character_zero_based: 5,
            end_line_zero_based: 0,
            end_character_zero_based: 9,
        };
        require_definition_range(&source, &definition).unwrap();

        let non_ascii = HistoricalV3ReviewContextSource::File {
            side: HistoricalV3SourceSide::Base,
            repository_path: "src/contract.rs".to_string(),
            source_sha256: sha256("éName\n".as_bytes()),
            source: "éName\n".to_string(),
        };
        definition.start_character_zero_based = 1;
        definition.end_character_zero_based = 5;
        assert!(require_definition_range(&non_ascii, &definition).is_err());
        definition.start_character_zero_based = 2;
        assert!(require_definition_range(&non_ascii, &definition).is_err());
    }
}
