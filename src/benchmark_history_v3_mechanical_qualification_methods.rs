use super::super::{
    HistoricalV3ChangedMethod, HistoricalV3MechanicalPolicy, HistoricalV3NonProductionRole,
    HistoricalV3SemanticSnapshot, HistoricalV3SourceSide, HistoricalV3SourceSnapshot,
    HistoricalV3UnresolvedChangedMethod, IntentionalBoundaryIndexerKind,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
};
use super::roles::{method_role_evidence, roles};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct MethodEvidence {
    pub base_production_count: usize,
    pub merge_production_count: usize,
    pub changed: Vec<HistoricalV3ChangedMethod>,
    pub unresolved: Vec<HistoricalV3UnresolvedChangedMethod>,
    pub non_production_roles: BTreeSet<HistoricalV3NonProductionRole>,
}

#[derive(Clone)]
struct MethodView<'a> {
    side: HistoricalV3SourceSide,
    language: &'a str,
    repository_path: &'a str,
    parser_unit_id: &'a str,
    symbol_name: &'a str,
    start_line: usize,
    end_line: usize,
    source_sha256: &'a str,
    non_whitespace_line_count: usize,
    syntax_sha256: &'a str,
    semantic: &'a IntentionalBoundarySemanticMethod,
}

pub(super) fn method_evidence<'a>(
    policy: &HistoricalV3MechanicalPolicy,
    base: &'a HistoricalV3SourceSnapshot,
    merge: &'a HistoricalV3SourceSnapshot,
    base_semantic: &'a HistoricalV3SemanticSnapshot,
    merge_semantic: &'a HistoricalV3SemanticSnapshot,
    changed_paths: &BTreeSet<&str>,
) -> Result<MethodEvidence, String> {
    let (base_count, base_methods, mut non_production_roles) = method_views(
        HistoricalV3SourceSide::Base,
        policy,
        base,
        base_semantic,
        changed_paths,
    )?;
    let (merge_count, merge_methods, merge_non_production) = method_views(
        HistoricalV3SourceSide::Merge,
        policy,
        merge,
        merge_semantic,
        changed_paths,
    )?;
    non_production_roles.extend(merge_non_production);
    let (mut changed, mut unresolved) = changed_methods(&base_methods, &merge_methods)?;
    changed.sort_by(|left, right| changed_method_key(left).cmp(&changed_method_key(right)));
    unresolved
        .sort_by(|left, right| unresolved_method_key(left).cmp(&unresolved_method_key(right)));
    Ok(MethodEvidence {
        base_production_count: base_count,
        merge_production_count: merge_count,
        changed,
        unresolved,
        non_production_roles,
    })
}

fn method_views<'a>(
    side: HistoricalV3SourceSide,
    policy: &HistoricalV3MechanicalPolicy,
    source: &'a HistoricalV3SourceSnapshot,
    semantic: &'a HistoricalV3SemanticSnapshot,
    changed_paths: &BTreeSet<&str>,
) -> Result<
    (
        usize,
        Vec<MethodView<'a>>,
        BTreeSet<HistoricalV3NonProductionRole>,
    ),
    String,
> {
    let semantic_methods = semantic
        .semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    if semantic_methods.len() != semantic.semantic_census.methods.len() {
        return Err("historical-v3 semantic census repeats a parser unit".to_string());
    }
    let source_facts = source
        .source_file_facts
        .iter()
        .map(|facts| (facts.repository_path.as_str(), facts))
        .collect::<BTreeMap<_, _>>();
    if source_facts.len() != source.source_file_facts.len() {
        return Err("historical-v3 source facts repeat a path".to_string());
    }
    let mut production_count = 0_usize;
    let mut changed = Vec::new();
    let mut non_production = BTreeSet::new();
    for file in &source.source_census.source_files {
        let file_facts = source_facts
            .get(file.repository_path.as_str())
            .copied()
            .ok_or_else(|| "historical-v3 source facts omitted a method file".to_string())?;
        let method_facts = file_facts
            .methods
            .iter()
            .map(|facts| (facts.parser_unit_id.as_str(), facts))
            .collect::<BTreeMap<_, _>>();
        if method_facts.len() != file_facts.methods.len() {
            return Err("historical-v3 source method facts repeat a parser unit".to_string());
        }
        for method in &file.methods {
            let semantic_method = semantic_methods
                .get(method.parser_unit_id.as_str())
                .copied()
                .ok_or_else(|| {
                    format!(
                        "historical-v3 method {} is absent from semantic census",
                        method.parser_unit_id
                    )
                })?;
            let facts = method_facts
                .get(method.parser_unit_id.as_str())
                .copied()
                .ok_or_else(|| "historical-v3 source method facts are incomplete".to_string())?;
            let method_roles = method_role_evidence(&file.repository_path, policy, semantic_method);
            let role_set = roles(&method_roles);
            non_production.extend(role_set.iter().copied());
            if role_set.is_empty() {
                production_count = production_count.checked_add(1).ok_or_else(|| {
                    "historical-v3 production method count overflowed".to_string()
                })?;
                if changed_paths.contains(file.repository_path.as_str()) {
                    changed.push(MethodView {
                        side,
                        language: &file.language,
                        repository_path: &file.repository_path,
                        parser_unit_id: &method.parser_unit_id,
                        symbol_name: &method.symbol_name,
                        start_line: method.start_line,
                        end_line: method.end_line,
                        source_sha256: &method.source_sha256,
                        non_whitespace_line_count: facts.non_whitespace_line_count,
                        syntax_sha256: &facts.syntax_sha256,
                        semantic: semantic_method,
                    });
                }
            }
        }
    }
    Ok((production_count, changed, non_production))
}

fn changed_methods(
    base: &[MethodView<'_>],
    merge: &[MethodView<'_>],
) -> Result<
    (
        Vec<HistoricalV3ChangedMethod>,
        Vec<HistoricalV3UnresolvedChangedMethod>,
    ),
    String,
> {
    let base_resolved = resolved_method_map(base)?;
    let merge_resolved = resolved_method_map(merge)?;
    let keys = base_resolved
        .keys()
        .chain(merge_resolved.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changed = Vec::new();
    for key in keys {
        let base_method = base_resolved.get(&key).copied();
        let merge_method = merge_resolved.get(&key).copied();
        if matches!((base_method, merge_method), (Some(base), Some(merge)) if base.source_sha256 == merge.source_sha256)
        {
            continue;
        }
        changed.extend(base_method.map(|method| resolved_changed_method(method, &key.1)));
        changed.extend(merge_method.map(|method| resolved_changed_method(method, &key.1)));
    }

    let base_unresolved = unresolved_method_map(base)?;
    let merge_unresolved = unresolved_method_map(merge)?;
    let keys = base_unresolved
        .keys()
        .chain(merge_unresolved.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut unresolved = Vec::new();
    for key in keys {
        let base_methods = base_unresolved.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        let merge_methods = merge_unresolved.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        if base_methods.len() > merge_methods.len() {
            unresolved.extend(
                base_methods[merge_methods.len()..]
                    .iter()
                    .map(|method| unresolved_changed_method(method)),
            );
        } else if merge_methods.len() > base_methods.len() {
            unresolved.extend(
                merge_methods[base_methods.len()..]
                    .iter()
                    .map(|method| unresolved_changed_method(method)),
            );
        }
    }
    Ok((changed, unresolved))
}

type ResolvedKey = (IntentionalBoundaryIndexerKind, String);

fn resolved_method_map<'a>(
    methods: &'a [MethodView<'a>],
) -> Result<BTreeMap<ResolvedKey, &'a MethodView<'a>>, String> {
    let mut map = BTreeMap::new();
    for method in methods {
        let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } =
            &method.semantic.status
        else {
            continue;
        };
        if map
            .insert((method.semantic.indexer, symbol.symbol_id.clone()), method)
            .is_some()
        {
            return Err("historical-v3 compiler symbol resolves multiple AST methods".to_string());
        }
    }
    Ok(map)
}

type UnresolvedKey = (
    String,
    String,
    String,
    IntentionalBoundaryIndexerKind,
    String,
);

fn unresolved_method_map<'a>(
    methods: &'a [MethodView<'a>],
) -> Result<BTreeMap<UnresolvedKey, Vec<&'a MethodView<'a>>>, String> {
    let mut map = BTreeMap::<UnresolvedKey, Vec<&MethodView<'_>>>::new();
    for method in methods {
        if matches!(
            method.semantic.status,
            IntentionalBoundarySemanticMethodStatus::Resolved { .. }
        ) {
            continue;
        }
        let status_sha256 = json_sha256(&method.semantic.status)?;
        map.entry((
            method.repository_path.to_string(),
            method.symbol_name.to_string(),
            method.source_sha256.to_string(),
            method.semantic.indexer,
            status_sha256,
        ))
        .or_default()
        .push(method);
    }
    for methods in map.values_mut() {
        methods.sort_by_key(|method| (method.start_line, method.end_line, method.parser_unit_id));
    }
    Ok(map)
}

fn resolved_changed_method(
    method: &MethodView<'_>,
    compiler_symbol_id: &str,
) -> HistoricalV3ChangedMethod {
    HistoricalV3ChangedMethod {
        side: method.side,
        language: method.language.to_string(),
        repository_path: method.repository_path.to_string(),
        parser_unit_id: method.parser_unit_id.to_string(),
        symbol_name: method.symbol_name.to_string(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: method.source_sha256.to_string(),
        non_whitespace_line_count: method.non_whitespace_line_count,
        syntax_sha256: method.syntax_sha256.to_string(),
        indexer: method.semantic.indexer,
        compiler_symbol_id: compiler_symbol_id.to_string(),
    }
}

fn unresolved_changed_method(method: &&MethodView<'_>) -> HistoricalV3UnresolvedChangedMethod {
    HistoricalV3UnresolvedChangedMethod {
        side: method.side,
        language: method.language.to_string(),
        repository_path: method.repository_path.to_string(),
        parser_unit_id: method.parser_unit_id.to_string(),
        symbol_name: method.symbol_name.to_string(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: method.source_sha256.to_string(),
        non_whitespace_line_count: method.non_whitespace_line_count,
        syntax_sha256: method.syntax_sha256.to_string(),
        indexer: method.semantic.indexer,
        status: method.semantic.status.clone(),
    }
}

fn changed_method_key(method: &HistoricalV3ChangedMethod) -> impl Ord + '_ {
    (
        method.side,
        method.repository_path.as_str(),
        method.start_line,
        method.parser_unit_id.as_str(),
    )
}

fn unresolved_method_key(method: &HistoricalV3UnresolvedChangedMethod) -> impl Ord + '_ {
    (
        method.side,
        method.repository_path.as_str(),
        method.start_line,
        method.parser_unit_id.as_str(),
    )
}

fn json_sha256(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 method status: {error}"))
}
