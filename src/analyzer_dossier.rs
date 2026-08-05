use crate::roles::{
    FileRole, classify_file_role, file_role_label, is_callback_contract_module,
    is_compatibility_shim_record, is_language_protocol_method, is_protocol_stub_method,
    is_protocol_surface_module, is_thin_wrapper_export,
};
use crate::symbol_graph::SymbolGraph;
use crate::types::{FileRecord, MethodRecord, Reference, SymbolDefinition};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const MAX_LEXICAL_CALL_ROOTS: usize = 8;
const MAX_LEXICAL_CHAIN_METHODS: usize = 16;
const MAX_LEXICAL_CHAIN_DEPTH: usize = 2;

#[derive(Debug, Clone)]
pub(super) struct MethodDossier {
    pub(super) full_file: Arc<str>,
    pub(super) context: String,
    pub(super) project_root: Box<PathBuf>,
    pub(super) boundary_requirements: Vec<String>,
    pub(super) callees: Vec<Reference>,
    pub(super) repository_private_unused_candidate: bool,
    pub(super) stale_discard_signature_proof: Option<Box<StaleDiscardSignatureProof>>,
}

#[derive(Debug, Clone, Copy)]
struct SourceLocation {
    file_index: usize,
    line_index: usize,
}

#[derive(Debug, Clone)]
struct GraphLocation {
    path: String,
    index: usize,
}

pub(super) struct DossierRepositoryIndex<'a> {
    graph: &'a SymbolGraph,
    file_records: &'a [FileRecord],
    files_by_lower_path: HashMap<String, usize>,
    source_lines: Vec<Vec<&'a str>>,
    identifier_locations: HashMap<String, Vec<SourceLocation>>,
    test_files_by_referenced_name: HashMap<String, Vec<usize>>,
    resolved_sites_by_leaf: HashMap<String, HashSet<(String, usize)>>,
    unresolved_sites_by_leaf: HashMap<String, HashSet<(String, usize)>>,
    definitions_by_name: HashMap<String, Vec<GraphLocation>>,
    imports_by_name: HashMap<String, Vec<GraphLocation>>,
    exports_by_name: HashMap<String, Vec<GraphLocation>>,
    numbered_files: HashMap<String, Arc<str>>,
    test_runner_methods: HashSet<(String, usize)>,
    private_js_ts_package_files: HashSet<String>,
}

impl<'a> DossierRepositoryIndex<'a> {
    fn source_locations(&self, identifier: &str) -> Vec<SourceLocation> {
        if identifier.chars().all(is_identifier_char) {
            return self
                .identifier_locations
                .get(identifier)
                .cloned()
                .unwrap_or_default();
        }

        self.source_lines
            .iter()
            .enumerate()
            .flat_map(|(file_index, lines)| {
                lines
                    .iter()
                    .enumerate()
                    .filter_map(move |(line_index, line)| {
                        contains_identifier(line, identifier).then_some(SourceLocation {
                            file_index,
                            line_index,
                        })
                    })
            })
            .collect()
    }

    fn file_by_lower_path(&self, path: &str) -> Option<&'a FileRecord> {
        self.files_by_lower_path
            .get(path)
            .and_then(|index| self.file_records.get(*index))
    }

    fn source_window(&self, location: SourceLocation) -> String {
        let file = &self.file_records[location.file_index];
        let lines = &self.source_lines[location.file_index];
        let start = location.line_index.saturating_sub(2);
        let end = (location.line_index + 11).min(lines.len());
        (start..end)
            .map(|index| {
                format!(
                    "{}:{}: {}",
                    file.file_path,
                    index + 1,
                    lines[index].trim_end()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub(super) fn build_dossier_repository_index<'a>(
    graph: &'a SymbolGraph,
    file_records: &'a [FileRecord],
) -> DossierRepositoryIndex<'a> {
    let mut files_by_lower_path = HashMap::new();
    let mut source_lines = Vec::with_capacity(file_records.len());
    let mut identifier_locations = HashMap::<String, Vec<SourceLocation>>::new();
    let mut numbered_files = HashMap::new();
    let mut test_runner_methods = HashSet::new();
    let mut private_js_ts_package_files = HashSet::new();

    for (file_index, file) in file_records.iter().enumerate() {
        let lower_path = file.file_path.to_lowercase();
        if matches!(file.language.as_str(), "javascript" | "typescript")
            && nearest_js_ts_package_is_private(&graph.project_root, &file.file_path)
        {
            private_js_ts_package_files.insert(lower_path.clone());
        }
        files_by_lower_path.insert(lower_path.clone(), file_index);
        numbered_files.insert(
            lower_path.clone(),
            Arc::from(numbered_source(&file.source, 1)),
        );
        test_runner_methods.extend(
            crate::scorer::method::cfg_test_method_lines(file)
                .into_iter()
                .map(|line| (lower_path.clone(), line)),
        );

        let lines = file.source.lines().collect::<Vec<_>>();
        for (line_index, line) in lines.iter().enumerate() {
            let mut seen = HashSet::new();
            let mut start = None;
            for (index, character) in line
                .char_indices()
                .chain(std::iter::once((line.len(), '\0')))
            {
                if is_identifier_char(character) {
                    start.get_or_insert(index);
                } else if let Some(token_start) = start.take() {
                    let token = &line[token_start..index];
                    if seen.insert(token) {
                        identifier_locations
                            .entry(token.to_string())
                            .or_default()
                            .push(SourceLocation {
                                file_index,
                                line_index,
                            });
                    }
                }
            }
        }
        source_lines.push(lines);
    }

    let referenced_names = file_records
        .iter()
        .filter_map(|file| {
            file.file_path
                .rsplit(['/', '\\'])
                .find(|part| !part.is_empty())
        })
        .collect::<HashSet<_>>();
    let mut test_files_by_referenced_name = HashMap::<String, Vec<usize>>::new();
    for file_name in referenced_names {
        for (file_index, file) in file_records.iter().enumerate() {
            if is_test_path(&file.file_path.to_lowercase())
                && source_lines[file_index]
                    .iter()
                    .any(|line| contains_identifier(line, file_name))
            {
                test_files_by_referenced_name
                    .entry(file_name.to_string())
                    .or_default()
                    .push(file_index);
            }
        }
    }

    let mut resolved_sites_by_leaf = HashMap::<String, HashSet<(String, usize)>>::new();
    let mut unresolved_sites_by_leaf = HashMap::<String, HashSet<(String, usize)>>::new();
    let mut definitions_by_name = HashMap::<String, Vec<GraphLocation>>::new();
    let mut imports_by_name = HashMap::<String, Vec<GraphLocation>>::new();
    let mut exports_by_name = HashMap::<String, Vec<GraphLocation>>::new();

    for (path, symbols) in &graph.files {
        let lower_path = path.to_lowercase();
        for reference in &symbols.references {
            let leaf_name = reference
                .name
                .rsplit(['.', ':'])
                .find(|part| !part.is_empty())
                .unwrap_or(&reference.name)
                .to_string();
            let sites = if reference.resolved_symbol.is_some() {
                &mut resolved_sites_by_leaf
            } else {
                &mut unresolved_sites_by_leaf
            };
            sites
                .entry(leaf_name)
                .or_default()
                .insert((lower_path.clone(), reference.line));
        }
        for (index, definition) in symbols.definitions.iter().enumerate() {
            definitions_by_name
                .entry(definition.name.clone())
                .or_default()
                .push(GraphLocation {
                    path: path.clone(),
                    index,
                });
        }
        for (index, import) in symbols.imports.iter().enumerate() {
            let location = GraphLocation {
                path: path.clone(),
                index,
            };
            imports_by_name
                .entry(import.local_name.clone())
                .or_default()
                .push(location.clone());
            if import.imported_name != import.local_name {
                imports_by_name
                    .entry(import.imported_name.clone())
                    .or_default()
                    .push(location);
            }
        }
        for (index, export) in symbols.exports.iter().enumerate() {
            let location = GraphLocation {
                path: path.clone(),
                index,
            };
            let mut names = vec![
                export.exported_name.as_str(),
                export.local_symbol_name.as_str(),
            ];
            if let Some(name) = export.source_symbol_name.as_deref() {
                names.push(name);
            }
            names.sort_unstable();
            names.dedup();
            for name in names {
                exports_by_name
                    .entry(name.to_string())
                    .or_default()
                    .push(location.clone());
            }
        }
    }

    DossierRepositoryIndex {
        graph,
        file_records,
        files_by_lower_path,
        source_lines,
        identifier_locations,
        test_files_by_referenced_name,
        resolved_sites_by_leaf,
        unresolved_sites_by_leaf,
        definitions_by_name,
        imports_by_name,
        exports_by_name,
        numbered_files,
        test_runner_methods,
        private_js_ts_package_files,
    }
}

fn nearest_js_ts_package_is_private(project_root: &str, file_path: &str) -> bool {
    let root = PathBuf::from(project_root);
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .map(|current| current.join(root))
            .unwrap_or_else(|_| PathBuf::from(project_root))
    };
    let source = Path::new(file_path);
    let source = if source.is_absolute() {
        source.to_path_buf()
    } else {
        root.join(source)
    };
    let mut directory = source.parent();

    while let Some(current) = directory {
        if !current.starts_with(&root) {
            break;
        }
        let manifest = current.join("package.json");
        if manifest.is_file() {
            return std::fs::read_to_string(manifest)
                .ok()
                .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok())
                .and_then(|value| value.get("private").and_then(serde_json::Value::as_bool))
                .unwrap_or(false);
        }
        if current == root {
            break;
        }
        directory = current.parent();
    }

    false
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct StaleDiscardSignatureProof {
    pub(super) discarded_parameters: Vec<String>,
    pub(super) caller_sites: Vec<String>,
}

impl StaleDiscardSignatureProof {
    pub(super) fn render(&self) -> String {
        format!(
            "discarded parameters: {}; closed resolved caller sites: {}",
            self.discarded_parameters.join(", "),
            self.caller_sites.join("; ")
        )
    }
}

#[derive(Debug)]
struct RepositoryFacts {
    rendered: String,
    has_protocol_contract: bool,
    has_callback_contract: bool,
    has_compatibility_contract: bool,
    has_external_contract_evidence: bool,
    has_repository_external_visibility: bool,
    repository_private_unused_candidate: bool,
    stale_discard_signature_proof: Option<Box<StaleDiscardSignatureProof>>,
}

#[cfg(test)]
pub(super) fn build_method_dossier(
    file: &FileRecord,
    method: &MethodRecord,
    graph: &SymbolGraph,
    file_records: &[FileRecord],
    callees: Vec<Reference>,
) -> MethodDossier {
    let index = build_dossier_repository_index(graph, file_records);
    build_method_dossier_with_index(file, method, &index, callees)
}

pub(super) fn build_method_dossier_with_index(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
    callees: Vec<Reference>,
) -> MethodDossier {
    let graph = index.graph;
    let symbols = graph.files.get(&file.file_path);
    let full_file = index
        .numbered_files
        .get(&file.file_path.to_lowercase())
        .cloned()
        .unwrap_or_else(|| Arc::from(numbered_source(&file.source, 1)));
    let symbol_facts = symbols
        .map(|symbols| render_symbol_facts(symbols, method))
        .unwrap_or_else(|| "symbol graph: no parsed symbol record for this file".to_string());
    let repository_facts = render_repository_facts(file, method, index);
    let boundary_requirements = boundary_requirements(file, method, &repository_facts);
    let context = format!(
        "Method dossier:\n\
- file role: {}\n\
- role contract evidence: {}\n\
- visibility/export status: {}\n\
- symbol and boundary facts:\n{}\n\
- repository evidence:\n{}",
        file_role_label(classify_file_role(&file.file_path)),
        role_contract_evidence(classify_file_role(&file.file_path)),
        visibility(method, index),
        symbol_facts,
        repository_facts.rendered,
    );

    MethodDossier {
        full_file,
        context,
        project_root: Box::new(PathBuf::from(&graph.project_root)),
        boundary_requirements,
        callees,
        repository_private_unused_candidate: repository_facts.repository_private_unused_candidate,
        stale_discard_signature_proof: repository_facts.stale_discard_signature_proof,
    }
}

fn role_contract_evidence(role: FileRole) -> &'static str {
    match role {
        FileRole::Entrypoint => {
            "entrypoints are invoked by a runtime or command boundary; zero internal callers is expected"
        }
        FileRole::Script => {
            "scripts are invoked directly by users or automation; zero internal callers is expected"
        }
        FileRole::Example => {
            "example code demonstrates an integration to a human consumer; coherent demonstration is its contract"
        }
        FileRole::Fixture => {
            "fixtures represent scenarios consumed by tests or tools; direct production callers are not required"
        }
        FileRole::Test => {
            "test methods are invoked by the test runner and may intentionally expose test seams"
        }
        FileRole::Docs => {
            "documentation code is consumed by readers or documentation tooling rather than production callers"
        }
        FileRole::Generated => "generated methods implement their generator's output contract",
        FileRole::AdapterIntegration => {
            "adapter methods require evidence of their framework or external-system translation contract"
        }
        FileRole::Library | FileRole::Mixed => {
            "no role-level external invocation contract is established; repository evidence must justify the method"
        }
    }
}

fn method_role_consumer(role: FileRole, method: &MethodRecord) -> bool {
    matches!(role, FileRole::Entrypoint | FileRole::Script)
        && (matches!(method.name.as_str(), "main" | "default")
            || method.source.trim_start().starts_with("export default"))
}

fn boundary_requirements(
    file: &FileRecord,
    method: &MethodRecord,
    facts: &RepositoryFacts,
) -> Vec<String> {
    let role = classify_file_role(&file.file_path);
    let intentional_surface = matches!(
        role,
        FileRole::Entrypoint
            | FileRole::Script
            | FileRole::Example
            | FileRole::Fixture
            | FileRole::Test
            | FileRole::Docs
            | FileRole::Generated
    );
    let mut requirements = Vec::new();

    if facts.has_repository_external_visibility
        && method.real_ref_count == 0
        && !intentional_surface
        && is_thin_wrapper_export(method)
        && !facts.has_external_contract_evidence
    {
        requirements.push(
            "external consumers of this exported method are not resolvable from the repository"
                .to_string(),
        );
    }
    if (is_protocol_stub_method(method) || is_protocol_surface_module(file))
        && !facts.has_protocol_contract
    {
        requirements.push(
            "protocol implementations and the external protocol contract are not fully resolvable"
                .to_string(),
        );
    }
    if is_callback_contract_module(file)
        && facts.has_repository_external_visibility
        && method.real_ref_count == 0
        && !facts.has_external_contract_evidence
        && !facts.has_callback_contract
    {
        requirements.push(
            "callback registrations and consumers outside the resolved graph are not fully resolvable"
                .to_string(),
        );
    }
    if is_compatibility_shim_record(file) && !facts.has_compatibility_contract {
        requirements.push(
            "compatibility and migration consumers outside the resolved repository are not fully resolvable"
                .to_string(),
        );
    }

    requirements
}

fn numbered_source(source: &str, first_line: usize) -> String {
    source
        .lines()
        .enumerate()
        .map(|(offset, line)| format!("{:>6} | {line}", first_line + offset))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
fn render_references(references: &[Reference]) -> String {
    if references.is_empty() {
        return "none resolved".to_string();
    }

    references
        .iter()
        .enumerate()
        .map(|(index, reference)| {
            format!(
                "{}. {}:{}\n{}",
                index + 1,
                reference.file_path,
                reference.line,
                reference.snippet
            )
        })
        .collect::<Vec<_>>()
        .join("\n---\n")
}

fn visibility(method: &MethodRecord, index: &DossierRepositoryIndex<'_>) -> &'static str {
    if method.language == "rust" {
        let declaration = rust_declaration_line(method);
        if declaration.starts_with("pub(") {
            return "repository-restricted Rust visibility; external consumers cannot invoke it";
        }
        if declaration.starts_with("pub ") {
            return "externally public Rust visibility";
        }
        if method.is_exported {
            return "Rust trait/protocol contract visibility";
        }
        return "private Rust visibility";
    }
    if method.is_exported && js_ts_file_is_in_private_package(method, index) {
        "module-exported inside a private JavaScript/TypeScript package; repository consumers form a closed world"
    } else if method.is_exported {
        "exported/public according to the parser"
    } else {
        "not exported according to the parser"
    }
}

fn rust_declaration_line(method: &MethodRecord) -> &str {
    method
        .source
        .lines()
        .map(str::trim)
        .find(|line| line.contains("fn "))
        .unwrap_or_default()
}

pub(super) fn has_external_visibility(method: &MethodRecord) -> bool {
    if method.language != "rust" {
        return method.is_exported;
    }
    let declaration = rust_declaration_line(method);
    if declaration.starts_with("pub(") {
        return false;
    }
    declaration.starts_with("pub ") || method.is_exported
}

fn js_ts_file_is_in_private_package(
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> bool {
    matches!(method.language.as_str(), "javascript" | "typescript")
        && index
            .private_js_ts_package_files
            .contains(&method.file_path.to_lowercase())
}

fn has_repository_external_visibility(
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> bool {
    has_external_visibility(method) && !js_ts_file_is_in_private_package(method, index)
}

fn is_inline_anonymous_callback(method: &MethodRecord) -> bool {
    matches!(method.language.as_str(), "javascript" | "typescript")
        && method.name.starts_with("<anonymous@")
        && method.name.ends_with('>')
}

#[path = "analyzer_dossier_js_ts.rs"]
mod js_ts;
use js_ts::*;

fn render_symbol_facts(symbols: &crate::types::LocalFileSymbols, method: &MethodRecord) -> String {
    let definitions = symbols
        .definitions
        .iter()
        .filter(|definition| {
            definition.name == method.name
                && definition.start_line <= method.start_line
                && method.end_line <= definition.end_line
        })
        .map(render_definition)
        .collect::<Vec<_>>();
    let imports = symbols
        .imports
        .iter()
        .filter(|item| item.local_name == method.name || item.imported_name == method.name)
        .map(|item| {
            format!(
                "{} <- {} from {}",
                item.local_name, item.imported_name, item.source_module
            )
        })
        .collect::<Vec<_>>();
    let exports = symbols
        .exports
        .iter()
        .filter(|item| {
            (item.source_module.is_some() || has_external_visibility(method))
                && (item.local_symbol_name == method.name
                    || item.source_symbol_name.as_deref() == Some(method.name.as_str())
                    || item.exported_name == method.name)
        })
        .map(|item| {
            let source = item.source_module.as_deref().unwrap_or("local definition");
            let source_symbol = item.source_symbol_name.as_deref().unwrap_or("-");
            format!(
                "{} -> {} (source symbol: {})",
                item.exported_name, source, source_symbol
            )
        })
        .collect::<Vec<_>>();

    format!(
        "definitions:\n{}\nimports:\n{}\nexports/re-exports:\n{}",
        if_empty(definitions),
        if_empty(imports),
        if_empty(exports)
    )
}

fn render_definition(definition: &SymbolDefinition) -> String {
    format!(
        "{} {:?} lines {}-{} exported={} owner={}",
        definition.name,
        definition.kind,
        definition.start_line,
        definition.end_line,
        definition.is_exported,
        definition.owner_type.as_deref().unwrap_or("none")
    )
}

fn if_empty(lines: Vec<String>) -> String {
    if lines.is_empty() {
        "none established".to_string()
    } else {
        lines
            .into_iter()
            .map(|line| format!("- {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn type_leaf(name: &str) -> &str {
    name.rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn trailing_identifier(value: &str) -> &str {
    let value = value.trim_end();
    let start = value
        .char_indices()
        .rev()
        .find(|(_, ch)| !is_identifier_char(*ch))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    &value[start..]
}

fn direct_type_bases(graph: &SymbolGraph, owner: &str) -> HashSet<String> {
    graph
        .files
        .values()
        .flat_map(|symbols| &symbols.types)
        .filter(|record| type_leaf(&record.name) == type_leaf(owner))
        .flat_map(|record| record.bases.iter())
        .map(|base| type_leaf(base).to_string())
        .filter(|base| !matches!(base.as_str(), "Any" | "Object" | "object"))
        .collect()
}

fn object_computed_invocation_evidence(
    owner_name: &str,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let marker = format!("{owner_name}[");
    index
        .file_records
        .iter()
        .enumerate()
        .flat_map(|(file_index, _)| {
            let marker = marker.clone();
            index.source_lines[file_index]
                .iter()
                .enumerate()
                .filter_map(move |(line_index, line)| {
                    let after_owner = line.split_once(&marker)?.1;
                    let after_key = after_owner.split_once(']')?.1.trim_start();
                    (after_key.starts_with('(') || after_key.starts_with("?.(")).then(|| {
                        index.source_window(SourceLocation {
                            file_index,
                            line_index,
                        })
                    })
                })
        })
        .collect()
}

fn owners_share_contract(graph: &SymbolGraph, target: &str, candidate: &str) -> bool {
    let target = type_leaf(target);
    let candidate = type_leaf(candidate);
    if target == candidate {
        return true;
    }
    let target_bases = direct_type_bases(graph, target);
    let candidate_bases = direct_type_bases(graph, candidate);
    target_bases.contains(candidate)
        || candidate_bases.contains(target)
        || !target_bases.is_disjoint(&candidate_bases)
}

fn owner_at_line<'a>(graph: &'a SymbolGraph, file_path: &str, line: usize) -> Option<&'a str> {
    graph
        .files
        .get(file_path)
        .and_then(|symbols| {
            symbols
                .definitions
                .iter()
                .filter(|definition| {
                    definition.start_line <= line
                        && line <= definition.end_line
                        && matches!(&definition.kind, crate::types::SymbolKind::Method)
                        && definition.owner_type.is_some()
                })
                .min_by_key(|definition| definition.end_line - definition.start_line)
        })
        .and_then(|definition| definition.owner_type.as_deref())
}

fn rust_method_has_receiver(method: &MethodRecord) -> bool {
    method
        .source
        .split_once('{')
        .map(|(signature, _)| contains_identifier(signature, "self"))
        .unwrap_or(false)
}

fn kotlin_method_declares_override(method: &MethodRecord) -> bool {
    if method.language != "kotlin" {
        return false;
    }
    let declaration = method
        .source
        .find(&method.name)
        .and_then(|name_start| method.source.get(..name_start))
        .unwrap_or_default();
    declaration
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == "override")
}

fn rust_qualified_reference_may_target(
    line: &str,
    method: &MethodRecord,
    target_owner: &str,
    candidate_owner: Option<&str>,
) -> bool {
    identifier_matches(line, &method.name).any(|end| {
        let start = end - method.name.len();
        let before = line[..start].trim_end();
        if let Some(path) = before.strip_suffix("::") {
            let qualifier = trailing_identifier(path);
            qualifier == type_leaf(target_owner)
                || (qualifier == "Self"
                    && candidate_owner
                        .is_some_and(|owner| type_leaf(owner) == type_leaf(target_owner)))
                || (path.ends_with('>') && path.contains(type_leaf(target_owner)))
        } else if before.ends_with('.') {
            rust_method_has_receiver(method)
        } else {
            false
        }
    })
}

fn kotlin_binding_owner_at_line<'a>(
    graph: &'a SymbolGraph,
    file_path: &str,
    line: usize,
    binding_name: &str,
) -> Option<&'a str> {
    graph.files.get(file_path).and_then(|symbols| {
        symbols
            .definitions
            .iter()
            .filter(|definition| {
                matches!(&definition.kind, crate::types::SymbolKind::Variable)
                    && definition.name == binding_name
                    && definition.start_line <= line
                    && line <= definition.end_line
            })
            .min_by_key(|definition| {
                (
                    definition.end_line.saturating_sub(definition.start_line),
                    usize::MAX - definition.start_line,
                )
            })
            .and_then(|definition| definition.owner_type.as_deref())
    })
}

fn kotlin_unresolved_reference_may_target(
    graph: &SymbolGraph,
    file_path: &str,
    line: usize,
    method_name: &str,
    target_owner: Option<&str>,
    candidate_owner: Option<&str>,
) -> bool {
    let Some(target_owner) = target_owner else {
        return true;
    };
    let Some(symbols) = graph.files.get(file_path) else {
        return true;
    };
    let references = symbols.references.iter().filter(|reference| {
        reference.line == line
            && reference.resolved_symbol.is_none()
            && reference
                .name
                .rsplit('.')
                .next()
                .is_some_and(|leaf| leaf == method_name)
    });
    let mut found = false;
    for reference in references {
        found = true;
        let Some((qualifier, _)) = reference.name.rsplit_once('.') else {
            if candidate_owner
                .is_some_and(|owner| owners_share_contract(graph, target_owner, owner))
            {
                return true;
            }
            continue;
        };
        let qualifier = qualifier.rsplit('.').next().unwrap_or(qualifier);
        let binding_owner = match qualifier {
            "this" | "super" => candidate_owner,
            _ => kotlin_binding_owner_at_line(graph, file_path, line, qualifier).or_else(|| {
                qualifier
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase())
                    .then_some(qualifier)
            }),
        };
        match binding_owner {
            Some(owner) if owners_share_contract(graph, target_owner, owner) => return true,
            Some(_) => continue,
            // Unknown receiver types remain explicit unresolved evidence.
            None => return true,
        }
    }
    !found
}

struct LexicalReferenceQuery<'a> {
    line: &'a str,
    method: &'a MethodRecord,
    target_owner: Option<&'a str>,
    candidate_owner: Option<&'a str>,
    allow_unknown_js_ts_member: bool,
    candidate_file: &'a str,
    candidate_line: usize,
}

fn lexical_reference_may_target(graph: &SymbolGraph, query: &LexicalReferenceQuery<'_>) -> bool {
    if query.method.language == "rust" {
        return query.target_owner.is_none_or(|owner| {
            rust_qualified_reference_may_target(
                query.line,
                query.method,
                owner,
                query.candidate_owner,
            )
        });
    }
    if query.method.language == "kotlin" {
        return kotlin_unresolved_reference_may_target(
            graph,
            query.candidate_file,
            query.candidate_line,
            &query.method.name,
            query.target_owner,
            query.candidate_owner,
        );
    }
    if matches!(query.method.language.as_str(), "javascript" | "typescript") {
        return js_ts_unresolved_reference_may_target(graph, query);
    }
    true
}

fn js_ts_unresolved_reference_may_target(
    graph: &SymbolGraph,
    query: &LexicalReferenceQuery<'_>,
) -> bool {
    let same_file = query
        .method
        .file_path
        .eq_ignore_ascii_case(query.candidate_file);
    let Some(symbols) = graph.files.get(query.candidate_file) else {
        return same_file;
    };
    let mut found = false;
    for reference in symbols.references.iter().filter(|reference| {
        reference.line == query.candidate_line
            && reference.resolved_symbol.is_none()
            && reference
                .name
                .rsplit('.')
                .next()
                .is_some_and(|leaf| leaf == query.method.name)
    }) {
        found = true;
        let Some((qualifier, _)) = reference.name.rsplit_once('.') else {
            if same_file || query.allow_unknown_js_ts_member {
                return true;
            }
            continue;
        };
        let qualifier = qualifier.rsplit('.').next().unwrap_or(qualifier);
        if matches!(qualifier, "this" | "super")
            && query
                .target_owner
                .zip(query.candidate_owner)
                .is_some_and(|(target, candidate)| owners_share_contract(graph, target, candidate))
        {
            return true;
        }
        if query.target_owner.is_some_and(|owner| owner == qualifier) {
            return true;
        }
        if query.allow_unknown_js_ts_member {
            return true;
        }
    }
    same_file && !found
}

fn explicit_string_contract_reference(line: &str, method_name: &str) -> bool {
    if !contains_quoted_identifier_literal(line, method_name) {
        return false;
    }
    let context = context_without_target_identifier(line, method_name);
    contains_any(
        &context,
        &[
            "register",
            "registry",
            "callback",
            "handler",
            "dispatch",
            "plugin",
            "route",
            "command",
            "getattr",
            "setattr",
            "monkeypatch",
            "patch(",
            "deprecated",
            "compat",
            "legacy",
            "migration",
        ],
    )
}

fn contains_quoted_identifier_literal(line: &str, identifier: &str) -> bool {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        index = start;
        let mut escaped = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                if line.get(start..index) == Some(identifier) {
                    return true;
                }
                index += 1;
                break;
            }
            index += 1;
        }
    }
    false
}

#[path = "analyzer_dossier_repository.rs"]
mod repository;
use repository::*;

#[path = "analyzer_dossier_proofs.rs"]
mod proofs;
pub(super) use proofs::{
    duplicated_branch_construct, python_parameter_discard_block,
    rejected_non_exhaustive_duplicate_branch,
};
use proofs::{is_lexical_call_site, python_stale_discard_signature_proof};

fn git_history(graph: &SymbolGraph, file_path: &str, method_name: &str) -> (String, bool) {
    git_history_from_root(&graph.project_root, file_path, method_name)
}

fn git_history_from_root(
    project_root: impl AsRef<std::path::Path>,
    file_path: &str,
    method_name: &str,
) -> (String, bool) {
    let output = Command::new("git")
        .args(["log", "--oneline", "-S", method_name, "--", file_path])
        .current_dir(project_root)
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let history = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if history.is_empty() {
                ("no matching commits".to_string(), false)
            } else {
                (history, true)
            }
        }
        Ok(output) => (
            format!("git history unavailable (exit status {})", output.status),
            false,
        ),
        Err(error) => (format!("git history unavailable ({error})"), false),
    }
}

pub(super) fn expand_git_history_evidence(
    context: &str,
    project_root: &std::path::Path,
    file_path: &str,
    method_name: &str,
) -> Option<String> {
    const OMITTED: &str =
        "git history: not queried because no compatibility/migration signal was detected";
    if !context.contains(OMITTED) || project_root.as_os_str().is_empty() {
        return None;
    }

    let (history, _) = git_history_from_root(project_root, file_path, method_name);
    if history.starts_with("git history unavailable") {
        return None;
    }
    Some(context.replacen(
        OMITTED,
        &format!("git history: queried after evidence escalation; {history}"),
        1,
    ))
}

#[cfg(test)]
#[path = "tests/analyzer_dossier.rs"]
mod tests;
