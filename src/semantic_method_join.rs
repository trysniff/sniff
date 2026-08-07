use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticLocation, SemanticResolution, SemanticSymbolCategory,
    SemanticSymbolId, SemanticSymbolOrigin, SemanticUnresolvedReason,
};
use crate::types::{FileRecord, MethodRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use syn::spanned::Spanned;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticMethodKey {
    pub file: RepositoryPath,
    pub name: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticMethodBinding {
    pub method: SemanticMethodKey,
    pub symbol: SemanticResolution<SemanticSymbolId>,
    pub definition: Option<SemanticLocation>,
    pub coverage: SemanticMethodCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticMethodCoverage {
    Indexed,
    CompilerExcluded { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticMethodJoin {
    pub bindings: BTreeMap<SemanticMethodKey, SemanticMethodBinding>,
}

impl SemanticMethodJoin {
    pub fn resolved_count(&self) -> usize {
        self.bindings
            .values()
            .filter(|binding| matches!(binding.symbol, SemanticResolution::Resolved { .. }))
            .count()
    }

    pub fn unresolved_count(&self) -> usize {
        self.bindings
            .values()
            .filter(|binding| {
                matches!(binding.coverage, SemanticMethodCoverage::Indexed)
                    && matches!(binding.symbol, SemanticResolution::Unresolved { .. })
            })
            .count()
    }

    pub fn compiler_excluded_count(&self) -> usize {
        self.bindings
            .values()
            .filter(|binding| {
                matches!(
                    binding.coverage,
                    SemanticMethodCoverage::CompilerExcluded { .. }
                )
            })
            .count()
    }

    pub fn require_complete(&self) -> Result<(), String> {
        let unresolved = self
            .bindings
            .values()
            .filter_map(|binding| match (&binding.coverage, &binding.symbol) {
                (SemanticMethodCoverage::CompilerExcluded { .. }, _) => None,
                (_, SemanticResolution::Resolved { .. }) => None,
                (_, SemanticResolution::Unresolved { detail, .. }) => Some(detail.as_str()),
            })
            .take(8)
            .collect::<Vec<_>>();
        if unresolved.is_empty() {
            return Ok(());
        }
        let remaining = self.unresolved_count().saturating_sub(unresolved.len());
        let suffix = (remaining > 0).then(|| format!("; and {remaining} more"));
        Err(format!(
            "semantic AST-to-SCIP join is incomplete for {} method(s): {}{}",
            self.unresolved_count(),
            unresolved.join("; "),
            suffix.unwrap_or_default()
        ))
    }
}

pub fn join_methods(
    repository_root: &Path,
    files: &[FileRecord],
    index: &SemanticIndex,
) -> Result<SemanticMethodJoin, String> {
    let root = fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve semantic method join repository root {}: {error}",
            repository_root.display()
        )
    })?;
    let mut bindings = BTreeMap::new();
    for file in files {
        let path = repository_relative_path(&root, Path::new(&file.file_path))?;
        for method in &file.methods {
            let key = method_key(path.clone(), method)?;
            let binding = bind_method(&key, file, method, index);
            if bindings.insert(key.clone(), binding).is_some() {
                return Err(format!(
                    "duplicate AST method identity in semantic join: {}::{}:{}-{}",
                    key.file.0, key.name, key.start_line, key.end_line
                ));
            }
        }
    }
    Ok(SemanticMethodJoin { bindings })
}

fn method_key(path: RepositoryPath, method: &MethodRecord) -> Result<SemanticMethodKey, String> {
    let start_line = u32::try_from(method.start_line).map_err(|_| {
        format!(
            "AST method {} in {} has a start line outside SCIP range",
            method.name, method.file_path
        )
    })?;
    let end_line = u32::try_from(method.end_line).map_err(|_| {
        format!(
            "AST method {} in {} has an end line outside SCIP range",
            method.name, method.file_path
        )
    })?;
    if start_line == 0 || end_line < start_line {
        return Err(format!(
            "AST method {} in {} has invalid range {}-{}",
            method.name, method.file_path, start_line, end_line
        ));
    }
    Ok(SemanticMethodKey {
        file: path,
        name: method.name.clone(),
        start_line,
        end_line,
    })
}

fn bind_method(
    key: &SemanticMethodKey,
    file: &FileRecord,
    method: &MethodRecord,
    index: &SemanticIndex,
) -> SemanticMethodBinding {
    let unresolved = |reason: SemanticUnresolvedReason, detail: String| SemanticMethodBinding {
        method: key.clone(),
        symbol: SemanticResolution::Unresolved {
            reason,
            raw_target: Some(method.name.clone()),
            detail,
        },
        definition: None,
        coverage: SemanticMethodCoverage::Indexed,
    };

    let Some(document) = index.documents.get(&key.file) else {
        return unresolved(
            SemanticUnresolvedReason::MissingIndexerFact,
            format!("{} has no SCIP document", key.file.0),
        );
    };
    let (definition_line, compiler_excluded) =
        rust_method_info(file, method).unwrap_or((key.start_line.saturating_sub(1), false));
    let js_like = file.language.eq_ignore_ascii_case("javascript")
        || file.language.eq_ignore_ascii_case("typescript");
    let source_name_range = js_like.then(|| method_name_range(file, method));
    let mut candidates = BTreeMap::<SemanticSymbolId, SemanticLocation>::new();
    for symbol in index.symbols.values() {
        let callable = matches!(
            symbol.kind.category,
            SemanticSymbolCategory::Callable
                | SemanticSymbolCategory::Constructor
                | SemanticSymbolCategory::Method
        );
        let named_javascript_definition = js_like
            && !method.name.starts_with("<anonymous@")
            && (symbol.display_name.as_deref() == Some(method.name.as_str())
                || source_name_range
                    .flatten()
                    .is_some_and(|(line, start, end)| {
                        symbol.definitions.iter().any(|definition| {
                            definition.document == document.path
                                && definition.range.start.line == line
                                && definition.range.start.character == start
                                && definition.range.end.character == end
                        })
                    }));
        if !callable && !named_javascript_definition {
            continue;
        }
        for definition in &symbol.definitions {
            if definition.document == document.path
                && definition.range.start.line == definition_line
            {
                candidates.insert(symbol.id.clone(), definition.clone());
            }
        }
    }

    if candidates.is_empty() {
        if let Some(reason) = compiler_excluded_reason(file, method) {
            return SemanticMethodBinding {
                method: key.clone(),
                symbol: SemanticResolution::Unresolved {
                    reason: SemanticUnresolvedReason::MissingIndexerFact,
                    raw_target: Some(method.name.clone()),
                    detail: format!(
                        "{}::{} is compiler-excluded: {reason}",
                        key.file.0, key.name
                    ),
                },
                definition: None,
                coverage: SemanticMethodCoverage::CompilerExcluded { reason },
            };
        }
        if compiler_excluded {
            return SemanticMethodBinding {
                method: key.clone(),
                symbol: SemanticResolution::Unresolved {
                    reason: SemanticUnresolvedReason::MissingIndexerFact,
                    raw_target: Some(method.name.clone()),
                    detail: format!(
                        "{}::{} is excluded from the active Rust SCIP target by cfg(test)",
                        key.file.0, key.name
                    ),
                },
                definition: None,
                coverage: SemanticMethodCoverage::CompilerExcluded {
                    reason: "cfg(test) is not part of the active production SCIP target"
                        .to_string(),
                },
            };
        }
        return unresolved(
            SemanticUnresolvedReason::MissingDefinition,
            format!(
                "{}::{} starts on line {} but SCIP has no exact callable definition range",
                key.file.0, key.name, key.start_line
            ),
        );
    }
    if candidates.len() > 1 {
        return unresolved(
            SemanticUnresolvedReason::Ambiguous,
            format!(
                "{}::{} line {} matches {} SCIP callable definitions",
                key.file.0,
                key.name,
                key.start_line,
                candidates.len()
            ),
        );
    }

    let (symbol_id, definition) = candidates.into_iter().next().expect("candidate exists");
    let symbol = index
        .symbols
        .get(&symbol_id)
        .expect("candidate symbol exists in index");
    if symbol.origin != SemanticSymbolOrigin::Repository {
        return unresolved(
            SemanticUnresolvedReason::MissingDefinition,
            format!("{} is not a repository-defined SCIP symbol", symbol_id.0),
        );
    }
    if !symbol.ambiguity_notes.is_empty() {
        return unresolved(
            SemanticUnresolvedReason::Ambiguous,
            format!(
                "{} has {} unresolved SCIP ambiguity note(s)",
                symbol_id.0,
                symbol.ambiguity_notes.len()
            ),
        );
    }

    SemanticMethodBinding {
        method: key.clone(),
        symbol: SemanticResolution::Resolved { value: symbol_id },
        definition: Some(definition),
        coverage: SemanticMethodCoverage::Indexed,
    }
}

fn compiler_excluded_reason(file: &FileRecord, method: &MethodRecord) -> Option<String> {
    let language = file.language.to_ascii_lowercase();
    if language == "javascript" || language == "typescript" {
        if method.name.starts_with("<anonymous@") {
            return Some(
                "scip-typescript does not emit a stable callable definition for inline anonymous function expressions"
                    .to_string(),
            );
        }
        let first_line = method
            .start_line
            .checked_sub(1)
            .and_then(|line| file.source.lines().nth(line))
            .map(str::trim_start);
        if first_line.as_ref().is_some_and(|line| line.contains("=>")) {
            return Some(
                "scip-typescript emitted no stable callable definition for this function expression"
                    .to_string(),
            );
        }
        if let Some(first_line) = first_line {
            let name_call = format!("{}(", method.name);
            let name_generic = format!("{}<", method.name);
            let top_level_declaration = first_line.starts_with("function ")
                || first_line.starts_with("async function ")
                || first_line.starts_with("export function ")
                || first_line.starts_with("export async function ")
                || first_line.starts_with("const ")
                || first_line.starts_with("let ")
                || first_line.starts_with("var ");
            if (method.name == "constructor" && first_line.contains("constructor"))
                || (!top_level_declaration
                    && (first_line.contains(&name_call) || first_line.contains(&name_generic)))
                || (first_line.contains("function ") && first_line.contains(&method.name))
            {
                return Some(
                    "scip-typescript emitted no stable definition occurrence for this member or returned function construct"
                        .to_string(),
                );
            }
        }
    }
    None
}

fn method_name_range(file: &FileRecord, method: &MethodRecord) -> Option<(u32, u32, u32)> {
    let line_number = method.start_line.checked_sub(1)?;
    let line = file.source.lines().nth(line_number)?;
    let byte_start = line.find(&method.name)?;
    let start = line[..byte_start].encode_utf16().count() as u32;
    let width = method.name.encode_utf16().count() as u32;
    Some((line_number as u32, start, start + width))
}

fn rust_method_info(file: &FileRecord, method: &MethodRecord) -> Option<(u32, bool)> {
    if !file.language.eq_ignore_ascii_case("rust") {
        return None;
    }
    let Ok(ast) = syn::parse_file(&file.source) else {
        return None;
    };
    let mut visitor = TestCfgVisitor {
        target_line: method.start_line,
        definition_line: None,
        test_context: false,
        matched: false,
    };
    syn::visit::Visit::visit_file(&mut visitor, &ast);
    visitor
        .definition_line
        .and_then(|line| u32::try_from(line.saturating_sub(1)).ok())
        .map(|line| (line, visitor.matched))
}

struct TestCfgVisitor {
    target_line: usize,
    definition_line: Option<usize>,
    test_context: bool,
    matched: bool,
}

impl TestCfgVisitor {
    fn enter_attributes(&mut self, attrs: &[syn::Attribute]) -> bool {
        let previous = self.test_context;
        self.test_context |= attrs.iter().any(attribute_has_test_cfg);
        previous
    }

    fn visit_callable(
        &mut self,
        node_start_line: usize,
        identifier_line: usize,
        attrs: &[syn::Attribute],
    ) {
        if node_start_line == self.target_line || identifier_line == self.target_line {
            self.definition_line = Some(identifier_line);
            if self.test_context || attrs.iter().any(attribute_has_test_cfg) {
                self.matched = true;
            }
        }
    }
}

fn attribute_has_test_cfg(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg")
        && attribute
            .meta
            .require_list()
            .map(|list| {
                list.tokens
                    .to_string()
                    .split(|character: char| !character.is_alphanumeric() && character != '_')
                    .any(|part| part == "test")
            })
            .unwrap_or(false)
}

impl<'ast> syn::visit::Visit<'ast> for TestCfgVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_mod(self, node);
        self.test_context = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_impl(self, node);
        self.test_context = previous;
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let previous = self.enter_attributes(&node.attrs);
        syn::visit::visit_item_trait(self, node);
        self.test_context = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.visit_callable(
            node.span().start().line,
            node.sig.ident.span().start().line,
            &node.attrs,
        );
        syn::visit::visit_trait_item_fn(self, node);
    }
}

fn repository_relative_path(root: &Path, file: &Path) -> Result<RepositoryPath, String> {
    let canonical = fs::canonicalize(file).map_err(|error| {
        format!(
            "failed to resolve semantic AST source {}: {error}",
            file.display()
        )
    })?;
    let relative = canonical.strip_prefix(root).map_err(|_| {
        format!(
            "semantic AST source {} is outside repository root {}",
            file.display(),
            root.display()
        )
    })?;
    let text = relative.to_string_lossy().replace('\\', "/");
    if text.is_empty() || text.starts_with("../") || text.contains('\0') {
        return Err(format!(
            "semantic AST source has unsafe repository-relative path: {}",
            relative.display()
        ));
    }
    Ok(RepositoryPath(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_index::{
        SemanticDocument, SemanticIndexProvenance, SemanticPosition, SemanticPositionEncoding,
        SemanticSignature, SemanticSourceRange, SemanticSymbol, SemanticSymbolKind,
        SemanticVisibility,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(
        notes: Vec<String>,
        definition_line: u32,
        second_definition: bool,
        test_only: bool,
    ) -> (std::path::PathBuf, Vec<FileRecord>, SemanticIndex) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-semantic-method-join-{nonce}"));
        fs::create_dir_all(root.join("src")).unwrap();
        let path = root.join("src").join("lib.rs");
        let source = if test_only {
            "#[cfg(test)]\nfn process(value: i32) -> i32 { value }\n"
        } else {
            "fn process(value: i32) -> i32 { value }\n"
        };
        fs::write(&path, source).unwrap();
        let document_path = RepositoryPath("src/lib.rs".to_string());
        let location = |line| SemanticLocation {
            document: document_path.clone(),
            range: SemanticSourceRange {
                start: SemanticPosition { line, character: 3 },
                end: SemanticPosition {
                    line,
                    character: 10,
                },
            },
        };
        let id = SemanticSymbolId("rust test process".to_string());
        let mut definitions = BTreeSet::from([location(definition_line)]);
        if second_definition {
            definitions.insert(SemanticLocation {
                document: document_path.clone(),
                range: SemanticSourceRange {
                    start: SemanticPosition {
                        line: definition_line,
                        character: 20,
                    },
                    end: SemanticPosition {
                        line: definition_line,
                        character: 27,
                    },
                },
            });
        }
        let symbol = SemanticSymbol {
            id: id.clone(),
            provider_identity: id.0.clone(),
            display_name: Some("process".to_string()),
            kind: SemanticSymbolKind {
                category: SemanticSymbolCategory::Callable,
                provider_name: "function".to_string(),
            },
            documentation: Vec::new(),
            signature: Some(SemanticSignature {
                language: "rust".to_string(),
                text: "fn process(value: i32) -> i32".to_string(),
                referenced_symbols: BTreeSet::new(),
            }),
            owner: None,
            definitions,
            visibility: SemanticVisibility::Private,
            surfaces: BTreeSet::new(),
            origin: SemanticSymbolOrigin::Repository,
            ambiguity_notes: notes,
        };
        let file = FileRecord {
            file_path: path.to_string_lossy().to_string(),
            source: source.to_string(),
            language: "rust".to_string(),
            methods: vec![MethodRecord {
                name: "process".to_string(),
                file_path: path.to_string_lossy().to_string(),
                source: source.to_string(),
                loc: 1,
                param_count: 1,
                start_line: if test_only { 2 } else { 1 },
                end_line: if test_only { 2 } else { 1 },
                is_exported: false,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: Vec::new(),
                real_ref_count: 0,
            }],
        };
        let mut symbols = BTreeMap::new();
        if !test_only {
            symbols.insert(id, symbol.clone());
        }
        if second_definition && !test_only {
            let duplicate_id = SemanticSymbolId("rust test process duplicate".to_string());
            let mut duplicate = symbol;
            duplicate.id = duplicate_id.clone();
            duplicate.provider_identity = duplicate_id.0.clone();
            symbols.insert(duplicate_id, duplicate);
        }
        let index = SemanticIndex {
            format_version: 1,
            repository_root: root.to_string_lossy().replace('\\', "/"),
            provenance: SemanticIndexProvenance {
                format: "scip".to_string(),
                tool_name: "test".to_string(),
                tool_version: None,
                arguments: Vec::new(),
                source_text_encoding: None,
                diagnostics: Vec::new(),
            },
            documents: BTreeMap::from([(
                document_path.clone(),
                SemanticDocument {
                    path: document_path,
                    language: "rust".to_string(),
                    position_encoding: SemanticPositionEncoding::Utf8,
                    embedded_text: None,
                    occurrences: Vec::new(),
                },
            )]),
            symbols,
            relationships: BTreeSet::new(),
            imports: BTreeSet::new(),
            calls: BTreeSet::new(),
            test_relationships: BTreeSet::new(),
            unresolved_edges: BTreeSet::new(),
        };
        (root, vec![file], index)
    }

    #[test]
    fn joins_a_method_by_exact_definition_line() {
        let (root, files, index) = fixture(Vec::new(), 0, false, false);
        let join = join_methods(&root, &files, &index).unwrap();
        assert_eq!(join.resolved_count(), 1);
        assert_eq!(join.unresolved_count(), 0);
        join.require_complete().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_ambiguous_definitions_instead_of_picking_one() {
        let (root, files, index) = fixture(Vec::new(), 0, true, false);
        let join = join_methods(&root, &files, &index).unwrap();
        assert_eq!(join.unresolved_count(), 1);
        assert!(join.require_complete().is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_a_symbol_with_untrusted_facts() {
        let (root, files, index) =
            fixture(vec!["conflicting signature".to_string()], 0, false, false);
        let join = join_methods(&root, &files, &index).unwrap();
        assert_eq!(join.unresolved_count(), 1);
        assert!(join.require_complete().is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn does_not_fallback_to_a_different_definition_line() {
        let (root, files, index) = fixture(Vec::new(), 4, false, false);
        let join = join_methods(&root, &files, &index).unwrap();
        assert_eq!(join.unresolved_count(), 1);
        assert!(join.require_complete().is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn records_cfg_test_methods_as_explicitly_compiler_excluded() {
        let (root, files, index) = fixture(Vec::new(), 1, false, true);
        let join = join_methods(&root, &files, &index).unwrap();
        assert_eq!(join.resolved_count(), 0);
        assert_eq!(join.compiler_excluded_count(), 1);
        assert_eq!(join.unresolved_count(), 0);
        join.require_complete().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn records_inline_javascript_callbacks_as_explicitly_compiler_excluded() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-semantic-method-join-js-{nonce}"));
        fs::create_dir_all(root.join("src")).unwrap();
        let path = root.join("src").join("main.js");
        let source = "items.map((item) => item)\n";
        fs::write(&path, source).unwrap();
        let file_path = path.to_string_lossy().to_string();
        let file = FileRecord {
            file_path: file_path.clone(),
            source: source.to_string(),
            language: "javascript".to_string(),
            methods: vec![MethodRecord {
                name: "<anonymous@1>".to_string(),
                file_path,
                source: source.to_string(),
                loc: 1,
                param_count: 1,
                start_line: 1,
                end_line: 1,
                is_exported: false,
                language: "javascript".to_string(),
                nesting_depth: 0,
                references: Vec::new(),
                real_ref_count: 0,
            }],
        };
        let document_path = RepositoryPath("src/main.js".to_string());
        let index = SemanticIndex {
            format_version: 1,
            repository_root: root.to_string_lossy().replace('\\', "/"),
            provenance: SemanticIndexProvenance {
                format: "scip".to_string(),
                tool_name: "scip-typescript".to_string(),
                tool_version: None,
                arguments: Vec::new(),
                source_text_encoding: None,
                diagnostics: Vec::new(),
            },
            documents: BTreeMap::from([(
                document_path.clone(),
                SemanticDocument {
                    path: document_path,
                    language: "javascript".to_string(),
                    position_encoding: SemanticPositionEncoding::Utf16,
                    embedded_text: None,
                    occurrences: Vec::new(),
                },
            )]),
            symbols: BTreeMap::new(),
            relationships: BTreeSet::new(),
            imports: BTreeSet::new(),
            calls: BTreeSet::new(),
            test_relationships: BTreeSet::new(),
            unresolved_edges: BTreeSet::new(),
        };

        let join = join_methods(&root, &[file], &index).unwrap();
        assert_eq!(join.resolved_count(), 0);
        assert_eq!(join.compiler_excluded_count(), 1);
        assert_eq!(join.unresolved_count(), 0);
        join.require_complete().unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
