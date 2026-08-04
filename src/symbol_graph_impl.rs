use crate::types::{LocalFileSymbols, ResolvedSymbol};
use std::collections::{HashMap, HashSet};

pub(crate) struct ResolveContext<'a> {
    importing_file: &'a str,
    project_root: &'a str,
    all_files: &'a HashMap<String, String>,
    rust_modules: &'a HashMap<(String, String), String>,
    rust_parents: &'a HashMap<String, String>,
    rust_crate_names: &'a HashSet<String>,
    language: &'a str,
}

#[path = "symbol_graph_path_resolver.rs"]
mod paths;
#[path = "symbol_graph_resolver.rs"]
mod resolver;
#[path = "symbol_graph_rust.rs"]
mod rust_resolver;
#[path = "symbol_graph_rust_target.rs"]
mod rust_target;

pub use paths::normalize_path;

pub struct SymbolGraph {
    pub files: HashMap<String, LocalFileSymbols>,
    pub project_root: String,
    resolved_imports: HashMap<(String, usize), ResolvedSymbol>,
    resolved_exports: HashMap<(String, usize), ResolvedSymbol>,
}

impl SymbolGraph {
    pub fn new(project_root: &str) -> Self {
        SymbolGraph {
            files: HashMap::new(),
            project_root: project_root.to_string(),
            resolved_imports: HashMap::new(),
            resolved_exports: HashMap::new(),
        }
    }

    pub fn add_file(&mut self, symbols: LocalFileSymbols) {
        self.files.insert(symbols.file_path.clone(), symbols);
    }

    fn find_definition<'a>(
        &'a self,
        file_symbols: &'a LocalFileSymbols,
        symbol_name: &str,
        owner_type: Option<&str>,
    ) -> Option<&'a crate::types::SymbolDefinition> {
        file_symbols.definitions.iter().find(|def| {
            def.name == symbol_name
                && match owner_type {
                    Some(owner) => def.owner_type.as_deref() == Some(owner),
                    None => true,
                }
        })
    }

    pub fn resolve_all(&mut self) {
        self.resolve_all_impl();
    }

    pub(crate) fn import_targets_definition(
        &self,
        file_path: &str,
        import_index: usize,
        target_file: &str,
        target_definition_id: usize,
    ) -> bool {
        self.resolved_imports
            .get(&(file_path.to_string(), import_index))
            .is_some_and(|resolved| {
                resolved_matches_definition(resolved, file_path, target_file, target_definition_id)
            })
    }

    pub(crate) fn export_targets_definition(
        &self,
        file_path: &str,
        export_index: usize,
        target_file: &str,
        target_definition_id: usize,
    ) -> bool {
        self.resolved_exports
            .get(&(file_path.to_string(), export_index))
            .is_some_and(|resolved| {
                resolved_matches_definition(resolved, file_path, target_file, target_definition_id)
            })
    }
}

fn resolved_matches_definition(
    resolved: &ResolvedSymbol,
    source_file: &str,
    target_file: &str,
    target_definition_id: usize,
) -> bool {
    match resolved {
        ResolvedSymbol::Local(definition_id) => {
            paths::same_path(source_file, target_file) && *definition_id == target_definition_id
        }
        ResolvedSymbol::External {
            file_path,
            definition_id: Some(definition_id),
            ..
        } => paths::same_path(file_path, target_file) && *definition_id == target_definition_id,
        ResolvedSymbol::External {
            definition_id: None,
            ..
        } => false,
    }
}
