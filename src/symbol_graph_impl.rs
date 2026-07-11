use crate::types::LocalFileSymbols;
use std::collections::HashMap;

pub(crate) struct ResolveContext<'a> {
    importing_file: &'a str,
    project_root: &'a str,
    all_files: &'a HashMap<String, String>,
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
}

impl SymbolGraph {
    pub fn new(project_root: &str) -> Self {
        SymbolGraph {
            files: HashMap::new(),
            project_root: project_root.to_string(),
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
}
