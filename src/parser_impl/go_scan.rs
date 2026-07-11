use super::*;
use tree_sitter::Parser;

#[path = "go_scan_defs.rs"]
mod defs;
#[path = "go_scan_methods.rs"]
mod methods;
#[path = "go_scan_refs.rs"]
mod refs_scan;
#[path = "go_symbol_extractor.rs"]
mod state;

pub(crate) use methods::extract_methods;
pub(crate) use state::SymbolExtractor;

pub(crate) fn get_parser(adapter: &LanguageAdapter) -> Option<Parser> {
    if adapter.name != "go" {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::language()).ok()?;
    Some(parser)
}

impl<'a> SymbolExtractor<'a> {
    pub(crate) fn visit<T>(&mut self, _root: T) {
        let ranges = defs::scan_go_defs_and_imports(self);
        refs_scan::scan_go_references(self, &ranges);
    }
}
