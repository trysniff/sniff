use super::*;
use tree_sitter::Parser;

#[path = "kotlin_scan_defs.rs"]
mod defs;
#[path = "kotlin_scan_methods.rs"]
mod methods;
#[path = "kotlin_refs.rs"]
mod refs;
#[path = "kotlin_symbol_extractor.rs"]
mod state;

pub(crate) use methods::extract_methods;
pub(crate) use state::SymbolExtractor;

pub(crate) fn get_parser(adapter: &LanguageAdapter) -> Option<Parser> {
    if adapter.name != "kotlin" {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_kotlin::language()).ok()?;
    Some(parser)
}

impl<'a> SymbolExtractor<'a> {
    pub(crate) fn visit<T>(&mut self, _root: T) {
        let _ = defs::scan_kotlin_defs_and_imports(self);
    }
}
