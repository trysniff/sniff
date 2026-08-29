use super::*;
use tree_sitter::{Parser, Tree};

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

pub(crate) fn parse_source(parser: &mut Parser, source_bytes: &[u8]) -> Option<Tree> {
    if source_bytes.ends_with(b"\n") {
        return parser.parse(source_bytes, None);
    }

    // Go inserts a semicolon at EOF, but tree-sitter-go needs the equivalent
    // final newline to avoid an error node. Keep Sniff's source bytes exact and
    // add the newline only to the parser input.
    let mut parser_bytes = Vec::with_capacity(source_bytes.len() + 1);
    parser_bytes.extend_from_slice(source_bytes);
    parser_bytes.push(b'\n');
    parser.parse(&parser_bytes, None)
}

impl<'a> SymbolExtractor<'a> {
    pub(crate) fn visit(&mut self, root: tree_sitter::Node<'_>) {
        defs::scan_go_defs_and_imports(self);
        refs_scan::scan_go_references(self, root);
    }
}
