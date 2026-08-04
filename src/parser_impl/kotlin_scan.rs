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

fn declaration_is_repository_external(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let declaration_end = node
        .child_by_field_name("name")
        .map(|name| name.start_byte())
        .unwrap_or_else(|| node.end_byte());
    let prefix = source
        .get(node.start_byte()..declaration_end)
        .unwrap_or_default();
    !prefix
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| matches!(token, "private" | "internal"))
}

pub(crate) fn get_parser(adapter: &LanguageAdapter) -> Option<Parser> {
    if adapter.name != "kotlin" {
        return None;
    }
    let mut parser = Parser::new();
    let language = unsafe {
        tree_sitter::Language::from_raw((tree_sitter_kotlin::LANGUAGE.into_raw())() as *const _)
    };
    parser.set_language(&language).ok()?;
    Some(parser)
}

impl<'a> SymbolExtractor<'a> {
    pub(crate) fn visit<T>(&mut self, _root: T) {
        let _ = defs::scan_kotlin_defs_and_imports(self);
    }
}
