use crate::language_adapter::LanguageAdapter;
use crate::languages;
use crate::types::{
    ExportRecord, FileRecord, ImportRecord, LocalFileSymbols, MethodRecord, ModuleRecord,
    SymbolDefinition, SymbolKind, SymbolReference, TypeRecord,
};
use std::collections::HashSet;
use std::path::Path;

#[path = "parser_impl_file.rs"]
mod file;
#[path = "parser_impl/go_extractor.rs"]
mod go;
#[path = "parser_impl/kotlin_extractor.rs"]
mod kotlin;
#[path = "parser_impl_line_index.rs"]
mod line_index;
#[path = "parser_impl/js_ts_extractor.rs"]
mod oxc;
#[path = "parser_impl/python_extractor.rs"]
mod python;
#[path = "parser_impl/python_blocks.rs"]
mod python_blocks;
#[path = "parser_impl/python_refs_helpers.rs"]
mod python_refs_helpers;
#[path = "parser_impl/rust_extractor.rs"]
mod rust;
#[path = "parser_impl/block_scan.rs"]
mod shared;

pub(in crate::parser) use file::{
    parse_file, parse_file_checked, parse_file_symbols, parse_file_symbols_checked,
    parse_source_checked, parse_source_symbols_checked,
};
pub(super) use line_index::LineIndex;

pub(in crate::parser) fn parse_tree_sitter_source_checked(
    file_path: &str,
    source_bytes: &[u8],
) -> Result<tree_sitter::Tree, String> {
    let extension = Path::new(file_path)
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("source file has no supported extension: {file_path}"))?;
    let adapter = languages::get_adapter(extension)
        .ok_or_else(|| format!("unsupported source extension for {file_path}"))?;
    let mut parser = match adapter.name.as_str() {
        "go" => go::get_parser(&adapter),
        "kotlin" => kotlin::get_parser(&adapter),
        language => {
            return Err(format!(
                "no tree-sitter parser implementation for {language} ({file_path})"
            ));
        }
    }
    .ok_or_else(|| format!("no {} parser available for {file_path}", adapter.name))?;
    let tree = match adapter.name.as_str() {
        "go" => go::parse_source(&mut parser, source_bytes),
        _ => parser.parse(source_bytes, None),
    }
    .ok_or_else(|| format!("failed to parse {file_path}: parser returned no syntax tree"))?;
    if tree.root_node().has_error() {
        return Err(format!(
            "failed to parse {file_path}: {} syntax tree contains error nodes",
            adapter.name
        ));
    }
    Ok(tree)
}
