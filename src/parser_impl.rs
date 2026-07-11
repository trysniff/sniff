use crate::language_adapter::LanguageAdapter;
use crate::languages;
use crate::types::{
    ExportRecord, FileRecord, ImportRecord, LocalFileSymbols, MethodRecord, SymbolDefinition,
    SymbolKind, SymbolReference,
};
use std::collections::HashSet;

#[path = "parser_impl_file.rs"]
mod file;
#[path = "parser_impl/go_extractor.rs"]
mod go;
#[path = "parser_impl/js_ts_functions.rs"]
mod js_ts_functions;
#[path = "parser_impl/js_ts_imports.rs"]
mod js_ts_imports;
#[path = "parser_impl/js_ts_references.rs"]
mod js_ts_references;
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
};
pub(super) use line_index::LineIndex;
