#[path = "parser_impl.rs"]
mod parser_impl;

use crate::types::{FileRecord, LocalFileSymbols};
use std::path::Path;

pub fn supports_source_path(file_path: &str) -> bool {
    Path::new(file_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .and_then(crate::languages::get_adapter)
        .is_some()
}

pub fn parse_file(file_path: &str) -> FileRecord {
    parser_impl::parse_file(file_path)
}

pub fn parse_file_checked(file_path: &str) -> Result<FileRecord, String> {
    parser_impl::parse_file_checked(file_path)
}

pub fn parse_source_checked(file_path: &str, source_bytes: &[u8]) -> Result<FileRecord, String> {
    parser_impl::parse_source_checked(file_path, source_bytes)
}

pub fn parse_file_symbols(file_path: &str) -> LocalFileSymbols {
    parser_impl::parse_file_symbols(file_path)
}

pub fn parse_file_symbols_checked(file_path: &str) -> Result<LocalFileSymbols, String> {
    parser_impl::parse_file_symbols_checked(file_path)
}

pub(crate) fn parse_tree_sitter_source_checked(
    file_path: &str,
    source_bytes: &[u8],
) -> Result<tree_sitter::Tree, String> {
    parser_impl::parse_tree_sitter_source_checked(file_path, source_bytes)
}
