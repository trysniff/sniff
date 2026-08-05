use super::*;
use std::collections::HashSet;

#[allow(dead_code)]
pub(crate) struct SymbolExtractor<'a> {
    pub source_bytes: &'a [u8],
    pub language: &'a str,
    pub adapter: &'a LanguageAdapter,
    pub definitions: Vec<SymbolDefinition>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub modules: Vec<ModuleRecord>,
    pub types: Vec<TypeRecord>,
    pub references: Vec<SymbolReference>,
    pub scopes: Vec<HashSet<String>>,
    pub next_id: usize,
}
