use super::*;

#[path = "rust_helpers.rs"]
mod helpers;

#[allow(dead_code)]
pub(super) struct RustExtractor<'a> {
    pub source: &'a str,
    pub file_path: String,
    pub methods: Vec<MethodRecord>,
    pub definitions: Vec<SymbolDefinition>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub modules: Vec<ModuleRecord>,
    pub references: Vec<SymbolReference>,
    pub scopes: Vec<HashSet<String>>,
    pub next_id: usize,
    pub in_impl: bool,
    pub current_impl_type: Option<String>,
}

impl<'a> RustExtractor<'a> {
    pub(super) fn visit_file(&mut self, file: &syn::File) {
        let lines: Vec<&str> = self.source.lines().collect();
        let mut idx = 0usize;
        while idx < lines.len() {
            let trimmed = lines[idx].trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                idx += 1;
                continue;
            }

            if trimmed.starts_with("use ")
                || trimmed.starts_with("pub use ")
                || trimmed.starts_with("pub(crate) use ")
                || trimmed.starts_with("pub(super) use ")
            {
                idx += 1;
                continue;
            }

            if let Some(name) = helpers::parse_struct_name(trimmed) {
                let start = idx + 1;
                let end = if trimmed.ends_with(';') {
                    start
                } else {
                    helpers::balanced_end(&lines, idx) + 1
                };
                self.definitions.push(SymbolDefinition {
                    id: self.next_id,
                    name: name.clone(),
                    kind: SymbolKind::Class,
                    start_line: start,
                    end_line: end,
                    is_exported: trimmed.starts_with("pub ") || trimmed.starts_with("pub("),
                    owner_type: None,
                    receiver_type: None,
                    value_type: None,
                });
                self.next_id += 1;
                idx = if trimmed.ends_with(';') { idx + 1 } else { end };
                continue;
            }

            if let Some(name) = helpers::parse_fn_name(trimmed) {
                for reference in helpers::scan::collect_refs(trimmed) {
                    if reference.name != name {
                        self.references.push(SymbolReference {
                            name: reference.name,
                            line: idx + 1,
                            snippet: trimmed.to_string(),
                            is_member_call: reference.is_member_call,
                            is_callable_value: false,
                            resolved_symbol: None,
                        });
                    }
                }
                idx += 1;
                continue;
            }

            for reference in helpers::scan::collect_refs(trimmed) {
                self.references.push(SymbolReference {
                    name: reference.name,
                    line: idx + 1,
                    snippet: trimmed.to_string(),
                    is_member_call: reference.is_member_call,
                    is_callable_value: false,
                    resolved_symbol: None,
                });
            }

            idx += 1;
        }

        // The file was already validated by syn. Use its spans as the source of
        // truth for callable boundaries rather than trying to balance Rust syntax.
        helpers::record_rust_ast_modules_and_uses(self, file);
        helpers::record_rust_ast_callables(self, file);
        helpers::record_rust_ast_callable_values(self, file);
        helpers::record_rust_ast_token_references(self, file);
    }
}
