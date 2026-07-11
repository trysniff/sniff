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
    pub references: Vec<SymbolReference>,
    pub scopes: Vec<HashSet<String>>,
    pub next_id: usize,
    pub in_impl: bool,
    pub current_impl_type: Option<String>,
}

impl<'a> RustExtractor<'a> {
    pub(super) fn visit_file<T>(&mut self, _file: &T) {
        let lines: Vec<&str> = self.source.lines().collect();
        let mut idx = 0usize;
        let mut impl_type: Option<String> = None;
        while idx < lines.len() {
            let trimmed = lines[idx].trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                idx += 1;
                continue;
            }

            if let Some((import, export)) = helpers::parse_use(trimmed) {
                self.imports.push(import);
                if let Some(export) = export {
                    self.exports.push(export);
                }
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
                });
                self.next_id += 1;
                idx = if trimmed.ends_with(';') { idx + 1 } else { end };
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("impl")
                && (rest.starts_with('<') || rest.chars().next().is_some_and(char::is_whitespace))
            {
                impl_type = helpers::parse_impl_name(trimmed);
                idx = self.scan_rust_impl_block(&lines, idx, impl_type.clone());
                continue;
            }

            if helpers::parse_fn_name(trimmed).is_some() {
                idx = self.scan_rust_fn_block(&lines, idx, impl_type.clone());
                continue;
            }

            for ref_name in helpers::scan::collect_refs(trimmed) {
                self.references.push(SymbolReference {
                    name: ref_name,
                    line: idx + 1,
                    snippet: trimmed.to_string(),
                    resolved_symbol: None,
                });
            }

            idx += 1;
        }
    }
}
