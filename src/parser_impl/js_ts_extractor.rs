use super::js_ts_functions::*;
use super::js_ts_imports::*;
use super::js_ts_references::*;
use super::*;
use crate::types::Reference;

fn extract_balanced_block(lines: &[&str], start: usize) -> usize {
    super::shared::scan_block_end(lines, start)
}

#[allow(clippy::too_many_arguments)]
fn build_method_record(
    file_path: &str,
    source: &str,
    name: &str,
    start_line: usize,
    end_line: usize,
    is_exported: bool,
    param_count: usize,
    refs: Vec<String>,
    line_index: &LineIndex,
) -> MethodRecord {
    let start_off = line_index.line_starts[start_line - 1];
    let end_off = if end_line < line_index.line_starts.len() {
        line_index.line_starts[end_line]
    } else {
        source.len()
    };
    let method_source = source[start_off..end_off].to_string();
    MethodRecord {
        name: name.to_string(),
        file_path: file_path.to_string(),
        source: method_source,
        loc: end_line.saturating_sub(start_line) + 1,
        param_count,
        start_line,
        end_line,
        is_exported,
        language: "javascript".to_string(),
        nesting_depth: 0,
        references: refs
            .into_iter()
            .map(|name| Reference {
                file_path: file_path.to_string(),
                line: start_line,
                snippet: name,
            })
            .collect(),
        real_ref_count: 0,
    }
}

fn push_method(methods: &mut Vec<MethodRecord>, method: MethodRecord) {
    methods.push(method);
}

#[allow(dead_code)]
pub(super) struct OxcExtractor<'a> {
    pub source: &'a str,
    pub line_index: LineIndex,
    pub file_path: String,
    pub methods: Vec<MethodRecord>,
    pub definitions: Vec<SymbolDefinition>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub references: Vec<SymbolReference>,
    pub scopes: Vec<HashSet<String>>,
    pub next_id: usize,
    pub current_name_hint: Option<String>,
    pub in_class: bool,
    pub in_function_body: bool,
    pub is_exported_context: bool,
}

impl<'a> OxcExtractor<'a> {
    pub(super) fn visit_program<T>(&mut self, _program: &T) {
        let lines: Vec<&str> = self.source.lines().collect();
        let mut i = 0usize;
        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                i += 1;
                continue;
            }

            if let Some(imports) = parse_import(trimmed) {
                self.imports.extend(imports);
                i += 1;
                continue;
            }

            if let Some(exports) = parse_export_from(trimmed) {
                self.exports.extend(exports);
                i += 1;
                continue;
            }

            if let Some((name, is_exported, is_default_export)) = parse_export_function(trimmed) {
                let params = trimmed
                    .split_once('(')
                    .and_then(|(_, rest)| rest.split_once(')').map(|(inside, _)| inside))
                    .unwrap_or("");
                let start_line = i + 1;
                let end_idx = extract_balanced_block(&lines, i);
                let end_line = end_idx + 1;
                let _body = lines[i..=end_idx].join("\n");
                self.definitions.push(SymbolDefinition {
                    id: self.next_id,
                    name: name.clone(),
                    kind: SymbolKind::Function,
                    start_line,
                    end_line,
                    is_exported,
                    owner_type: None,
                });
                self.next_id += 1;
                if is_exported {
                    self.exports.push(ExportRecord {
                        exported_name: if is_default_export {
                            "default".to_string()
                        } else {
                            name.clone()
                        },
                        local_symbol_name: name.clone(),
                        source_module: None,
                        source_symbol_name: None,
                    });
                }
                let mut refs = Vec::new();
                for (offset, body_line) in lines[i..=end_idx].iter().enumerate() {
                    let line_no = i + offset + 1;
                    for r in collect_js_references(body_line) {
                        if r != name {
                            self.references.push(SymbolReference {
                                name: r.clone(),
                                line: line_no,
                                snippet: body_line.trim().to_string(),
                                resolved_symbol: None,
                            });
                            refs.push(r);
                        }
                    }
                }
                push_method(
                    &mut self.methods,
                    build_method_record(
                        &self.file_path,
                        self.source,
                        &name,
                        start_line,
                        end_line,
                        is_exported,
                        count_params(params),
                        refs,
                        &self.line_index,
                    ),
                );
                i = end_idx + 1;
                continue;
            }

            if let Some((name, param_count)) = parse_arrow_function(trimmed) {
                let start_line = i + 1;
                let end_idx = extract_balanced_block(&lines, i);
                let end_line = end_idx + 1;
                let _body = lines[i..=end_idx].join("\n");
                self.definitions.push(SymbolDefinition {
                    id: self.next_id,
                    name: name.clone(),
                    kind: SymbolKind::Function,
                    start_line,
                    end_line,
                    is_exported: false,
                    owner_type: None,
                });
                self.next_id += 1;
                let mut refs = Vec::new();
                for (offset, body_line) in lines[i..=end_idx].iter().enumerate() {
                    let line_no = i + offset + 1;
                    for r in collect_js_references(body_line) {
                        self.references.push(SymbolReference {
                            name: r.clone(),
                            line: line_no,
                            snippet: body_line.trim().to_string(),
                            resolved_symbol: None,
                        });
                        refs.push(r);
                    }
                }
                push_method(
                    &mut self.methods,
                    build_method_record(
                        &self.file_path,
                        self.source,
                        &name,
                        start_line,
                        end_line,
                        false,
                        param_count,
                        refs,
                        &self.line_index,
                    ),
                );
                i = end_idx + 1;
                continue;
            }

            for r in collect_js_references(trimmed) {
                self.references.push(SymbolReference {
                    name: r,
                    line: i + 1,
                    snippet: trimmed.to_string(),
                    resolved_symbol: None,
                });
            }
            i += 1;
        }
    }
}
