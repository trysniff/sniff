use super::*;

#[path = "python_defs.rs"]
mod core;
#[path = "python_core_helpers.rs"]
mod core_helpers;
#[path = "python_references.rs"]
mod refs;

#[allow(dead_code)]
pub(crate) struct PyExtractor<'a> {
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
    pub parent_is_class: bool,
    pub in_function_body: bool,
    pub scanned: bool,
}

impl<'a> PyExtractor<'a> {
    pub(crate) fn visit_stmt<T>(&mut self, _stmt: T) {
        let spans = core::scan_python_defs_and_imports(self);
        let spans = spans
            .into_iter()
            .map(|(start, end, shadowed, header)| refs::PythonSpan {
                start,
                end,
                shadowed,
                header,
            })
            .collect::<Vec<_>>();
        refs::scan_python_references(self, &spans);
    }
}
