use super::*;

#[path = "python_defs.rs"]
mod core;
#[path = "python_core_helpers.rs"]
mod core_helpers;
#[path = "python_references.rs"]
mod refs;

#[allow(dead_code)]
pub(crate) struct ScopedPythonImport {
    pub local_name: String,
    pub scoped_name: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[allow(dead_code)]
pub(crate) struct PyExtractor<'a> {
    pub source: &'a str,
    pub line_index: LineIndex,
    pub file_path: String,
    pub methods: Vec<MethodRecord>,
    pub definitions: Vec<SymbolDefinition>,
    pub imports: Vec<ImportRecord>,
    pub scoped_imports: Vec<ScopedPythonImport>,
    pub exports: Vec<ExportRecord>,
    pub types: Vec<TypeRecord>,
    pub references: Vec<SymbolReference>,
    pub scopes: Vec<HashSet<String>>,
    pub next_id: usize,
    pub parent_is_class: bool,
    pub in_function_body: bool,
    pub scanned: bool,
    pub explicit_exports: Option<HashSet<String>>,
}

impl<'a> PyExtractor<'a> {
    pub(crate) fn visit_stmt(&mut self, stmt: rustpython_ast::Stmt) {
        let spans = core::scan_python_defs_and_imports(self);
        let spans = spans
            .into_iter()
            .map(|(start, end, shadowed)| refs::PythonSpan {
                start,
                end,
                shadowed,
            })
            .collect::<Vec<_>>();
        refs::scan_python_references(self, &spans);
        core::record_python_assignment_alias(self, &stmt);
        core::record_python_explicit_exports(self, &stmt);
    }
}
