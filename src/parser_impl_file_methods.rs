use super::*;
use std::collections::HashSet;
use std::path::Path;

fn parse_js_ts_file_methods(record: &mut FileRecord, file_path: &str) -> Result<(), String> {
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::from_path(Path::new(file_path)).unwrap_or_default();
    let parser = oxc_parser::Parser::new(&allocator, &record.source, source_type);
    let parsed = parser.parse();
    if !parsed.errors.is_empty() {
        return Err(format!(
            "failed to parse {file_path}: {} JavaScript/TypeScript parser error(s): {:?}",
            parsed.errors.len(),
            parsed.errors
        ));
    }

    let line_index = LineIndex::new(&record.source);
    let mut extractor = oxc::OxcExtractor {
        source: &record.source,
        line_index,
        file_path: file_path.to_string(),
        methods: Vec::new(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        references: Vec::new(),
        scopes: vec![HashSet::new()],
        next_id: 0,
        current_name_hint: None,
        in_class: false,
        in_function_body: false,
        is_exported_context: false,
    };

    extractor.visit_program(&parsed.program);
    record.methods = extractor.methods;
    Ok(())
}

fn parse_python_file_methods(record: &mut FileRecord, file_path: &str) -> Result<(), String> {
    let parsed =
        rustpython_parser::parse(&record.source, rustpython_parser::Mode::Module, file_path)
            .map_err(|err| format!("failed to parse {file_path}: {err}"))?;
    let rustpython_ast::Mod::Module(module) = parsed else {
        return Err(format!(
            "failed to parse {file_path}: source is not a Python module"
        ));
    };
    let line_index = LineIndex::new(&record.source);
    let mut extractor = python::PyExtractor {
        source: &record.source,
        line_index,
        file_path: file_path.to_string(),
        methods: Vec::new(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        references: Vec::new(),
        scopes: vec![HashSet::new()],
        next_id: 0,
        parent_is_class: false,
        in_function_body: false,
        scanned: false,
    };

    for stmt in module.body {
        extractor.visit_stmt(stmt);
    }
    record.methods = extractor.methods;
    Ok(())
}

fn parse_rust_file_methods(record: &mut FileRecord, file_path: &str) -> Result<(), String> {
    let ast = syn::parse_file(&record.source)
        .map_err(|err| format!("failed to parse {file_path}: {err}"))?;
    let mut extractor = rust::RustExtractor {
        source: &record.source,
        file_path: file_path.to_string(),
        methods: Vec::new(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        references: Vec::new(),
        scopes: vec![HashSet::new()],
        next_id: 0,
        in_impl: false,
        current_impl_type: None,
    };

    extractor.visit_file(&ast);
    record.language = "rust".to_string();
    record.methods = extractor.methods;
    Ok(())
}

fn parse_kotlin_file_methods(
    record: &mut FileRecord,
    file_path: &str,
    adapter: &LanguageAdapter,
) -> Result<(), String> {
    let mut parser = match kotlin::get_parser(adapter) {
        Some(p) => p,
        None => return Err(format!("no Kotlin parser available for {file_path}")),
    };

    let tree = parser
        .parse(record.source.as_bytes(), None)
        .ok_or_else(|| format!("failed to parse {file_path}: parser returned no syntax tree"))?;
    if tree.root_node().has_error() {
        return Err(format!(
            "failed to parse {file_path}: Kotlin syntax tree contains error nodes"
        ));
    }
    record.methods = kotlin::extract_methods(
        tree.root_node(),
        record.source.as_bytes(),
        adapter,
        file_path,
    );
    Ok(())
}

fn parse_go_file_methods(
    record: &mut FileRecord,
    file_path: &str,
    adapter: &LanguageAdapter,
) -> Result<(), String> {
    let mut parser = match go::get_parser(adapter) {
        Some(p) => p,
        None => return Err(format!("no Go parser available for {file_path}")),
    };

    let tree = parser
        .parse(record.source.as_bytes(), None)
        .ok_or_else(|| format!("failed to parse {file_path}: parser returned no syntax tree"))?;
    if tree.root_node().has_error() {
        return Err(format!(
            "failed to parse {file_path}: Go syntax tree contains error nodes"
        ));
    }
    record.methods = go::extract_methods(
        tree.root_node(),
        record.source.as_bytes(),
        adapter,
        file_path,
    );
    Ok(())
}

pub(crate) fn parse_methods_for_language(
    record: &mut FileRecord,
    file_path: &str,
    adapter: &LanguageAdapter,
) -> Result<(), String> {
    match adapter.name.as_str() {
        "javascript" | "typescript" => parse_js_ts_file_methods(record, file_path),
        "python" => parse_python_file_methods(record, file_path),
        "rust" => parse_rust_file_methods(record, file_path),
        "kotlin" => parse_kotlin_file_methods(record, file_path, adapter),
        "go" => parse_go_file_methods(record, file_path, adapter),
        other => Err(format!(
            "no parser implementation for {other} ({file_path})"
        )),
    }
}
