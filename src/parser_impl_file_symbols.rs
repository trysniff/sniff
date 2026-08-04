use super::*;
use std::collections::HashSet;
use std::path::Path;

fn parse_js_ts_symbols(source_text: &str, file_path: &str) -> LocalFileSymbols {
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::from_path(Path::new(file_path)).unwrap_or_default();
    let parser = oxc_parser::Parser::new(&allocator, source_text, source_type);
    let parsed = parser.parse();

    let line_index = LineIndex::new(source_text);
    let mut extractor = oxc::OxcExtractor {
        source: source_text,
        line_index,
        file_path: file_path.to_string(),
        methods: Vec::new(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        references: Vec::new(),
        next_id: 0,
        current_name_hint: None,
        current_class: None,
        current_class_exported: false,
        current_object: None,
        current_object_exported: false,
        is_exported_context: false,
        callable_depth: 0,
    };

    extractor.visit_program(&parsed.program);

    LocalFileSymbols {
        file_path: file_path.to_string(),
        definitions: extractor.definitions,
        imports: extractor.imports,
        exports: extractor.exports,
        modules: Vec::new(),
        types: Vec::new(),
        references: extractor.references,
    }
}

fn parse_python_symbols(source_text: &str, file_path: &str) -> LocalFileSymbols {
    let mut symbols = LocalFileSymbols {
        file_path: file_path.to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: Vec::new(),
    };

    let parsed = rustpython_parser::parse(source_text, rustpython_parser::Mode::Module, file_path);
    if let Ok(ast) = parsed
        && let rustpython_ast::Mod::Module(module) = ast
    {
        let line_index = LineIndex::new(source_text);
        let mut extractor = python::PyExtractor {
            source: source_text,
            line_index,
            file_path: file_path.to_string(),
            methods: Vec::new(),
            definitions: Vec::new(),
            imports: Vec::new(),
            scoped_imports: Vec::new(),
            exports: Vec::new(),
            types: Vec::new(),
            references: Vec::new(),
            scopes: vec![HashSet::new()],
            next_id: 0,
            parent_is_class: false,
            in_function_body: false,
            scanned: false,
            explicit_exports: None,
        };

        for stmt in module.body {
            extractor.visit_stmt(stmt);
        }

        symbols.definitions = extractor.definitions;
        symbols.imports = extractor.imports;
        symbols.exports = extractor.exports;
        symbols.types = extractor.types;
        symbols.references = extractor.references;
    }

    symbols
}

fn parse_rust_symbols(source_text: &str, file_path: &str) -> LocalFileSymbols {
    let mut symbols = LocalFileSymbols {
        file_path: file_path.to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: Vec::new(),
    };

    if let Ok(ast) = syn::parse_file(source_text) {
        let mut extractor = rust::RustExtractor {
            source: source_text,
            file_path: file_path.to_string(),
            methods: Vec::new(),
            definitions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            modules: Vec::new(),
            references: Vec::new(),
            scopes: vec![HashSet::new()],
            next_id: 0,
            in_impl: false,
            current_impl_type: None,
        };

        extractor.visit_file(&ast);
        symbols.definitions = extractor.definitions;
        symbols.imports = extractor.imports;
        symbols.exports = extractor.exports;
        symbols.modules = extractor.modules;
        symbols.references = extractor.references;
    }

    for def in &symbols.definitions {
        if !def.name.starts_with('_')
            && !symbols
                .exports
                .iter()
                .any(|e| e.local_symbol_name == def.name)
        {
            symbols.exports.push(ExportRecord {
                exported_name: def.name.clone(),
                local_symbol_name: def.name.clone(),
                source_module: None,
                source_symbol_name: None,
            });
        }
    }

    symbols
}

fn parse_kotlin_symbols(
    source_bytes: &[u8],
    file_path: &str,
    adapter: &LanguageAdapter,
) -> LocalFileSymbols {
    let mut symbols = LocalFileSymbols {
        file_path: file_path.to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: Vec::new(),
    };

    let mut parser = match kotlin::get_parser(adapter) {
        Some(p) => p,
        None => return symbols,
    };

    if let Some(tree) = parser.parse(source_bytes, None) {
        let mut extractor = kotlin::SymbolExtractor {
            source_bytes,
            language: &adapter.name,
            adapter,
            definitions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            modules: Vec::new(),
            references: Vec::new(),
            scopes: vec![HashSet::new()],
            next_id: 0,
        };

        extractor.visit(tree.root_node());
        symbols.definitions = extractor.definitions;
        symbols.imports = extractor.imports;
        symbols.exports = extractor.exports;
        symbols.modules = extractor.modules;
        symbols.references = extractor.references;
    }

    symbols
}

fn parse_go_symbols(
    source_bytes: &[u8],
    file_path: &str,
    adapter: &LanguageAdapter,
) -> LocalFileSymbols {
    let mut symbols = LocalFileSymbols {
        file_path: file_path.to_string(),
        definitions: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        modules: Vec::new(),
        types: Vec::new(),
        references: Vec::new(),
    };

    let mut parser = match go::get_parser(adapter) {
        Some(p) => p,
        None => return symbols,
    };

    if let Some(tree) = parser.parse(source_bytes, None) {
        let mut extractor = go::SymbolExtractor {
            source_bytes,
            language: &adapter.name,
            adapter,
            definitions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            references: Vec::new(),
            scopes: vec![HashSet::new()],
            next_id: 0,
        };

        extractor.visit(tree.root_node());
        symbols.definitions = extractor.definitions;
        symbols.imports = extractor.imports;
        symbols.exports = extractor.exports;
        symbols.references = extractor.references;

        if adapter.name == "go" {
            for def in &symbols.definitions {
                if let Some(first_char) = def.name.chars().next()
                    && first_char.is_uppercase()
                {
                    symbols.exports.push(ExportRecord {
                        exported_name: def.name.clone(),
                        local_symbol_name: def.name.clone(),
                        source_module: None,
                        source_symbol_name: None,
                    });
                }
            }
        }
    }

    symbols
}

pub(crate) fn parse_symbols_for_language(
    source_text: &str,
    source_bytes: &[u8],
    file_path: &str,
    adapter: &LanguageAdapter,
) -> LocalFileSymbols {
    match adapter.name.as_str() {
        "javascript" | "typescript" => parse_js_ts_symbols(source_text, file_path),
        "python" => parse_python_symbols(source_text, file_path),
        "rust" => parse_rust_symbols(source_text, file_path),
        "kotlin" => parse_kotlin_symbols(source_bytes, file_path, adapter),
        "go" => parse_go_symbols(source_bytes, file_path, adapter),
        _ => LocalFileSymbols {
            file_path: file_path.to_string(),
            definitions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            modules: Vec::new(),
            types: Vec::new(),
            references: Vec::new(),
        },
    }
}
