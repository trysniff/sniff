use super::*;
use std::fs;
use std::path::Path;

#[path = "parser_impl_file_methods.rs"]
mod methods;
#[path = "parser_impl_file_symbols.rs"]
mod symbols;

fn load_file_context(file_path: &str) -> Option<(Vec<u8>, LanguageAdapter)> {
    load_file_context_checked(file_path).ok()
}

fn load_file_context_checked(file_path: &str) -> Result<(Vec<u8>, LanguageAdapter), String> {
    let path = Path::new(file_path);
    let source_bytes =
        fs::read(path).map_err(|err| format!("failed to read source file {file_path}: {err}"))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .ok_or_else(|| format!("source file has no supported extension: {file_path}"))?;
    let adapter = languages::get_adapter(ext)
        .ok_or_else(|| format!("unsupported source extension for {file_path}"))?;
    Ok((source_bytes, adapter))
}

pub(in crate::parser) fn parse_file(file_path: &str) -> FileRecord {
    let mut record = FileRecord {
        file_path: file_path.to_string(),
        source: String::new(),
        language: String::new(),
        methods: Vec::new(),
    };

    let Some((source_bytes, adapter)) = load_file_context(file_path) else {
        return record;
    };

    record.source = String::from_utf8_lossy(&source_bytes).into_owned();
    record.language = adapter.name.clone();
    let _ = methods::parse_methods_for_language(&mut record, file_path, &adapter);

    record
}

pub(in crate::parser) fn parse_file_checked(file_path: &str) -> Result<FileRecord, String> {
    let (source_bytes, adapter) = load_file_context_checked(file_path)?;
    let source = String::from_utf8(source_bytes)
        .map_err(|err| format!("source file is not valid UTF-8 {file_path}: {err}"))?;
    let mut record = FileRecord {
        file_path: file_path.to_string(),
        source,
        language: adapter.name.clone(),
        methods: Vec::new(),
    };
    methods::parse_methods_for_language(&mut record, file_path, &adapter)?;
    Ok(record)
}

pub(in crate::parser) fn parse_file_symbols_checked(
    file_path: &str,
) -> Result<LocalFileSymbols, String> {
    let (source_bytes, adapter) = load_file_context_checked(file_path)?;
    let source_text = String::from_utf8(source_bytes.clone())
        .map_err(|err| format!("source file is not valid UTF-8 {file_path}: {err}"))?;

    // Validate the same syntax used by the method extractor before building
    // the graph, so graph failures cannot silently become zero references.
    let mut validation_record = FileRecord {
        file_path: file_path.to_string(),
        source: source_text.clone(),
        language: adapter.name.clone(),
        methods: Vec::new(),
    };
    methods::parse_methods_for_language(&mut validation_record, file_path, &adapter)?;

    Ok(symbols::parse_symbols_for_language(
        &source_text,
        &source_bytes,
        file_path,
        &adapter,
    ))
}

pub(in crate::parser) fn parse_file_symbols(file_path: &str) -> LocalFileSymbols {
    let Some((source_bytes, adapter)) = load_file_context(file_path) else {
        return LocalFileSymbols {
            file_path: file_path.to_string(),
            definitions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            modules: Vec::new(),
            types: Vec::new(),
            references: Vec::new(),
        };
    };

    let source_text = String::from_utf8_lossy(&source_bytes).into_owned();
    symbols::parse_symbols_for_language(&source_text, &source_bytes, file_path, &adapter)
}

#[cfg(test)]
#[path = "tests/parser_impl_file.rs"]
mod tests;
