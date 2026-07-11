use crate::types::LocalFileSymbols;

pub(crate) fn resolve_default_export(file_symbols: &LocalFileSymbols) -> Option<String> {
    file_symbols
        .exports
        .iter()
        .find(|e| e.exported_name == "default")
        .map(|e| e.local_symbol_name.clone())
}

pub(crate) fn resolve_symbol_key(file_path: &str, symbol_name: &str) -> String {
    format!(
        "{}::{}",
        super::core::normalize_path(file_path),
        symbol_name
    )
}

pub(crate) fn same_path(a: &str, b: &str) -> bool {
    super::core::normalize_path(a) == super::core::normalize_path(b)
}
