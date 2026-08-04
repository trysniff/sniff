use crate::types::{LocalFileSymbols, ResolvedSymbol};

use super::same_path;

pub(crate) fn resolve_direct_symbol(
    current_file: &str,
    target_file: &str,
    file_symbols: &LocalFileSymbols,
    symbol_name: &str,
) -> Option<ResolvedSymbol> {
    let def = file_symbols
        .definitions
        .iter()
        .find(|def| def.name == symbol_name)?;
    if same_path(current_file, target_file) {
        Some(ResolvedSymbol::Local(def.id))
    } else {
        Some(ResolvedSymbol::External {
            file_path: target_file.to_string(),
            symbol_name: def.name.clone(),
            definition_id: Some(def.id),
        })
    }
}
