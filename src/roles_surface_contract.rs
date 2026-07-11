use crate::roles::normalize_path;
use crate::types::FileRecord;

fn looks_like_callback_contract_source(source: &str) -> bool {
    let lowered = source.to_lowercase();
    if !lowered.contains("data class") {
        return false;
    }
    if lowered.contains("@composable") || lowered.contains("\nfun ") {
        return false;
    }

    let callback_properties = source.matches("-> Unit").count()
        + source.matches("-> () -> Unit").count()
        + source.matches("= {}").count()
        + source.matches("= { _ -> }").count();

    callback_properties >= 3
}

pub fn is_callback_contract_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    let name = crate::roles::file_name(&normalized).to_lowercase();

    let looks_like_kotlin = normalized.ends_with(".kt") || normalized.ends_with(".kts");
    if !looks_like_kotlin {
        return false;
    }

    let name_hint = name.ends_with("callbacks.kt")
        || name.ends_with("callbacks.kts")
        || name.ends_with("models.kt")
        || name.ends_with("bindings.kt");

    name_hint && looks_like_callback_contract_source(&file.source)
        || looks_like_callback_contract_source(&file.source)
}
