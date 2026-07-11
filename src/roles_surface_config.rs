use crate::roles::file_name;
use crate::types::FileRecord;

fn is_validation_helper_name(name: &str) -> bool {
    name.starts_with("_ensure_") || name.starts_with("_parse_") || name.starts_with("load_")
}

pub fn is_config_validation_module(file: &FileRecord) -> bool {
    let normalized = crate::roles::normalize_path(&file.file_path);
    let name = file_name(&normalized);
    let is_config_named = matches!(
        name,
        "config.py" | "config.rs" | "config.ts" | "config.js" | "config.go"
    ) || name.ends_with("_config.py")
        || name.ends_with("_config.rs")
        || name.ends_with("_config.ts")
        || name.ends_with("_config.js")
        || name.ends_with("_config.go");
    if !is_config_named || file.methods.is_empty() {
        return false;
    }

    let validation_methods = file
        .methods
        .iter()
        .filter(|method| is_validation_helper_name(&method.name))
        .count();
    if validation_methods == 0 {
        return false;
    }

    validation_methods * 2 >= file.methods.len()
}
