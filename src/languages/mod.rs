use crate::language_adapter::LanguageAdapter;

macro_rules! language_adapter {
    (
        $name:expr,
        $grammar_package:expr,
        [$($extension:expr),* $(,)?],
        [$($function_node_type:expr),* $(,)?],
        [$($excluded_parent_type:expr),* $(,)?],
        $name_field:expr,
        $params_field:expr,
        [$($param_node_type:expr),* $(,)?],
        [$($nesting_node_type:expr),* $(,)?],
        $export_detection:expr,
        [$($generic_name:expr),* $(,)?],
        [$($allowed_name:expr),* $(,)?]
    ) => {
        LanguageAdapter {
            name: $name.into(),
            grammar_package: $grammar_package.into(),
            extensions: vec![$($extension.into()),*],
            function_node_types: vec![$($function_node_type.into()),*],
            excluded_parent_types: vec![$($excluded_parent_type.into()),*],
            name_field: $name_field.into(),
            params_field: $params_field.into(),
            param_node_types: vec![$($param_node_type.into()),*],
            nesting_node_types: vec![$($nesting_node_type.into()),*],
            export_detection: $export_detection,
            generic_names: vec![$($generic_name.into()),*],
            allowed_names: vec![$($allowed_name.into()),*],
        }
    };
}

mod go;
mod javascript;
mod kotlin;
mod python;
mod rust;
mod typescript;

pub fn get_adapter(extension: &str) -> Option<LanguageAdapter> {
    let ext = extension
        .strip_prefix('.')
        .unwrap_or(extension)
        .to_ascii_lowercase();
    match ext.as_str() {
        "js" | "jsx" => Some(javascript::adapter()),
        "ts" | "tsx" => Some(typescript::adapter()),
        "kt" | "kts" => Some(kotlin::adapter()),
        "py" => Some(python::adapter()),
        "go" => Some(go::adapter()),
        "rs" => Some(rust::adapter()),
        _ => None,
    }
}
