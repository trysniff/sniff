use crate::language_adapter::{ExportDetection, LanguageAdapter};

pub(super) fn adapter() -> LanguageAdapter {
    language_adapter!(
        "go",
        "tree-sitter-go",
        [".go"],
        ["function_declaration", "method_declaration"],
        [],
        "name",
        "parameters",
        ["parameter_declaration", "variadic_parameter_declaration"],
        [
            "if_statement",
            "for_statement",
            "switch_statement",
            "select_statement",
            "type_switch_statement",
        ],
        ExportDetection::Convention,
        ["Handle*", "Process*", "Do*", "Manage*", "Get*"],
        []
    )
}
