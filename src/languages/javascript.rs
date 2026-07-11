use crate::language_adapter::{ExportDetection, LanguageAdapter};

pub(super) fn adapter() -> LanguageAdapter {
    language_adapter!(
        "javascript",
        "tree-sitter-javascript",
        [".js", ".jsx", ".mjs", ".cjs"],
        [
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        ],
        ["arguments", "call_expression"],
        "name",
        "parameters",
        [
            "identifier",
            "rest_pattern",
            "assignment_pattern",
            "object_pattern",
            "array_pattern"
        ],
        [
            "if_statement",
            "for_statement",
            "for_in_statement",
            "while_statement",
            "switch_statement",
            "try_statement",
        ],
        ExportDetection::Keyword,
        [
            "handle*", "process*", "do*", "manage*", "data", "result", "temp", "info"
        ],
        []
    )
}
