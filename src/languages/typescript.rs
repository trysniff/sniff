use crate::language_adapter::{ExportDetection, LanguageAdapter};

pub(super) fn adapter() -> LanguageAdapter {
    language_adapter!(
        "typescript",
        "tree-sitter-typescript",
        [".ts", ".tsx"],
        [
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
            "method_signature",
        ],
        ["arguments", "call_expression"],
        "name",
        "parameters",
        [
            "required_parameter",
            "optional_parameter",
            "rest_parameter",
            "identifier"
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
