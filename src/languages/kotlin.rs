use crate::language_adapter::{ExportDetection, LanguageAdapter};

pub(super) fn adapter() -> LanguageAdapter {
    language_adapter!(
        "kotlin",
        "tree-sitter-kotlin",
        [".kt", ".kts"],
        ["function_declaration", "secondary_constructor",],
        [],
        "name",
        "value_parameters",
        ["value_parameter", "lambda_literal",],
        [
            "if_expression",
            "when_expression",
            "for_statement",
            "while_statement",
            "do_while_statement",
            "try_expression",
        ],
        ExportDetection::None,
        [
            "handle*", "process*", "do*", "manage*", "data", "result", "temp", "info",
        ],
        ["main", "new", "default", "from", "into", "clone",]
    )
}
