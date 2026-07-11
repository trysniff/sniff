use crate::language_adapter::{ExportDetection, LanguageAdapter};

pub(super) fn adapter() -> LanguageAdapter {
    language_adapter!(
        "rust",
        "syn",
        [".rs"],
        [],
        [],
        "name",
        "parameters",
        [],
        ["if", "match", "for", "while", "loop", "try"],
        ExportDetection::Convention,
        [
            "handle*", "process*", "do*", "manage*", "data", "result", "temp", "info"
        ],
        ["main", "new", "default", "from", "into", "clone"]
    )
}
