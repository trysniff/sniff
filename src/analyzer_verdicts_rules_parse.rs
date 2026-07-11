use crate::roles::is_parsing_or_serialization_helper_module;
use crate::slop_reason::{self, ReasonKind};
use crate::types::FileRecord;

pub(crate) fn should_clear_parsing_verdict(file: &FileRecord, reason: &str) -> bool {
    is_parsing_or_serialization_helper_module(&file.file_path)
        && (slop_reason::any(
            reason,
            &[
                ReasonKind::StrongSlop,
                ReasonKind::ControlFlow,
                ReasonKind::FilenameVague,
            ],
        ) || reason.to_lowercase().contains("helper surface")
            || reason
                .to_lowercase()
                .contains("module mixes public surface and orchestration"))
}
