use crate::roles::is_versioning_tag_module;
use crate::slop_reason::{self, ReasonKind};
use crate::types::FileRecord;

pub(crate) fn should_clear_versioning_verdict(file: &FileRecord, reason: &str) -> bool {
    is_versioning_tag_module(&file.file_path)
        && (slop_reason::is(reason, ReasonKind::StrongSlop)
            || reason.to_lowercase().contains("overbuilt logic")
            || reason.to_lowercase().contains("source order")
            || reason.to_lowercase().contains("monotonicity"))
}
