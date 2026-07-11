use crate::roles::{
    is_detector_facade_module, is_detector_support_module, is_utility_surface_module,
};
use crate::types::FileRecord;

fn detector_noise_reason(lower_reason: &str) -> bool {
    lower_reason.contains("filename is vague")
        || lower_reason.contains("vague filename")
        || lower_reason.contains("filename suggests")
        || (lower_reason.contains("filename") && lower_reason.contains("suggests"))
        || lower_reason.contains("helper surface")
        || lower_reason.contains("sprawling helper surface")
        || lower_reason.contains("file does too much")
        || lower_reason.contains("branchy control flow")
        || lower_reason.contains("control flow is tangled")
        || lower_reason.contains("name is vague")
        || lower_reason.contains("placeholder implementation")
}

pub(super) fn should_clear_detector_verdict(
    file: &FileRecord,
    _reason: &str,
    lower_reason: &str,
) -> bool {
    is_detector_facade_module(file)
        || (is_detector_support_module(&file.file_path) && detector_noise_reason(lower_reason))
        || (is_utility_surface_module(file) && detector_noise_reason(lower_reason))
}
