use crate::roles::{file_name, normalize_path};
use crate::types::FileRecord;

fn is_common_hydration_hook_name(name: &str) -> bool {
    matches!(
        name,
        "usehasmounted.ts"
            | "usehasmounted.tsx"
            | "useismounted.ts"
            | "useismounted.tsx"
            | "usebrowser.ts"
            | "usebrowser.tsx"
    )
}

pub fn is_hydration_hook_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    if !normalized.contains("/hooks/") {
        return false;
    }

    let name = file_name(&normalized);
    if is_common_hydration_hook_name(name) {
        return true;
    }

    let lowered = file.source.to_lowercase();
    lowered.contains("useeffect(")
        && lowered.contains("settimeout(")
        && lowered.contains("cleartimeout(")
        && lowered.contains("usestate(false)")
        && lowered.contains("return hasmounted")
}
