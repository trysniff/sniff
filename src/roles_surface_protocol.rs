use crate::roles::normalize_path;
use crate::types::{FileRecord, MethodRecord};

pub fn is_protocol_stub_method(method: &MethodRecord) -> bool {
    let source = method.source.trim();
    if source.is_empty() {
        return false;
    }

    let mut body_lines = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    if let Some(signature) = body_lines.next() {
        let lowered = signature.to_lowercase();
        if signature.ends_with("...")
            || signature.ends_with("pass")
            || signature.contains(": ...")
            || lowered.contains(": pass")
            || lowered.ends_with("raise notimplementederror")
            || lowered.contains(": raise notimplementederror")
        {
            return true;
        }
    }

    body_lines.any(|line| {
        let lowered = line.to_lowercase();
        line == "..."
            || line == "pass"
            || line.ends_with("...")
            || lowered.ends_with("pass")
            || lowered.contains(": ...")
            || lowered.contains(": pass")
            || lowered.contains("raise notimplementederror")
            || lowered.contains("return notimplementederror")
    })
}

pub fn is_protocol_surface_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    if normalized.ends_with("_protocols.py") {
        return !file.methods.is_empty();
    }

    if !file.source.contains("Protocol") {
        return false;
    }

    if file.methods.is_empty() {
        return false;
    }

    file.methods.iter().all(is_protocol_stub_method)
}
