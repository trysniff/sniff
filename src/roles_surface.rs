#[path = "roles_surface_assignment.rs"]
mod assignment;
#[path = "roles_surface_config.rs"]
mod config;
#[path = "roles_surface_contract.rs"]
mod contract;
#[path = "roles_surface_facade.rs"]
mod facade;
#[path = "roles_surface_hooks.rs"]
mod hooks;
#[path = "roles_surface_presentation.rs"]
mod presentation;
#[path = "roles_surface_protocol.rs"]
mod protocol;

use crate::types::FileRecord;

fn source_has_export_markers(source: &str) -> bool {
    let lower = source.to_lowercase();
    (lower.contains("from ") && lower.contains(" import "))
        || lower.contains("export * from")
        || lower.contains("export {")
        || lower.contains("pub use ")
        || lower.contains("__all__")
        || lower.contains(" as _")
}

fn source_has_only_exports(source: &str) -> bool {
    let lower = source.to_lowercase();
    source_has_export_markers(source) && !lower.contains("def ") && !lower.contains("class ")
}

fn source_has_only_module_declarations(source: &str) -> bool {
    let mut saw_declaration = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        let is_module_declaration = trimmed.starts_with("mod ")
            || trimmed.starts_with("pub mod ")
            || (trimmed.starts_with("pub(")
                && (trimmed.contains(" mod ") || trimmed.contains(" use ")));
        let is_use_declaration = trimmed.starts_with("use ")
            || trimmed.starts_with("pub use ")
            || (trimmed.starts_with("pub(") && trimmed.contains(" use "));
        let is_attribute = trimmed.starts_with("#![") || trimmed.starts_with("#[");

        if is_module_declaration || is_use_declaration || is_attribute {
            saw_declaration = true;
            continue;
        }

        return false;
    }

    saw_declaration
}

pub fn source_looks_like_wrapper_module(source: &str) -> bool {
    source_has_export_markers(source)
}

pub fn is_pure_reexport_module(file: &FileRecord) -> bool {
    source_has_only_exports(&file.source)
        || (file.methods.is_empty()
            && source_has_export_markers(&file.source)
            && !file.source.to_lowercase().contains("def "))
}

pub fn is_module_barrel_module(file: &FileRecord) -> bool {
    file.methods.is_empty() && source_has_only_module_declarations(&file.source)
}

pub fn is_wrapper_only_module(file: &FileRecord) -> bool {
    if file.methods.is_empty() {
        return false;
    }

    file.methods.iter().all(|method| {
        facade::is_thin_wrapper_export(method) || facade::is_thin_delegation_method(method)
    })
}

pub use assignment::is_wrapper_assignment;
pub use config::is_config_validation_module;
pub use contract::is_callback_contract_module;
pub use facade::{is_detector_facade_module, is_thin_delegation_method, is_thin_wrapper_export};
pub use hooks::is_hydration_hook_module;
pub use presentation::is_presentation_surface_module;
pub use protocol::{is_protocol_stub_method, is_protocol_surface_module};
