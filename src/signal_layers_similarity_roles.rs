use crate::roles::FileRole;
use crate::roles::is_protocol_stub_method;
use crate::roles::is_utility_helper_name;
use crate::roles::{is_thin_delegation_method, is_thin_wrapper_export};
use crate::types::MethodRecord;

pub(crate) fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

pub(crate) fn is_skippable_role(role: FileRole) -> bool {
    matches!(
        role,
        FileRole::Test
            | FileRole::Example
            | FileRole::Script
            | FileRole::Fixture
            | FileRole::Docs
            | FileRole::Generated
            | FileRole::AdapterIntegration
    )
}

pub(crate) fn is_comparable_method(method: &MethodRecord, role: FileRole) -> bool {
    !is_skippable_role(role)
        && method.loc >= 4
        && !is_utility_helper_name(&method.name)
        && !is_thin_wrapper_export(method)
        && !is_thin_delegation_method(method)
        && !is_protocol_stub_method(method)
}
