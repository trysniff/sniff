use crate::report_types::StaticFlag;
use crate::roles::{
    is_analysis_finding_support_module, is_contract_type_module, is_data_catalog_module,
    is_intentional_surface_record, is_protocol_stub_method, is_protocol_surface_module,
    is_thin_wrapper_export, is_utility_helper_name, is_wrapper_only_module,
};
use crate::types::{FileRecord, FindingTier};

fn should_skip_ref_flag(method_name: &str) -> bool {
    matches!(
        method_name,
        "new"
            | "add_file"
            | "parse_file"
            | "parse_file_symbols"
            | "adapter"
            | "visit"
            | "visit_stmt"
            | "reset_model_request_interval"
    )
}

fn has_explicit_public_api(file_record: &FileRecord) -> bool {
    let normalized = file_record.file_path.replace('\\', "/").to_lowercase();
    normalized.ends_with("/__init__.py") || file_record.source.contains("__all__")
}

fn make_ref_flag(method: &crate::types::MethodRecord, reason: String) -> StaticFlag {
    StaticFlag {
        flag_type: "method".to_string(),
        file_path: method.file_path.clone(),
        method_name: Some(method.name.clone()),
        reasons: vec![reason],
        tier: FindingTier::KindaSlop,
        gate: "ref_count".to_string(),
        loc: method.loc,
        start_line: method.start_line,
        end_line: method.end_line,
    }
}

fn should_skip_file_record(file_record: &FileRecord) -> bool {
    is_wrapper_only_module(file_record)
        || is_intentional_surface_record(file_record)
        || is_protocol_surface_module(file_record)
        || is_data_catalog_module(file_record)
        || is_contract_type_module(file_record)
        || is_analysis_finding_support_module(&file_record.file_path)
}

fn should_skip_method_record(
    file_record: &FileRecord,
    method: &crate::types::MethodRecord,
) -> bool {
    should_skip_ref_flag(&method.name)
        || is_utility_helper_name(&method.name)
        || is_protocol_stub_method(method)
        || is_thin_wrapper_export(method)
        || is_intentional_surface_record(file_record)
        || is_data_catalog_module(file_record)
        || is_contract_type_module(file_record)
        || is_analysis_finding_support_module(&file_record.file_path)
}

fn ref_flag_reason(method: &crate::types::MethodRecord) -> Option<String> {
    if method.real_ref_count == 0 && method.is_exported {
        return Some("orphaned export (never referenced)".to_string());
    }

    if (method.real_ref_count == 1 || method.real_ref_count == 2)
        && method.is_exported
        && method.loc >= 5
    {
        return Some(format!(
            "overbuilt helper (only {} references)",
            method.real_ref_count
        ));
    }

    None
}

pub fn build_ref_count_flags(file_records: &[FileRecord]) -> Vec<StaticFlag> {
    file_records
        .iter()
        .filter(|file_record| !should_skip_file_record(file_record))
        .flat_map(|file_record| {
            file_record.methods.iter().filter_map(move |method| {
                if should_skip_method_record(file_record, method) {
                    return None;
                }

                let reason = ref_flag_reason(method)?;
                if reason == "orphaned export (never referenced)"
                    && has_explicit_public_api(file_record)
                {
                    return None;
                }

                Some(make_ref_flag(method, reason))
            })
        })
        .collect()
}
