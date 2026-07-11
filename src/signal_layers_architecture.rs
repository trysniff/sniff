use crate::config::ResolvedConfig;
use crate::report_types::StaticFlag;
use crate::roles::is_analysis_finding_support_module;
use crate::roles::is_analysis_findings_facade_module;
use crate::roles::is_parsing_or_serialization_helper_module;
use crate::roles::is_utility_helper_name;
use crate::roles::is_versioning_tag_module;
use crate::roles::{FileRole, classify_file_role};
use crate::types::{FileRecord, FindingTier};

use super::similarity;
#[path = "signal_layers_architecture_metrics.rs"]
mod metrics;

fn is_utility_surface(file: &FileRecord) -> bool {
    !file.methods.is_empty()
        && file
            .methods
            .iter()
            .all(|method| is_utility_helper_name(&method.name))
}

fn is_architecture_surface_candidate(file: &FileRecord) -> bool {
    if crate::roles::is_support_plumbing_module(&file.file_path) {
        return false;
    }
    if crate::roles::is_protocol_surface_module(file) {
        return false;
    }
    if crate::roles::is_intentional_surface_record(file)
        && !matches!(
            classify_file_role(&file.file_path),
            FileRole::AdapterIntegration
        )
    {
        return false;
    }
    if crate::roles::is_data_catalog_module(file) {
        return false;
    }
    if is_analysis_finding_support_module(&file.file_path) {
        return false;
    }
    if is_analysis_findings_facade_module(&file.file_path) {
        return false;
    }
    if is_parsing_or_serialization_helper_module(&file.file_path) {
        return false;
    }
    if is_versioning_tag_module(&file.file_path) {
        return false;
    }
    if is_utility_surface(file) {
        return false;
    }

    let role = crate::roles::classify_file_role(&file.file_path);
    !matches!(
        role,
        FileRole::Test | FileRole::Example | FileRole::Script | FileRole::Fixture
    )
}

pub(crate) fn architecture_flags(
    file_records: &[FileRecord],
    config: &ResolvedConfig,
) -> Vec<StaticFlag> {
    let mut flags = Vec::new();

    for file in file_records {
        if !is_architecture_surface_candidate(file) {
            continue;
        }
        let reasons = metrics::architecture_reasons(file, config);
        if !reasons.is_empty() {
            flags.push(similarity::make_file_flag(
                &file.file_path,
                reasons.join("; "),
                FindingTier::KindaSlop,
                "architecture",
            ));
        }
    }

    flags
}

#[cfg(test)]
#[path = "tests/signal_layers_architecture.rs"]
mod tests;
