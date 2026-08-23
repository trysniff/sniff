use super::intentional_boundary_source_census::{
    SOURCE_CENSUS_CONTRACT, compute_census_sha256, method_unit_id,
};
use super::{
    BoundaryGitEntryKind, INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensus,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn validate_source_census_commitment(
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundarySourceCensus,
) -> Result<(), String> {
    let expected = expected_sources(inventory)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION
        || census.census_contract != SOURCE_CENSUS_CONTRACT
        || census.repository != inventory.repository
        || census.revision != inventory.revision
        || census.inventory_sha256 != inventory.inventory_sha256
        || census.tracked_entry_count != inventory.tracked_entries.len()
        || census.source_file_count != census.source_files.len()
        || census.source_file_count != expected.len()
        || census
            .source_files
            .windows(2)
            .any(|pair| pair[0].repository_path >= pair[1].repository_path)
    {
        return Err("intentional-boundary source census commitment identity changed".to_string());
    }
    let mut method_ids = BTreeSet::new();
    let mut method_count = 0_usize;
    for file in &census.source_files {
        let Some((entry, language)) = expected.get(file.repository_path.as_str()) else {
            return Err("intentional-boundary source census changed its source set".to_string());
        };
        if entry.object_id != file.object_id
            || entry.byte_length != Some(file.byte_length)
            || file.language != language.as_str()
            || !is_lower_sha256(&file.source_sha256)
        {
            return Err("intentional-boundary source census Git identity changed".to_string());
        }
        for method in &file.methods {
            if method.start_line == 0
                || method.end_line < method.start_line
                || !is_lower_sha256(&method.source_sha256)
                || method.parser_unit_id
                    != method_unit_id(
                        &file.repository_path,
                        &method.symbol_name,
                        method.start_line,
                        method.end_line,
                        &method.source_sha256,
                    )?
                || !method_ids.insert(method.parser_unit_id.as_str())
            {
                return Err("intentional-boundary source method commitment changed".to_string());
            }
        }
        method_count = method_count
            .checked_add(file.methods.len())
            .ok_or_else(|| "intentional-boundary source method count overflowed".to_string())?;
    }
    if census.method_count != method_count || census.census_sha256 != compute_census_sha256(census)?
    {
        return Err("intentional-boundary source census commitment changed".to_string());
    }
    Ok(())
}

fn expected_sources(
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<BTreeMap<&str, (&super::IntentionalBoundaryTrackedEntry, String)>, String> {
    let mut expected = BTreeMap::new();
    for entry in &inventory.tracked_entries {
        if entry.kind == BoundaryGitEntryKind::Gitlink {
            return Err("completed source census contains a Git submodule".to_string());
        }
        let adapter = Path::new(&entry.repository_path)
            .extension()
            .and_then(|value| value.to_str())
            .and_then(crate::languages::get_adapter);
        let Some(adapter) = adapter else {
            continue;
        };
        if !matches!(
            entry.kind,
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
        ) {
            return Err("completed source census contains a non-blob source".to_string());
        }
        expected.insert(entry.repository_path.as_str(), (entry, adapter.name));
    }
    Ok(expected)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
