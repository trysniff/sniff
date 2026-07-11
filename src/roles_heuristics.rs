use super::FileRole;
use super::paths::{
    file_name, is_adapter_integration_path, is_cli_path, is_docs_path, is_entrypoint_path,
    is_example_path, is_fixture_path, is_generated_path, is_script_path,
    is_serverless_function_entrypoint, is_test_path, normalize_path,
};

fn is_top_level_src_file(normalized: &str) -> bool {
    normalized
        .rsplit_once("/src/")
        .map(|(_, rest)| !rest.contains('/'))
        .or_else(|| {
            normalized
                .strip_prefix("src/")
                .map(|rest| !rest.contains('/'))
        })
        .unwrap_or(false)
}

pub fn heuristic_file_role(file_path: &str) -> Option<FileRole> {
    let normalized = normalize_path(file_path);
    let name = file_name(&normalized);

    if is_example_path(&normalized) {
        return Some(FileRole::Example);
    } else if is_fixture_path(&normalized) {
        return Some(FileRole::Fixture);
    } else if is_script_path(&normalized) {
        return Some(FileRole::Script);
    } else if is_test_path(&normalized, name) {
        return Some(FileRole::Test);
    } else if is_docs_path(&normalized) {
        return Some(FileRole::Docs);
    } else if is_generated_path(&normalized, name) {
        return Some(FileRole::Generated);
    } else if is_cli_path(name)
        || is_entrypoint_path(&normalized, name)
        || is_serverless_function_entrypoint(&normalized, name)
    {
        return Some(FileRole::Entrypoint);
    } else if is_adapter_integration_path(&normalized, name) {
        return Some(FileRole::AdapterIntegration);
    } else if is_top_level_src_file(&normalized)
        || normalized.contains("/src/")
        || normalized.starts_with("src/")
        || normalized.contains('/')
    {
        return Some(FileRole::Library);
    }

    None
}
