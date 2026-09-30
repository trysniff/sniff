use crate::semantic_indexer_manifest::{IndexerInstallSource, SemanticIndexerKind, pinned_indexer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const OUTPUT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompilerOutput {
    pub(crate) schema_version: u32,
    pub(crate) typescript_version: String,
    pub(crate) worlds: Vec<CompilerWorld>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompilerWorld {
    pub(crate) root_config: Option<String>,
    pub(crate) root_source_files: Vec<String>,
    pub(crate) inferred: bool,
    pub(crate) config_closure: Vec<String>,
    pub(crate) diagnostics: Vec<Value>,
    pub(crate) projects: Vec<CompilerProject>,
    pub(crate) selected_source_files: Vec<String>,
    pub(crate) ignored_source_files: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompilerProject {
    pub(crate) config_path: Option<String>,
    pub(crate) config_reads: Vec<String>,
    pub(crate) diagnostics: Vec<Value>,
    pub(crate) effective_options: Value,
    pub(crate) references: Vec<String>,
    pub(crate) selected_source_files: Vec<String>,
}

pub(crate) fn parse_output(stdout: &[u8]) -> Result<CompilerOutput, String> {
    let output: CompilerOutput = serde_json::from_slice(stdout)
        .map_err(|error| format!("failed to parse TypeScript compiler project model: {error}"))?;
    if output.schema_version != OUTPUT_SCHEMA_VERSION
        || output.typescript_version != pinned_compiler_version()?
        || output.worlds.is_empty()
    {
        return Err("TypeScript compiler project-model identity changed".to_string());
    }
    Ok(output)
}

pub(crate) fn is_config_candidate(repository_path: &str) -> bool {
    let lower = repository_path
        .rsplit('/')
        .next()
        .unwrap_or(repository_path)
        .to_ascii_lowercase();
    lower == "tsconfig.json"
        || lower == "jsconfig.json"
        || (lower.starts_with("tsconfig.") && lower.ends_with(".json"))
        || (lower.starts_with("jsconfig.") && lower.ends_with(".json"))
}

pub(crate) fn pinned_compiler_version() -> Result<&'static str, String> {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript)?;
    let IndexerInstallSource::NpmTarballs { packages } = spec.source else {
        return Err("pinned scip-typescript installation is not an npm closure".to_string());
    };
    let mut matches = packages
        .iter()
        .filter(|package| package.name == "typescript");
    let package = matches
        .next()
        .ok_or_else(|| "pinned scip-typescript closure omitted TypeScript".to_string())?;
    if matches.next().is_some() {
        return Err("pinned scip-typescript closure repeats TypeScript".to_string());
    }
    Ok(package.version)
}
