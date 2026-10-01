//! Shared Go compiler wire types. Consumers must separately verify toolchain,
//! source-snapshot and module/source ownership; decoding is not that proof.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GoCompilerQuery {
    ModulePackages,
    StandaloneSource { source_repository_path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GoCompilerArchitecture {
    Default,
    Explicit {
        environment_variable: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoCompilerContext {
    pub(crate) goos: String,
    pub(crate) goarch: String,
    pub(crate) cgo_enabled: bool,
    pub(crate) build_tags: Vec<String>,
    pub(crate) architecture: GoCompilerArchitecture,
    pub(crate) query: GoCompilerQuery,
}

pub(crate) const GO_LIST_COMMAND_CONTRACT: &str = "go-mod-download-then-offline-list-module-identity-e-json-find-mod-readonly-buildvcs-off-valid-exact-equivalent-source-fact-variants-v8";

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct GoListPackage {
    #[serde(rename = "Dir")]
    pub(crate) dir: String,
    #[serde(rename = "ImportPath")]
    pub(crate) import_path: String,
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(default, rename = "GoFiles")]
    pub(crate) go_files: Vec<String>,
    #[serde(default, rename = "CgoFiles")]
    pub(crate) cgo_files: Vec<String>,
    #[serde(default, rename = "IgnoredGoFiles")]
    pub(crate) ignored_go_files: Vec<String>,
    #[serde(rename = "Module")]
    pub(crate) module: Option<GoListModule>,
    #[serde(default, rename = "Incomplete")]
    pub(crate) incomplete: bool,
    #[serde(rename = "Error")]
    pub(crate) error: Option<GoListError>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct GoListModule {
    #[serde(rename = "Path")]
    pub(crate) path: String,
    #[serde(default, rename = "Version")]
    pub(crate) version: String,
    #[serde(rename = "Dir")]
    pub(crate) dir: String,
    #[serde(rename = "GoMod")]
    pub(crate) go_mod: String,
    #[serde(default, rename = "Main")]
    pub(crate) main: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct GoListError {
    #[serde(rename = "Err")]
    pub(crate) message: String,
}

pub(crate) fn parse_go_list_packages(
    stdout: &[u8],
) -> impl Iterator<Item = Result<GoListPackage, String>> + '_ {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<GoListPackage>()
        .map(|package| {
            package.map_err(|error| format!("failed to parse concatenated go list JSON: {error}"))
        })
}

pub(crate) fn canonical_go_list_projection(stdout: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut packages = parse_go_list_packages(stdout.as_bytes())
        .map(|package| {
            package.and_then(|package| {
                serde_json::to_vec(&package)
                    .map_err(|error| format!("failed to normalize go list JSON: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    packages.sort();
    Ok(packages)
}

#[cfg(test)]
#[path = "tests/compiler_go_model.rs"]
mod tests;
