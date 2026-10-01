use super::go_shards::{
    GoPackageInventory, go_package_relative_directory, parse_go_package_inventory,
};
use crate::compiler_go_model::{GoCompilerContext, GoCompilerQuery, GoListError, GoListModule};
use crate::semantic_index::{RepositoryPath, SemanticIndexerCompilerQuery};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ModuleIdentity {
    pub(super) path: String,
    pub(super) project: RepositoryPath,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum ContextOutcome {
    Accepted { inventory: GoPackageInventory },
    Rejected { diagnostics: Vec<String> },
}

#[derive(Debug, Serialize)]
pub(super) struct CompilerWorld {
    pub(super) module: ModuleIdentity,
    pub(super) context: GoCompilerContext,
    pub(super) environment: BTreeMap<String, String>,
    pub(super) outcome: ContextOutcome,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct PackageRecord {
    #[serde(default)]
    dir: String,
    #[serde(default)]
    import_path: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    go_files: Vec<String>,
    #[serde(default)]
    cgo_files: Vec<String>,
    #[serde(default)]
    test_go_files: Vec<String>,
    #[serde(default)]
    x_test_go_files: Vec<String>,
    #[serde(default)]
    ignored_go_files: Vec<String>,
    module: Option<GoListModule>,
    #[serde(default)]
    incomplete: bool,
    error: Option<GoListError>,
}

pub(super) fn module_identity(
    root: &Path,
    project: &RepositoryPath,
    raw: &GoListModule,
) -> Result<ModuleIdentity, String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let directory = go_package_relative_directory(&root, &raw.dir)?;
    let manifest = go_package_relative_directory(&root, &raw.go_mod)?;
    let expected_directory = Path::new(&project.0).parent().unwrap_or(Path::new(""));
    if !raw.main
        || !raw.version.is_empty()
        || raw.path.is_empty()
        || raw.path.trim() != raw.path
        || raw.path.chars().any(char::is_whitespace)
        || directory != expected_directory
        || manifest != Path::new(&project.0)
    {
        return Err("Go compiler module identity changed its exact manifest ownership".to_string());
    }
    Ok(ModuleIdentity {
        path: raw.path.clone(),
        project: project.clone(),
    })
}

pub(super) fn query(context: &GoCompilerContext) -> SemanticIndexerCompilerQuery {
    match &context.query {
        GoCompilerQuery::ModulePackages => SemanticIndexerCompilerQuery::ProjectPackages,
        GoCompilerQuery::StandaloneSource {
            source_repository_path,
        } => SemanticIndexerCompilerQuery::ExactSource {
            source_document: RepositoryPath(source_repository_path.clone()),
        },
    }
}

pub(super) fn parse_world(
    root: &Path,
    module: ModuleIdentity,
    context: GoCompilerContext,
    environment: BTreeMap<String, String>,
    owned: &BTreeSet<RepositoryPath>,
    stdout: &str,
) -> Result<CompilerWorld, String> {
    let mut diagnostics = Vec::new();
    // Decode every object, including the tail of rejected output. A malformed
    // transport is not a compiler's negative context-selection witness.
    let compiler_query = query(&context);
    let module_root = super::go_model_commands::module_root(&module.project);
    let stream = serde_json::Deserializer::from_str(stdout).into_iter::<PackageRecord>();
    let mut package_count = 0;
    let mut import_paths = BTreeSet::new();
    let mut source_records = String::new();
    for package in stream {
        let package =
            package.map_err(|error| format!("Go compiler package stream is invalid: {error}"))?;
        package_count += 1;
        if !package.import_path.is_empty() && !import_paths.insert(package.import_path.clone()) {
            return Err("Go compiler stream repeats a package import identity".to_string());
        }
        let mut source_names = BTreeSet::new();
        for name in package
            .go_files
            .iter()
            .chain(&package.cgo_files)
            .chain(&package.test_go_files)
            .chain(&package.x_test_go_files)
            .chain(&package.ignored_go_files)
        {
            if !source_names.insert(name) {
                return Err("Go compiler package repeats a source selection fact".to_string());
            }
        }
        validate_package(root, &module, &compiler_query, &package)?;
        let has_sources = !package.go_files.is_empty()
            || !package.cgo_files.is_empty()
            || !package.test_go_files.is_empty()
            || !package.x_test_go_files.is_empty()
            || !package.ignored_go_files.is_empty();
        if has_sources {
            let record = serde_json::to_string(&package).map_err(|error| error.to_string())?;
            let inventory =
                parse_go_package_inventory(root, &module_root, &compiler_query, &record)?;
            require_owned_inventory(&inventory, owned)?;
            source_records.push_str(&record);
        }
        if package.incomplete || package.error.is_some() {
            let message = package
                .error
                .as_ref()
                .map_or("package marked incomplete", |error| error.message.as_str());
            diagnostics.push(format!(
                "{}: {}",
                package.import_path,
                normalize_diagnostic(root, message)
            ));
        } else if !has_sources {
            return Err("Go complete package omitted its source selection facts".to_string());
        }
    }
    if matches!(
        compiler_query,
        SemanticIndexerCompilerQuery::ExactSource { .. }
    ) && package_count != 1
    {
        return Err("Go exact-source context did not return one compiler package".to_string());
    }
    if !source_records.is_empty() {
        let inventory =
            parse_go_package_inventory(root, &module_root, &compiler_query, &source_records)?;
        require_owned_inventory(&inventory, owned)?;
    }
    if !diagnostics.is_empty() {
        diagnostics.sort();
        diagnostics.dedup();
        return Ok(CompilerWorld {
            module,
            context,
            environment,
            outcome: ContextOutcome::Rejected { diagnostics },
        });
    }
    let inventory = parse_go_package_inventory(root, &module_root, &compiler_query, stdout)?;
    require_owned_inventory(&inventory, owned)?;
    Ok(CompilerWorld {
        module,
        context,
        environment,
        outcome: ContextOutcome::Accepted { inventory },
    })
}

fn validate_package(
    root: &Path,
    module: &ModuleIdentity,
    compiler_query: &SemanticIndexerCompilerQuery,
    package: &PackageRecord,
) -> Result<(), String> {
    let rejected = package.incomplete || package.error.is_some();
    if !rejected
        && (package.name.trim().is_empty()
            || package.dir.is_empty()
            || package.import_path.is_empty())
    {
        return Err("Go complete package omitted its compiler identity".to_string());
    }
    let canonical_root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let directory = Path::new(&module.project.0)
        .parent()
        .unwrap_or(Path::new(""));
    match compiler_query {
        SemanticIndexerCompilerQuery::ProjectPackages => {
            if let Some(package_module) = package.module.as_ref() {
                if module_identity(root, &module.project, package_module)? != *module {
                    return Err("Go compiler package belongs to a different module".to_string());
                }
            } else if !rejected {
                return Err("Go compiler package omitted module ownership".to_string());
            }
            if package.dir.is_empty() {
                if !package.import_path.is_empty()
                    && package.import_path != module.path
                    && !package
                        .import_path
                        .starts_with(&format!("{}/", module.path))
                {
                    return Err(
                        "Go rejected package provided a foreign import identity".to_string()
                    );
                }
                return Ok(());
            }
            let package_directory = go_package_relative_directory(&canonical_root, &package.dir)?;
            let suffix = package_directory
                .strip_prefix(directory)
                .map_err(|_| "Go package escaped its module directory".to_string())?;
            let suffix = suffix.to_string_lossy().replace('\\', "/");
            let expected_import = if suffix.is_empty() {
                module.path.clone()
            } else {
                format!("{}/{suffix}", module.path)
            };
            if !package.import_path.is_empty() && package.import_path != expected_import {
                return Err(
                    "Go package import identity disagrees with its compiler directory".to_string(),
                );
            }
        }
        SemanticIndexerCompilerQuery::ExactSource { .. } => {
            if package.module.is_some()
                || (!package.name.is_empty() && package.name != "main")
                || (!package.import_path.is_empty()
                    && package.import_path != "command-line-arguments")
                || !package.cgo_files.is_empty()
            {
                return Err("Go exact-source context changed its compiler shape".to_string());
            }
        }
        SemanticIndexerCompilerQuery::ExactSources { .. } => {
            unreachable!("Go queries never contain TypeScript source sets")
        }
    }
    Ok(())
}

fn require_owned_inventory(
    inventory: &GoPackageInventory,
    owned: &BTreeSet<RepositoryPath>,
) -> Result<(), String> {
    let selected = inventory
        .packages
        .iter()
        .flat_map(|package| package.source_documents.iter().cloned())
        .collect::<BTreeSet<_>>();
    if !selected.is_subset(owned) || !inventory.ignored_documents.is_subset(owned) {
        return Err("Go compiler inventory selected sources owned by another module or unsupported package scope".to_string());
    }
    Ok(())
}

fn normalize_diagnostic(root: &Path, raw: &str) -> String {
    let mut result = raw.replace('\\', "/");
    for spelling in [
        root.to_string_lossy().replace('\\', "/"),
        root.to_string_lossy()
            .trim_start_matches("\\\\?\\")
            .replace('\\', "/"),
        "/workspace".to_string(),
    ] {
        result = result.replace(&spelling, "<repository>");
    }
    result
}
