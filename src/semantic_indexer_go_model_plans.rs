use super::go_model_output::{CompilerWorld, ContextOutcome, ModuleIdentity, query};
use super::go_model_scope::GoRepositoryScope;
use crate::compiler_go_model::{GoCompilerArchitecture, GoCompilerContext, GoCompilerQuery};
use crate::compiler_go_variants::GO_VARIANT_LIMIT;
use crate::semantic_index::{RepositoryPath, SemanticIndexerVariantPlan, SemanticVariantId};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub(super) struct ModuleCensus {
    pub(super) module: ModuleIdentity,
    pub(super) expected_contexts: Vec<GoCompilerContext>,
    pub(super) worlds: Vec<CompilerWorld>,
}

pub(super) fn plans_from_census(
    census: &[ModuleCensus],
    scope: &GoRepositoryScope,
    required: &BTreeSet<RepositoryPath>,
    repository_sha256: &str,
    runtime_sha256: &str,
    compiler_sha256: &str,
    sdk_sha256: &str,
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    for digest in [
        repository_sha256,
        runtime_sha256,
        compiler_sha256,
        sdk_sha256,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("Go project-model provenance digest is invalid".to_string());
        }
    }
    scope.require_source_owners(required)?;
    let projects = census
        .iter()
        .map(|module| module.module.project.clone())
        .collect::<BTreeSet<_>>();
    if required.is_empty()
        || projects != scope.modules.keys().cloned().collect()
        || census
            .windows(2)
            .any(|pair| pair[0].module.project >= pair[1].module.project)
    {
        return Err("Go project census omitted or repeated a module/source scope".to_string());
    }
    let census_sha256 = hash(census)?;
    let mut covered = BTreeSet::new();
    let mut plans = Vec::new();
    for module in census {
        let expected = &module.expected_contexts;
        if expected.is_empty()
            || expected.len() > GO_VARIANT_LIMIT
            || expected.windows(2).any(|pair| pair[0] >= pair[1])
            || module.worlds.len() != expected.len()
        {
            return Err(
                "Go compiler context ledger is incomplete, repeated or exceeds its strict limit"
                    .to_string(),
            );
        }
        let owned = &scope.modules[&module.module.project];
        for (world, expected) in module.worlds.iter().zip(expected) {
            if world.module != module.module || world.context != *expected {
                return Err(
                    "Go compiler context ledger changed module/context identity".to_string()
                );
            }
            validate_environment(world)?;
            let inventory = match &world.outcome {
                ContextOutcome::Rejected { diagnostics } => {
                    if diagnostics.is_empty()
                        || diagnostics.iter().any(|message| message.trim().is_empty())
                    {
                        return Err("Go rejected context omitted its compiler witness".to_string());
                    }
                    continue;
                }
                ContextOutcome::Accepted { inventory } => inventory,
            };
            let selected = inventory
                .packages
                .iter()
                .flat_map(|package| package.source_documents.iter().cloned())
                .collect::<BTreeSet<_>>();
            if !selected.is_subset(owned)
                || !inventory.ignored_documents.is_subset(owned)
                || !selected.is_disjoint(&inventory.ignored_documents)
                || !inventory.test_documents.is_subset(&selected)
            {
                return Err(
                    "Go compiler context changed its source ownership/partition".to_string()
                );
            }
            covered.extend(selected.intersection(required).cloned());
            // Unselected exact-source helpers in a partial scan have no method
            // context to index, but remain validated in the committed census.
            if let GoCompilerQuery::StandaloneSource {
                source_repository_path,
            } = &world.context.query
                && !required.contains(&RepositoryPath(source_repository_path.clone()))
            {
                continue;
            }
            let production = selected
                .difference(&inventory.test_documents)
                .filter(|path| required.contains(*path))
                .cloned()
                .collect::<BTreeSet<_>>();
            let identity = hash(&(
                "sniff-normal-go-compiler-world-v2",
                repository_sha256,
                runtime_sha256,
                compiler_sha256,
                sdk_sha256,
                &census_sha256,
                world,
            ))?;
            let plan = SemanticIndexerVariantPlan {
                identity: SemanticVariantId(identity),
                dimensions: BTreeMap::from([
                    (
                        "compiler_project".to_string(),
                        module.module.project.0.clone(),
                    ),
                    ("compiler_module".to_string(), module.module.path.clone()),
                    (
                        "compiler_context".to_string(),
                        serde_json::to_string(&world.context).map_err(|error| error.to_string())?,
                    ),
                    (
                        "source_snapshot_sha256".to_string(),
                        repository_sha256.to_string(),
                    ),
                    (
                        "project_model_runtime_sha256".to_string(),
                        runtime_sha256.to_string(),
                    ),
                    (
                        "compiler_runtime_sha256".to_string(),
                        compiler_sha256.to_string(),
                    ),
                    ("compiler_sdk_sha256".to_string(), sdk_sha256.to_string()),
                    (
                        "project_model_census_sha256".to_string(),
                        census_sha256.clone(),
                    ),
                    (
                        "discovery_scope".to_string(),
                        "isolated-modules-package-patterns-and-declared-exact-source-queries"
                            .to_string(),
                    ),
                ]),
                environment: world.environment.clone(),
                compiler_query: query(&world.context),
                compiler_project: Some(module.module.project.clone()),
                selected_documents: production.clone(),
                ignored_documents: required.difference(&production).cloned().collect(),
            };
            plan.validate()?;
            plans.push(plan);
        }
    }
    if covered != *required || plans.is_empty() {
        let missing = required.difference(&covered).take(8).collect::<Vec<_>>();
        return Err(format!(
            "Go compiler census omitted required source coverage: {missing:?}"
        ));
    }
    plans.sort_by(|left, right| left.identity.cmp(&right.identity));
    if plans
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err("Go compiler census repeated a qualified world identity".to_string());
    }
    Ok(plans)
}

pub(super) fn explicit_environment(context: &GoCompilerContext) -> BTreeMap<String, String> {
    let mut environment = offline_environment();
    environment.extend([
        ("GOOS".to_string(), context.goos.clone()),
        ("GOARCH".to_string(), context.goarch.clone()),
        (
            "CGO_ENABLED".to_string(),
            if context.cgo_enabled { "1" } else { "0" }.to_string(),
        ),
        (
            "GOFLAGS".to_string(),
            if context.build_tags.is_empty() {
                String::new()
            } else {
                format!("-tags={}", context.build_tags.join(","))
            },
        ),
    ]);
    if let GoCompilerArchitecture::Explicit {
        environment_variable,
        value,
    } = &context.architecture
    {
        environment.insert(environment_variable.clone(), value.clone());
    }
    environment
}

pub(super) fn offline_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("GOFLAGS".to_string(), String::new()),
        ("GOWORK".to_string(), "off".to_string()),
        ("GO111MODULE".to_string(), "on".to_string()),
        ("GOPROXY".to_string(), "off".to_string()),
        ("GOSUMDB".to_string(), "off".to_string()),
    ])
}

fn validate_environment(world: &CompilerWorld) -> Result<(), String> {
    let expected = explicit_environment(&world.context);
    if expected
        .iter()
        .any(|(name, value)| world.environment.get(name) != Some(value))
    {
        return Err("Go context environment changed its compiler assignment".to_string());
    }
    let mut names = expected.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(name) =
        crate::compiler_go_variants::go_architecture_environment_variable(&world.context.goarch)
    {
        names.insert(name.to_string());
    }
    if names != world.environment.keys().cloned().collect() {
        return Err("Go context environment omitted a resolved architecture default or added an unrelated variable".to_string());
    }
    Ok(())
}

fn hash<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "tests/semantic_indexer_go_model_plans.rs"]
mod tests;
