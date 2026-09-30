use super::typescript_model_output::{CompilerWorld, parse_output};
use crate::semantic_index::{
    RepositoryPath, SemanticIndexerCompilerQuery, SemanticIndexerVariantPlan, SemanticVariantId,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn plans_from_output(
    stdout: &[u8],
    configs: &[String],
    sources: &[String],
    repository_sha256: &str,
    runtime_sha256: &str,
    mut require_file: impl FnMut(&str) -> Result<(), String>,
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    for digest in [repository_sha256, runtime_sha256] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("TypeScript project-model provenance digest is invalid".to_string());
        }
    }
    let required = paths(sources, "TypeScript source scope", &mut require_file)?;
    let expected_configs = paths(configs, "TypeScript configuration scope", &mut require_file)?;
    let output = parse_output(stdout)?;
    let mut covered_configs = BTreeSet::new();
    let mut covered_sources = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut plans = Vec::new();
    for world in output.worlds {
        if !roots.insert(world.root_config.clone())
            || world.inferred != world.root_config.is_none()
            || world
                .root_config
                .as_ref()
                .is_some_and(|path| !expected_configs.contains(path))
        {
            return Err("TypeScript compiler world identity changed".to_string());
        }
        let selected = validate_world(&world, &required, &mut require_file)?;
        covered_configs.extend(world.config_closure.iter().cloned());
        covered_configs.extend(
            world
                .projects
                .iter()
                .flat_map(|project| project.config_reads.iter().cloned()),
        );
        covered_sources.extend(selected.iter().cloned());
        // A discovered project unrelated to a partial scan is still validated,
        // but has no method context to index for that scan.
        if selected.is_empty() {
            continue;
        }
        let identity = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    "sniff-normal-typescript-project-world-v1",
                    repository_sha256,
                    runtime_sha256,
                    &output.typescript_version,
                    &world,
                ))
                .map_err(|error| format!("failed to commit TypeScript compiler world: {error}"))?
            )
        );
        let plan = SemanticIndexerVariantPlan {
            identity: SemanticVariantId(identity),
            dimensions: BTreeMap::from([
                (
                    "compiler_version".to_string(),
                    output.typescript_version.clone(),
                ),
                (
                    "root_config".to_string(),
                    world
                        .root_config
                        .clone()
                        .unwrap_or_else(|| "<inferred>".to_string()),
                ),
                (
                    "discovery_scope".to_string(),
                    "conventional-config-roots-and-compiler-reference-closure".to_string(),
                ),
                (
                    "source_snapshot_sha256".to_string(),
                    repository_sha256.to_string(),
                ),
                (
                    "project_model_runtime_sha256".to_string(),
                    runtime_sha256.to_string(),
                ),
            ]),
            environment: BTreeMap::new(),
            compiler_query: if world.inferred {
                SemanticIndexerCompilerQuery::ExactSources {
                    source_documents: world
                        .root_source_files
                        .iter()
                        .cloned()
                        .map(RepositoryPath)
                        .collect(),
                }
            } else {
                SemanticIndexerCompilerQuery::ProjectPackages
            },
            compiler_project: world.root_config.map(RepositoryPath),
            selected_documents: selected.into_iter().map(RepositoryPath).collect(),
            ignored_documents: world
                .ignored_source_files
                .into_iter()
                .map(RepositoryPath)
                .collect(),
        };
        plan.validate()?;
        plans.push(plan);
    }
    if covered_sources != required
        || !expected_configs.is_subset(&covered_configs)
        || plans.is_empty()
    {
        return Err(
            "TypeScript compiler project census omitted a source or discovered configuration"
                .to_string(),
        );
    }
    plans.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(plans)
}

fn validate_world(
    world: &CompilerWorld,
    required: &BTreeSet<String>,
    require_file: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<BTreeSet<String>, String> {
    if !world.diagnostics.is_empty() || world.projects.is_empty() {
        return Err(
            "TypeScript compiler world has configuration diagnostics or no projects".to_string(),
        );
    }
    let closure = paths(
        &world.config_closure,
        "TypeScript config closure",
        require_file,
    )?;
    let roots = paths(
        &world.root_source_files,
        "TypeScript root sources",
        require_file,
    )?;
    let selected = paths(
        &world.selected_source_files,
        "TypeScript selected sources",
        require_file,
    )?;
    let ignored = paths(
        &world.ignored_source_files,
        "TypeScript ignored sources",
        require_file,
    )?;
    if !selected.is_disjoint(&ignored)
        || selected.union(&ignored).cloned().collect::<BTreeSet<_>>() != *required
        || roots != selected
    {
        return Err("TypeScript compiler world changed its source partition".to_string());
    }
    if world.inferred && (world.projects.len() != 1 || !closure.is_empty()) {
        return Err("TypeScript inferred compiler world contains configured projects".to_string());
    }
    let mut projects = BTreeMap::new();
    let mut project_sources = BTreeSet::new();
    for project in &world.projects {
        if world.inferred != project.config_path.is_none()
            || !project.diagnostics.is_empty()
            || !project.effective_options.is_object()
            || (world.inferred
                && (!project.config_reads.is_empty() || !project.references.is_empty()))
        {
            return Err("TypeScript compiler project identity or options changed".to_string());
        }
        let reads = paths(
            &project.config_reads,
            "TypeScript config reads",
            require_file,
        )?;
        let references = paths(
            &project.references,
            "TypeScript project references",
            require_file,
        )?;
        let sources = paths(
            &project.selected_source_files,
            "TypeScript project sources",
            require_file,
        )?;
        if !sources.is_subset(&selected) {
            return Err(
                "TypeScript project selected a source outside its compiler world".to_string(),
            );
        }
        project_sources.extend(sources);
        if let Some(config) = &project.config_path {
            require_file(config)?;
            if !reads.contains(config)
                || !closure.contains(config)
                || projects.insert(config.clone(), references).is_some()
            {
                return Err(
                    "TypeScript compiler project changed its configuration identity".to_string(),
                );
            }
        }
    }
    if project_sources != selected || projects.keys().cloned().collect::<BTreeSet<_>>() != closure {
        return Err(
            "TypeScript compiler world changed its project closure or source union".to_string(),
        );
    }
    if let Some(root) = &world.root_config {
        let mut pending = vec![root.clone()];
        let mut reached = BTreeSet::new();
        while let Some(config) = pending.pop() {
            if reached.insert(config.clone()) {
                pending.extend(
                    projects
                        .get(&config)
                        .ok_or_else(|| {
                            "TypeScript compiler omitted a referenced project".to_string()
                        })?
                        .iter()
                        .cloned(),
                );
            }
        }
        if reached != closure {
            return Err("TypeScript compiler emitted a disconnected project closure".to_string());
        }
    }
    Ok(selected)
}

fn paths(
    values: &[String],
    label: &str,
    require_file: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<BTreeSet<String>, String> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} is repeated or not canonical"));
    }
    for path in values {
        if path.is_empty()
            || path.starts_with('/')
            || path.contains(['\\', '\0', ':'])
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(format!("{label} contains a noncanonical repository path"));
        }
        require_file(path)?;
    }
    Ok(values.iter().cloned().collect())
}

#[cfg(test)]
#[path = "tests/semantic_indexer_typescript_model_plans.rs"]
mod tests;
