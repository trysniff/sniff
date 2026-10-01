use super::go_model_commands::{ModelRuntime, inventory_arguments, model_failure, module_root};
use super::go_model_output::parse_world;
use super::go_model_plans::{
    CompilerInputBindings, ModuleCensus, offline_environment, plans_from_census,
};
use super::go_model_scope::GoRepositoryScope;
use super::*;
use crate::compiler_go_model::{GoCompilerContext, GoCompilerQuery};
use crate::compiler_go_variants::{
    GO_VARIANT_LIMIT, GoConstraintTagDomain, go_project_model_pipeline_identity,
    parse_go_constraint_tags, parse_go_dist_variants, stage_go_constraint_invocation,
};

pub(super) async fn discover(
    context: &RequiredIndexerRunContext<'_>,
) -> Result<Vec<SemanticIndexerVariantPlan>, SemanticIndexerRunFailure> {
    let scope = super::go_model_scope::require_normal_source_scope(context.root, context.files)?;
    let spec = pinned_indexer(SemanticIndexerKind::Go).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::InstallationVerification,
            Some(SemanticIndexerKind::Go),
            detail,
        )
    })?;
    let installed = context.store.verify(spec).map_err(|detail| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::InstallationVerification,
            detail,
        )
    })?;
    let root = context
        .recovery
        .prepare_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    let result = discover_at(context, &scope, spec, &installed, &root).await;
    let cleanup = context
        .recovery
        .finish_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Cleanup, detail));
    combine_typed_run_and_integrity(result, cleanup)
}

async fn discover_at(
    context: &RequiredIndexerRunContext<'_>,
    scope: &GoRepositoryScope,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    root: &Path,
) -> Result<Vec<SemanticIndexerVariantPlan>, SemanticIndexerRunFailure> {
    repository_snapshot::stage_repository_snapshot(context.root, root)
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    require_snapshot(context, root).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    let runtime_before =
        super::go_runner::runtime_identity_sha256(spec, root, installed).map_err(|detail| {
            model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
        })?;
    let sdk_before = super::go_sdk::identity_sha256(spec, root, installed).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    let runtime = ModelRuntime {
        spec,
        root,
        installed,
    };
    let result = census(&runtime, scope).await;
    let integrity = (|| {
        require_snapshot(context, root)?;
        context.store.verify(spec)?;
        if super::go_runner::runtime_identity_sha256(spec, root, installed)? != runtime_before {
            return Err("Go compiler runtime changed during project discovery".to_string());
        }
        if super::go_sdk::identity_sha256(spec, root, installed)? != sdk_before {
            return Err("Go SDK inputs changed during project discovery".to_string());
        }
        Ok(())
    })()
    .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail));
    let (census, dependencies_sha256) = combine_typed_run_and_integrity(result, integrity)?;
    let runtime_sha256 = go_project_model_pipeline_identity(
        &runtime_before,
        "sniff-normal-go-all-owned-modules-dependency-preparation-v2",
    )
    .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    let required = files_for_indexer(context.files, spec.kind)
        .iter()
        .map(|file| repository_relative_path(context.root, Path::new(&file.file_path)))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|detail| {
            model_failure(spec, SemanticIndexerRunPhase::RepositoryValidation, detail)
        })?;
    plans_from_census(
        &census,
        scope,
        &required,
        context.repository_content_sha256,
        &CompilerInputBindings {
            project_model: &runtime_sha256,
            executable: &runtime_before,
            sdk: &sdk_before,
            dependencies: &dependencies_sha256,
        },
    )
    .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::OutputValidation, detail))
}

async fn census(
    runtime: &ModelRuntime<'_>,
    scope: &GoRepositoryScope,
) -> Result<(Vec<ModuleCensus>, String), SemanticIndexerRunFailure> {
    super::go_dependencies::prepare_root(runtime.root).map_err(|detail| {
        model_failure(runtime.spec, SemanticIndexerRunPhase::Preparation, detail)
    })?;
    for project in scope.modules.keys() {
        prepare_go_dependency_cache(
            runtime.spec,
            runtime.root,
            runtime.installed,
            &module_root(project),
        )
        .await?;
    }
    let before = super::go_dependencies::identity_sha256(runtime.root).map_err(|detail| {
        model_failure(
            runtime.spec,
            SemanticIndexerRunPhase::IntegrityVerification,
            detail,
        )
    })?;
    let result = census_prepared(runtime, scope).await;
    let integrity = super::go_dependencies::identity_sha256(runtime.root)
        .and_then(|after| {
            super::go_runner::require_discovery_commitment("dependency inputs", &before, &after)
        })
        .map_err(|detail| {
            model_failure(
                runtime.spec,
                SemanticIndexerRunPhase::IntegrityVerification,
                detail,
            )
        });
    combine_typed_run_and_integrity(result, integrity).map(|census| (census, before))
}

async fn census_prepared(
    runtime: &ModelRuntime<'_>,
    scope: &GoRepositoryScope,
) -> Result<Vec<ModuleCensus>, SemanticIndexerRunFailure> {
    let mut census = Vec::new();
    let platforms = runtime
        .run(
            vec![
                "tool".to_string(),
                "dist".to_string(),
                "list".to_string(),
                "-json".to_string(),
            ],
            &offline_environment(),
            "Go compiler platform domain",
        )
        .await?;
    for (index, (project, sources)) in scope.modules.iter().enumerate() {
        let module = runtime.module(project).await?;
        let directory = runtime
            .root
            .join(INDEXER_TEMP_DIR)
            .join(format!("go-model-{index}"));
        fs::create_dir(&directory).map_err(|error| {
            model_failure(
                runtime.spec,
                SemanticIndexerRunPhase::Preparation,
                error.to_string(),
            )
        })?;
        let source_paths = sources
            .iter()
            .map(|path| path.0.clone())
            .collect::<Vec<_>>();
        let invocation = stage_go_constraint_invocation(runtime.root, &directory, &source_paths)
            .map_err(|detail| {
                model_failure(runtime.spec, SemanticIndexerRunPhase::Preparation, detail)
            })?;
        let files = [
            runtime.root.join(&invocation.helper_repository_path),
            runtime.root.join(&invocation.request_repository_path),
        ];
        let identities = runtime_file_identities(&files).map_err(|detail| {
            model_failure(
                runtime.spec,
                SemanticIndexerRunPhase::IntegrityVerification,
                detail,
            )
        })?;
        let mut helper_environment = offline_environment();
        helper_environment.insert("GO111MODULE".to_string(), "off".to_string());
        let result = runtime
            .run(
                vec![
                    "run".to_string(),
                    invocation.helper_repository_path,
                    invocation.request_repository_path,
                ],
                &helper_environment,
                "Go compiler source constraint facts",
            )
            .await;
        let integrity = runtime_file_identities(&files)
            .and_then(|after| {
                verify_runtime_identities_unchanged(
                    "Go source constraint helper",
                    &identities,
                    &after,
                )
            })
            .map_err(|detail| {
                model_failure(
                    runtime.spec,
                    SemanticIndexerRunPhase::IntegrityVerification,
                    detail,
                )
            });
        let output = combine_typed_run_and_integrity(result, integrity)?;
        let tags = parse_go_constraint_tags(&output.stdout, &source_paths, &platforms.stdout)
            .map_err(|detail| {
                model_failure(
                    runtime.spec,
                    SemanticIndexerRunPhase::OutputValidation,
                    detail,
                )
            })?;
        let expected_contexts = contexts(&platforms.stdout, &tags).map_err(|detail| {
            model_failure(
                runtime.spec,
                SemanticIndexerRunPhase::OutputValidation,
                detail,
            )
        })?;
        let mut worlds = Vec::new();
        for context in &expected_contexts {
            let environment = runtime.environment(project, context).await?;
            let arguments = inventory_arguments(project, context).map_err(|detail| {
                model_failure(runtime.spec, SemanticIndexerRunPhase::Preparation, detail)
            })?;
            let output = runtime
                .run(arguments, &environment, "Go compiler package selection")
                .await?;
            worlds.push(
                parse_world(
                    runtime.root,
                    module.clone(),
                    context.clone(),
                    environment,
                    sources,
                    &output.stdout,
                )
                .map_err(|detail| {
                    model_failure(
                        runtime.spec,
                        SemanticIndexerRunPhase::OutputValidation,
                        detail,
                    )
                })?,
            );
        }
        census.push(ModuleCensus {
            module,
            expected_contexts,
            worlds,
        });
    }
    Ok(census)
}

fn contexts(
    platforms: &str,
    tags: &GoConstraintTagDomain,
) -> Result<Vec<GoCompilerContext>, String> {
    let base = parse_go_dist_variants(platforms, tags)?;
    let count = base
        .len()
        .checked_mul(tags.standalone_source_repository_paths.len() + 1)
        .ok_or_else(|| "Go exact-source context domain is unbounded".to_string())?;
    if count > GO_VARIANT_LIMIT {
        return Err(
            "Go combined package/exact-source context domain exceeds its strict limit".to_string(),
        );
    }
    let mut contexts = Vec::with_capacity(count);
    for context in base {
        for source in &tags.standalone_source_repository_paths {
            let mut exact = context.clone();
            exact.query = GoCompilerQuery::StandaloneSource {
                source_repository_path: source.clone(),
            };
            contexts.push(exact);
        }
        contexts.push(context);
    }
    contexts.sort();
    if contexts.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Go compiler context domain repeated an exact query".to_string());
    }
    Ok(contexts)
}

fn require_snapshot(context: &RequiredIndexerRunContext<'_>, root: &Path) -> Result<(), String> {
    source_integrity_digest_at(context.root, root, context.files)?;
    for root in [context.root, root] {
        if repository_snapshot::repository_content_digest(root)?
            != context.repository_content_sha256
        {
            return Err(
                "Go project-model repository differs from its parsed scan snapshot".to_string(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/semantic_indexer_go_model.rs"]
mod tests;
