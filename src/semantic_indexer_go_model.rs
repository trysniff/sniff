use super::census::{Inputs, Journal, ModelPart, Role};
use super::go_model_commands::{
    ModelRuntime, inventory_arguments, model_failure, module_root, validate_model_output,
};
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
    let journal = Journal::open(context, spec, &installed)?;
    let root = match context
        .recovery
        .prepare_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))
    {
        Ok(root) => root,
        Err(failure) => return journal.finish(Err(failure)),
    };
    let result = discover_at(context, &scope, spec, &installed, &root, &journal).await;
    let cleanup = context
        .recovery
        .finish_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Cleanup, detail));
    journal.finish(combine_witnessed_run_and_integrity(result, cleanup).map(|(plans, _)| plans))
}

async fn discover_at(
    context: &RequiredIndexerRunContext<'_>,
    scope: &GoRepositoryScope,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    root: &Path,
    journal: &Journal,
) -> Result<
    (
        Vec<SemanticIndexerVariantPlan>,
        SemanticIndexerProcessEvidence,
    ),
    SemanticIndexerRunFailure,
> {
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
        journal,
    };
    let result = census(&runtime, scope, &runtime_before, &sdk_before, context).await;
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
    let ((census, dependencies_sha256), process) =
        combine_witnessed_run_and_integrity(result, integrity)?;
    let result = (|| {
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
    })();
    match result {
        Ok(plans) => Ok((plans, process)),
        Err(mut failure) => {
            if failure.process.is_none() {
                failure.process = Some(Box::new(process));
            }
            Err(failure)
        }
    }
}

async fn census(
    runtime: &ModelRuntime<'_>,
    scope: &GoRepositoryScope,
    executable_sha256: &str,
    sdk_sha256: &str,
    context: &RequiredIndexerRunContext<'_>,
) -> Result<((Vec<ModuleCensus>, String), SemanticIndexerProcessEvidence), SemanticIndexerRunFailure>
{
    super::go_dependencies::prepare_root(runtime.root).map_err(|detail| {
        model_failure(runtime.spec, SemanticIndexerRunPhase::Preparation, detail)
    })?;
    let preparation_inputs = Inputs::Go {
        executable_sha256: executable_sha256.to_string(),
        sdk_sha256: sdk_sha256.to_string(),
        dependencies_sha256: super::go_dependencies::identity_sha256(runtime.root).map_err(
            |detail| {
                model_failure(
                    runtime.spec,
                    SemanticIndexerRunPhase::IntegrityVerification,
                    detail,
                )
            },
        )?,
    };
    runtime.journal.begin_go_preparation(
        runtime.root,
        scope.modules.keys().cloned().collect(),
        preparation_inputs,
    )?;
    let verify = || {
        require_snapshot(context, runtime.root)?;
        context.store.verify(runtime.spec)?;
        super::go_runner::require_discovery_commitment(
            "compiler runtime",
            executable_sha256,
            &super::go_runner::runtime_identity_sha256(
                runtime.spec,
                runtime.root,
                runtime.installed,
            )?,
        )?;
        super::go_runner::require_discovery_commitment(
            "SDK inputs",
            sdk_sha256,
            &super::go_sdk::identity_sha256(runtime.spec, runtime.root, runtime.installed)?,
        )
    };
    for project in scope.modules.keys() {
        prepare_go_dependency_cache_observed(
            runtime.spec,
            runtime.root,
            runtime.installed,
            &module_root(project),
            runtime.journal,
            &verify,
        )
        .await?;
    }
    let before = runtime
        .journal
        .check_go_preparation_integrity(super::go_dependencies::identity_sha256(runtime.root))?;
    let inputs = Inputs::Go {
        executable_sha256: executable_sha256.to_string(),
        sdk_sha256: sdk_sha256.to_string(),
        dependencies_sha256: before.clone(),
    };
    runtime.journal.finish_go_preparation(&inputs)?;
    runtime.journal.bind_inputs(inputs)?;
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
    combine_witnessed_run_and_integrity(result, integrity)
        .map(|(census, process)| ((census, before), process))
}

async fn census_prepared(
    runtime: &ModelRuntime<'_>,
    scope: &GoRepositoryScope,
) -> Result<(Vec<ModuleCensus>, SemanticIndexerProcessEvidence), SemanticIndexerRunFailure> {
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
            Role::GoPlatforms,
        )
        .await?;
    let (platforms, mut process) = platform_domain(runtime.spec, platforms)?;
    runtime
        .journal
        .record_model(ModelPart::GoPlatforms(platforms.clone()))?;
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
                Role::GoSourceContexts,
            )
            .await
            .and_then(|output| source_contexts(runtime.spec, output, &source_paths, &platforms));
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
        let (expected_contexts, helper_process) =
            combine_witnessed_run_and_integrity(result, integrity)?;
        runtime
            .journal
            .record_model(ModelPart::GoSourceContexts(expected_contexts.clone()))?;
        process = helper_process;
        let mut worlds = Vec::new();
        for context in &expected_contexts {
            let environment = runtime.environment(project, context).await?;
            let arguments = inventory_arguments(project, context).map_err(|detail| {
                model_failure(runtime.spec, SemanticIndexerRunPhase::Preparation, detail)
            })?;
            let output = runtime.run(arguments, &environment, Role::GoWorld).await?;
            let (world, world_process) = validate_model_output(runtime.spec, output, |stdout| {
                parse_world(
                    runtime.root,
                    module.clone(),
                    context.clone(),
                    environment,
                    sources,
                    stdout,
                )
            })?;
            runtime
                .journal
                .record_model(ModelPart::GoWorld(Box::new(world.clone())))?;
            worlds.push(world);
            process = world_process;
        }
        census.push(ModuleCensus {
            module,
            expected_contexts,
            worlds,
        });
    }
    // The journal retains every model command; guards retain the last actual process.
    Ok((census, process))
}

fn platform_domain(
    spec: PinnedIndexer,
    output: crate::sandbox::SandboxOutput,
) -> Result<(String, SemanticIndexerProcessEvidence), SemanticIndexerRunFailure> {
    validate_model_output(spec, output, |stdout| {
        contexts(
            stdout,
            &GoConstraintTagDomain {
                custom_build_tags: Vec::new(),
                architecture_feature_tags: Vec::new(),
                standalone_source_repository_paths: Vec::new(),
            },
        )?;
        Ok(stdout.to_string())
    })
}

fn source_contexts(
    spec: PinnedIndexer,
    output: crate::sandbox::SandboxOutput,
    sources: &[String],
    platforms: &str,
) -> Result<(Vec<GoCompilerContext>, SemanticIndexerProcessEvidence), SemanticIndexerRunFailure> {
    validate_model_output(spec, output, |stdout| {
        let tags = parse_go_constraint_tags(stdout, sources, platforms)?;
        contexts(platforms, &tags)
    })
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

#[cfg(test)]
#[path = "tests/semantic_indexer_go_preparation.rs"]
mod preparation_tests;

#[cfg(test)]
#[path = "tests/semantic_indexer_go_model_evidence.rs"]
mod evidence_tests;
