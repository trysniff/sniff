use super::super::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelGoArchitecture, IntentionalBoundaryProjectModelGoQuery,
    IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelVariant,
};
use crate::semantic_index::{
    RepositoryPath, SemanticIndexerCompilerQuery, SemanticIndexerVariantPlan, SemanticVariantId,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn go_semantic_variant_plans(
    model: &IntentionalBoundaryProjectModelCensus,
    semantic_documents: &BTreeSet<RepositoryPath>,
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    if model
        .executions
        .iter()
        .any(|execution| execution.provider != IntentionalBoundaryProjectModelProvider::GoList)
    {
        return Err("historical-v2 Go variant ledger mixed project-model providers".to_string());
    }
    let semantic_modules = semantic_go_module_documents(model, semantic_documents)?;
    let mut plans = Vec::new();
    let mut executions = BTreeSet::new();
    let mut contexts = BTreeSet::new();
    for execution in &model.executions {
        if !executions.insert(execution.execution_id.as_str()) {
            return Err(
                "historical-v2 Go variant ledger repeats an execution identity".to_string(),
            );
        }
        let targets = model
            .targets
            .iter()
            .filter(|target| target.execution_id == execution.execution_id)
            .collect::<Vec<_>>();
        if targets.len() != execution.target_count {
            return Err(format!(
                "historical-v2 Go variant {} changed its package count",
                execution.execution_id
            ));
        }
        let selected_documents = targets
            .iter()
            .flat_map(|target| target.source_repository_paths.iter())
            .map(|path| RepositoryPath(path.clone()))
            .filter(|path| semantic_documents.contains(path))
            .collect::<BTreeSet<_>>();
        let ignored_documents = semantic_documents
            .difference(&selected_documents)
            .cloned()
            .collect::<BTreeSet<_>>();
        let IntentionalBoundaryProjectModelVariant::Go { query, .. } = &execution.variant else {
            return Err("historical-v2 Go variant ledger contains an untyped variant".to_string());
        };
        // go list equivalence proves source selection, not equivalent type/API facts.
        // Each context must run its own semantic indexer, even with identical sources.
        for variant in std::iter::once(&execution.variant).chain(&execution.equivalent_variants) {
            let IntentionalBoundaryProjectModelVariant::Go {
                query: variant_query,
                ..
            } = variant
            else {
                return Err(
                    "historical-v2 Go source-equivalence ledger contains an untyped variant"
                        .to_string(),
                );
            };
            if variant_query != query {
                return Err(
                    "historical-v2 Go source-equivalence ledger changed its compiler query"
                        .to_string(),
                );
            }
            if !contexts.insert((&execution.invocation_anchor_repository_path, variant)) {
                return Err(
                    "historical-v2 Go variant ledger repeats a compiler context".to_string()
                );
            }
            let plan = go_semantic_variant_plan(
                execution,
                variant,
                selected_documents.clone(),
                ignored_documents.clone(),
            )?;
            if semantic_modules.contains_key(&execution.invocation_anchor_repository_path) {
                plans.push(plan);
            }
        }
    }
    validate_go_source_coverage(&plans, &semantic_modules)?;
    plans.sort_by(|left, right| left.identity.cmp(&right.identity));
    if plans
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err("historical-v2 Go compiler worlds repeat an identity".to_string());
    }
    Ok(plans)
}

fn go_semantic_variant_plan(
    execution: &IntentionalBoundaryProjectModelExecution,
    variant: &IntentionalBoundaryProjectModelVariant,
    selected_documents: BTreeSet<RepositoryPath>,
    ignored_documents: BTreeSet<RepositoryPath>,
) -> Result<SemanticIndexerVariantPlan, String> {
    let IntentionalBoundaryProjectModelVariant::Go {
        goos,
        goarch,
        cgo_enabled,
        build_tags,
        architecture,
        query,
    } = variant
    else {
        return Err("historical-v2 Go compiler world is untyped".to_string());
    };
    let identity = if variant == &execution.variant {
        execution.execution_id.clone()
    } else {
        format!(
            "go-source-equivalent-world-v1-{}",
            super::hash_json(&(
                "go-source-equivalent-world-v1",
                &execution.execution_id,
                variant
            ))?
        )
    };
    let architecture_dimension = match architecture {
        IntentionalBoundaryProjectModelGoArchitecture::Default => "default".to_string(),
        IntentionalBoundaryProjectModelGoArchitecture::Explicit {
            environment_variable,
            value,
        } => format!("{environment_variable}={value}"),
    };
    let (compiler_query, query_dimension) = match query {
        IntentionalBoundaryProjectModelGoQuery::ModulePackages => (
            SemanticIndexerCompilerQuery::ProjectPackages,
            "module_packages".to_string(),
        ),
        IntentionalBoundaryProjectModelGoQuery::StandaloneSource {
            source_repository_path,
        } => (
            SemanticIndexerCompilerQuery::ExactSource {
                source_document: RepositoryPath(source_repository_path.clone()),
            },
            format!("standalone_source:{source_repository_path}"),
        ),
    };
    let dimensions = BTreeMap::from([
        ("architecture".to_string(), architecture_dimension),
        (
            "build_tags".to_string(),
            serde_json::to_string(build_tags)
                .map_err(|error| format!("failed to serialize Go build tags: {error}"))?,
        ),
        ("cgo_enabled".to_string(), cgo_enabled.to_string()),
        ("goarch".to_string(), goarch.clone()),
        ("goos".to_string(), goos.clone()),
        (
            "project_model_execution_id".to_string(),
            execution.execution_id.clone(),
        ),
        ("query".to_string(), query_dimension),
    ]);
    let mut environment = BTreeMap::from([
        (
            "CGO_ENABLED".to_string(),
            if *cgo_enabled { "1" } else { "0" }.to_string(),
        ),
        ("GOARCH".to_string(), goarch.clone()),
        (
            "GOFLAGS".to_string(),
            if build_tags.is_empty() {
                String::new()
            } else {
                format!("-tags={}", build_tags.join(","))
            },
        ),
        ("GOOS".to_string(), goos.clone()),
    ]);
    if let IntentionalBoundaryProjectModelGoArchitecture::Explicit {
        environment_variable,
        value,
    } = architecture
        && environment
            .insert(environment_variable.clone(), value.clone())
            .is_some()
    {
        return Err(format!(
            "historical-v2 Go variant {} repeats environment variable {environment_variable}",
            execution.execution_id
        ));
    }
    let plan = SemanticIndexerVariantPlan {
        identity: SemanticVariantId(identity),
        dimensions,
        environment,
        compiler_query,
        compiler_project: Some(RepositoryPath(
            execution.invocation_anchor_repository_path.clone(),
        )),
        selected_documents,
        ignored_documents,
    };
    plan.validate()?;
    Ok(plan)
}

fn validate_go_source_coverage(
    plans: &[SemanticIndexerVariantPlan],
    semantic_modules: &BTreeMap<String, BTreeSet<RepositoryPath>>,
) -> Result<(), String> {
    for (project, documents) in semantic_modules {
        let candidates = plans
            .iter()
            .filter(|plan| plan.compiler_project.as_ref().map(|path| &path.0) == Some(project))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(format!(
                "historical-v2 Go module {project} has no compiler world"
            ));
        }
        let selected = candidates
            .iter()
            .flat_map(|plan| &plan.selected_documents)
            .collect::<BTreeSet<_>>();
        if let Some(document) = documents
            .iter()
            .filter(|document| !document.0.ends_with("_test.go"))
            .find(|document| !selected.contains(document))
        {
            return Err(format!(
                "historical-v2 Go module {project} has no compiler world selecting required source {}",
                document.0
            ));
        }
    }
    Ok(())
}

fn semantic_go_module_documents(
    model: &IntentionalBoundaryProjectModelCensus,
    semantic_documents: &BTreeSet<RepositoryPath>,
) -> Result<BTreeMap<String, BTreeSet<RepositoryPath>>, String> {
    let manifests = model
        .executions
        .iter()
        .map(|execution| execution.invocation_anchor_repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let module_directories = manifests
        .iter()
        .map(|manifest| Ok((*manifest, go_module_directory(manifest)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let mut selected = BTreeMap::<String, BTreeSet<RepositoryPath>>::new();
    for document in semantic_documents {
        let owner = module_directories
            .iter()
            .filter(|(_, directory)| {
                directory.is_empty() || document.0.starts_with(&format!("{directory}/"))
            })
            .max_by_key(|(_, directory)| directory.len());
        let Some((manifest, _)) = owner else {
            return Err(format!(
                "historical-v2 Go source {} has no compiler module",
                document.0
            ));
        };
        selected
            .entry((*manifest).to_string())
            .or_default()
            .insert(document.clone());
    }
    Ok(selected)
}

fn go_module_directory(manifest: &str) -> Result<&str, String> {
    if manifest == "go.mod" {
        return Ok("");
    }
    manifest.strip_suffix("/go.mod").ok_or_else(|| {
        format!("historical-v2 Go compiler project is not an exact go.mod path: {manifest}")
    })
}

pub(super) fn typescript_semantic_variant_plans(
    model: &IntentionalBoundaryProjectModelCensus,
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    let mut plans = Vec::with_capacity(model.executions.len());
    let mut identities = BTreeSet::new();
    for execution in &model.executions {
        if execution.provider != IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi {
            return Err(
                "historical-v2 TypeScript variant ledger mixed project-model providers".to_string(),
            );
        }
        let IntentionalBoundaryProjectModelVariant::TypeScript {
            root_config_repository_path,
            root_source_repository_paths,
            compiler_version,
            projects,
            selected_source_repository_paths,
            ignored_source_repository_paths,
        } = &execution.variant
        else {
            return Err(
                "historical-v2 TypeScript variant ledger contains an untyped variant".to_string(),
            );
        };
        if !identities.insert(execution.execution_id.as_str()) {
            return Err(
                "historical-v2 TypeScript variant ledger repeats an execution identity".to_string(),
            );
        }
        let target_count = model
            .targets
            .iter()
            .filter(|target| target.execution_id == execution.execution_id)
            .count();
        if target_count != execution.target_count || target_count != projects.len() {
            return Err(format!(
                "historical-v2 TypeScript variant {} changed its compiler-project count",
                execution.execution_id
            ));
        }
        let dimensions = BTreeMap::from([
            ("compiler_version".to_string(), compiler_version.clone()),
            (
                "root_config".to_string(),
                root_config_repository_path
                    .clone()
                    .unwrap_or_else(|| "<inferred>".to_string()),
            ),
        ]);
        let plan = SemanticIndexerVariantPlan {
            identity: SemanticVariantId(execution.execution_id.clone()),
            dimensions,
            environment: BTreeMap::new(),
            compiler_query: match root_config_repository_path {
                Some(_) => SemanticIndexerCompilerQuery::ProjectPackages,
                None => SemanticIndexerCompilerQuery::ExactSources {
                    source_documents: root_source_repository_paths
                        .iter()
                        .cloned()
                        .map(RepositoryPath)
                        .collect(),
                },
            },
            compiler_project: root_config_repository_path.clone().map(RepositoryPath),
            selected_documents: selected_source_repository_paths
                .iter()
                .cloned()
                .map(RepositoryPath)
                .collect(),
            ignored_documents: ignored_source_repository_paths
                .iter()
                .cloned()
                .map(RepositoryPath)
                .collect(),
        };
        plan.validate()?;
        plans.push(plan);
    }
    plans.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::release::{
        IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelTarget,
        IntentionalBoundaryProjectModelTargetStatus,
        IntentionalBoundaryProjectModelUnresolvedReason,
    };

    fn semantic_go_documents(
        model: &IntentionalBoundaryProjectModelCensus,
    ) -> BTreeSet<RepositoryPath> {
        model
            .targets
            .iter()
            .flat_map(|target| target.source_repository_paths.iter())
            .cloned()
            .map(RepositoryPath)
            .collect()
    }

    #[test]
    fn exact_go_project_model_variant_becomes_a_semantic_execution_plan() {
        let model = go_model();
        let semantic_documents = semantic_go_documents(&model);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].identity.0, "go-linux-amd64");
        assert_eq!(plans[0].environment["GOOS"], "linux");
        assert_eq!(plans[0].environment["GOAMD64"], "v3");
        assert_eq!(plans[0].environment["GOFLAGS"], "-tags=enterprise");
        assert_eq!(
            plans[0].compiler_project,
            Some(RepositoryPath("go.mod".to_string()))
        );
        assert!(
            plans[0]
                .selected_documents
                .contains(&RepositoryPath("api/api_amd64.go".to_string()))
        );
    }

    #[test]
    fn go_semantic_plan_excludes_nonrequired_compiler_documents() {
        let mut model = go_model();
        model.targets[0]
            .source_repository_paths
            .push("api/zz_generated.deepcopy.go".to_string());
        model.targets[0]
            .ignored_source_repository_paths
            .push("api/zz_generated.windows.go".to_string());
        let semantic_documents = BTreeSet::from([RepositoryPath("api/api_amd64.go".to_string())]);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].selected_documents,
            BTreeSet::from([RepositoryPath("api/api_amd64.go".to_string())])
        );
        assert!(plans[0].ignored_documents.is_empty());
    }

    #[test]
    fn source_selected_by_one_go_execution_is_ignored_by_an_empty_execution() {
        let mut model = go_model();
        let mut empty_execution = model.executions[0].clone();
        empty_execution.execution_id = "go-windows-arm64-empty".to_string();
        empty_execution.variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "windows".to_string(),
            goarch: "arm64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        empty_execution.target_count = 0;
        model.executions.push(empty_execution);
        let semantic_documents = semantic_go_documents(&model);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();
        let empty = plans
            .iter()
            .find(|plan| plan.identity.0 == "go-windows-arm64-empty")
            .unwrap();

        assert!(empty.selected_documents.is_empty());
        assert_eq!(
            empty.ignored_documents,
            BTreeSet::from([RepositoryPath("api/api_amd64.go".to_string())])
        );
    }

    #[test]
    fn identical_go_sources_keep_distinct_platform_compiler_worlds() {
        let mut model = go_model();
        model.executions[0].execution_id = "linux-amd64".to_string();
        model.executions[0].variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        model.targets[0].execution_id = "linux-amd64".to_string();
        model.targets[0].source_repository_paths = vec!["api/common.go".to_string()];
        model.targets[0].ignored_source_repository_paths.clear();
        let mut freebsd = model.executions[0].clone();
        freebsd.execution_id = "freebsd-amd64".to_string();
        freebsd.variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "freebsd".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        let mut freebsd_target = model.targets[0].clone();
        freebsd_target.execution_id = freebsd.execution_id.clone();
        model.executions.push(freebsd);
        model.targets.push(freebsd_target);
        let semantic_documents = semantic_go_documents(&model);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();

        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].identity.0, "freebsd-amd64");
        assert_eq!(plans[1].identity.0, "linux-amd64");
        assert_eq!(plans[0].selected_documents, plans[1].selected_documents);
        assert_ne!(plans[0].environment, plans[1].environment);
    }

    #[test]
    fn source_equivalent_go_variants_receive_distinct_semantic_worlds() {
        let mut model = go_model();
        let mut alternate = model.executions[0].variant.clone();
        let IntentionalBoundaryProjectModelVariant::Go {
            goos, architecture, ..
        } = &mut alternate
        else {
            unreachable!()
        };
        *goos = "freebsd".to_string();
        *architecture = IntentionalBoundaryProjectModelGoArchitecture::Default;
        model.executions[0].equivalent_variants.push(alternate);
        let documents = semantic_go_documents(&model);
        let plans = go_semantic_variant_plans(&model, &documents).unwrap();
        assert_eq!(plans.len(), 2);
        let primary = plans
            .iter()
            .find(|plan| plan.identity.0 == "go-linux-amd64")
            .unwrap();
        let alternate = plans
            .iter()
            .find(|plan| plan.identity != primary.identity)
            .unwrap();
        assert_eq!(alternate.selected_documents, primary.selected_documents);
        assert_eq!(alternate.ignored_documents, primary.ignored_documents);
        assert_eq!(alternate.environment["GOOS"], "freebsd");
        assert!(!alternate.environment.contains_key("GOAMD64"));
        assert_eq!(
            alternate.dimensions["project_model_execution_id"],
            "go-linux-amd64"
        );
        assert!(
            alternate
                .identity
                .0
                .starts_with("go-source-equivalent-world-v1-")
        );
        assert_eq!(
            plans,
            go_semantic_variant_plans(&model, &documents).unwrap()
        );
    }

    #[test]
    fn source_equivalent_go_variant_cannot_change_the_compiler_query() {
        let mut model = go_model();
        let mut alternate = model.executions[0].variant.clone();
        let IntentionalBoundaryProjectModelVariant::Go { query, .. } = &mut alternate else {
            unreachable!()
        };
        *query = IntentionalBoundaryProjectModelGoQuery::StandaloneSource {
            source_repository_path: "api/api_amd64.go".to_string(),
        };
        model.executions[0].equivalent_variants.push(alternate);
        let error = go_semantic_variant_plans(&model, &semantic_go_documents(&model)).unwrap_err();
        assert!(error.contains("changed its compiler query"), "{error}");
    }

    #[test]
    fn go_semantic_world_rejects_a_repeated_compiler_context() {
        let mut model = go_model();
        let repeated = model.executions[0].variant.clone();
        model.executions[0].equivalent_variants.push(repeated);
        let error = go_semantic_variant_plans(&model, &semantic_go_documents(&model)).unwrap_err();
        assert!(error.contains("repeats a compiler context"), "{error}");
    }

    #[test]
    fn source_coverage_keeps_worlds_with_unique_and_overlapping_repository_sources() {
        let mut model = go_model();
        model.executions[0].execution_id = "linux-amd64".to_string();
        model.executions[0].variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        model.targets[0].execution_id = "linux-amd64".to_string();
        model.targets[0].source_repository_paths =
            vec!["api/common.go".to_string(), "api/linux.go".to_string()];
        model.targets[0].ignored_source_repository_paths =
            vec!["api/cgo.go".to_string(), "api/windows.go".to_string()];

        let mut windows = model.executions[0].clone();
        windows.execution_id = "windows-amd64".to_string();
        windows.variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "windows".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        let mut windows_target = model.targets[0].clone();
        windows_target.execution_id = windows.execution_id.clone();
        windows_target.source_repository_paths =
            vec!["api/common.go".to_string(), "api/windows.go".to_string()];
        windows_target.ignored_source_repository_paths =
            vec!["api/cgo.go".to_string(), "api/linux.go".to_string()];

        let mut cgo = model.executions[0].clone();
        cgo.execution_id = "linux-amd64-cgo".to_string();
        cgo.variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: true,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        let mut cgo_target = model.targets[0].clone();
        cgo_target.execution_id = cgo.execution_id.clone();
        cgo_target.source_repository_paths = vec![
            "api/cgo.go".to_string(),
            "api/common.go".to_string(),
            "api/linux.go".to_string(),
        ];
        cgo_target.ignored_source_repository_paths = vec!["api/windows.go".to_string()];

        let mut redundant = model.executions[0].clone();
        redundant.execution_id = "freebsd-amd64".to_string();
        redundant.variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "freebsd".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        let mut redundant_target = model.targets[0].clone();
        redundant_target.execution_id = redundant.execution_id.clone();

        model.executions.extend([windows, cgo, redundant]);
        model
            .targets
            .extend([windows_target, cgo_target, redundant_target]);
        let semantic_documents = semantic_go_documents(&model);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();
        let identities = plans
            .iter()
            .map(|plan| plan.identity.0.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            identities,
            BTreeSet::from([
                "freebsd-amd64",
                "linux-amd64",
                "linux-amd64-cgo",
                "windows-amd64"
            ])
        );
        let covered = plans
            .iter()
            .flat_map(|plan| plan.selected_documents.iter().cloned())
            .collect::<BTreeSet<_>>();
        assert!(semantic_documents.is_subset(&covered));

        model.executions.reverse();
        model.targets.reverse();
        let reordered = go_semantic_variant_plans(&model, &semantic_documents).unwrap();
        assert_eq!(plans, reordered);
    }

    #[test]
    fn standalone_go_source_gets_a_named_file_compiler_world() {
        let mut model = go_model();
        model.executions[0].execution_id = "module-packages".to_string();
        model.targets[0].execution_id = "module-packages".to_string();
        model.targets[0].source_repository_paths = vec!["api/common.go".to_string()];
        model.targets[0].ignored_source_repository_paths = vec!["plugins/generate.go".to_string()];
        let mut standalone = model.executions[0].clone();
        standalone.execution_id = "standalone-generator".to_string();
        standalone.variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::StandaloneSource {
                source_repository_path: "plugins/generate.go".to_string(),
            },
        };
        let mut target = model.targets[0].clone();
        target.execution_id = standalone.execution_id.clone();
        target.target_name = "standalone:plugins/generate.go".to_string();
        target.source_repository_paths = vec!["plugins/generate.go".to_string()];
        target.ignored_source_repository_paths.clear();
        model.executions.push(standalone);
        model.targets.push(target);
        let semantic_documents = BTreeSet::from([
            RepositoryPath("api/common.go".to_string()),
            RepositoryPath("plugins/generate.go".to_string()),
        ]);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();
        let standalone = plans
            .iter()
            .find(|plan| plan.identity.0 == "standalone-generator")
            .unwrap();

        assert_eq!(plans.len(), 2);
        assert_eq!(
            standalone.compiler_query,
            SemanticIndexerCompilerQuery::ExactSource {
                source_document: RepositoryPath("plugins/generate.go".to_string())
            }
        );
        assert_eq!(
            standalone.selected_documents,
            BTreeSet::from([RepositoryPath("plugins/generate.go".to_string())])
        );
        assert_eq!(
            standalone.ignored_documents,
            BTreeSet::from([RepositoryPath("api/common.go".to_string())])
        );
    }

    #[test]
    fn required_production_source_without_a_compiler_world_fails_closed() {
        let model = go_model();
        let mut semantic_documents = semantic_go_documents(&model);
        semantic_documents.insert(RepositoryPath("api/unselected.go".to_string()));

        let error = go_semantic_variant_plans(&model, &semantic_documents).unwrap_err();

        assert!(
            error.contains("no compiler world selecting required source api/unselected.go"),
            "{error}"
        );
    }

    #[test]
    #[ignore = "requires a sealed historical-v2 Go project-model artifact"]
    fn sealed_go_project_model_retains_all_compiler_worlds() {
        let path = std::env::var_os("SNIFF_SEALED_GO_PROJECT_MODEL")
            .expect("SNIFF_SEALED_GO_PROJECT_MODEL must name the sealed model");
        let expected_count = std::env::var("SNIFF_EXPECTED_GO_SEMANTIC_WORLD_COUNT")
            .expect("SNIFF_EXPECTED_GO_SEMANTIC_WORLD_COUNT must be set")
            .parse::<usize>()
            .expect("SNIFF_EXPECTED_GO_SEMANTIC_WORLD_COUNT must be an integer");
        let bytes = std::fs::read(&path).expect("sealed Go project model must be readable");
        let envelope: serde_json::Value =
            serde_json::from_slice(&bytes).expect("sealed Go project-model envelope must be valid");
        let payload = envelope
            .get("payload")
            .cloned()
            .expect("sealed Go project-model envelope must contain a payload");
        let model: IntentionalBoundaryProjectModelCensus =
            serde_json::from_value(payload).expect("sealed Go project model must be valid");
        let semantic_documents = model
            .targets
            .iter()
            .flat_map(|target| {
                target
                    .source_repository_paths
                    .iter()
                    .chain(&target.ignored_source_repository_paths)
            })
            .cloned()
            .map(RepositoryPath)
            .collect::<BTreeSet<_>>();

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();
        let covered = plans
            .iter()
            .flat_map(|plan| plan.selected_documents.iter().cloned())
            .collect::<BTreeSet<_>>();

        assert_eq!(plans.len(), expected_count);
        assert!(semantic_documents.is_subset(&covered));
        eprintln!(
            "sealed Go semantic worlds: {} -> {}; production sources: {}",
            model.executions.len(),
            plans.len(),
            semantic_documents.len()
        );
    }

    #[test]
    fn module_with_no_semantically_required_document_has_no_compiler_world() {
        let mut model = go_model();
        let mut execution = model.executions[0].clone();
        execution.execution_id = "vendored-linux".to_string();
        execution.invocation_anchor_repository_path = "vendor/example/go.mod".to_string();
        execution.covered_manifest_repository_paths = vec!["vendor/example/go.mod".to_string()];
        let mut target = model.targets[0].clone();
        target.execution_id = execution.execution_id.clone();
        target.manifest_repository_path = execution.invocation_anchor_repository_path.clone();
        target.source_repository_paths = vec!["vendor/example/api.go".to_string()];
        target.ignored_source_repository_paths.clear();
        model.executions.push(execution);
        model.targets.push(target);
        let semantic_documents = BTreeSet::from([RepositoryPath("api/api_amd64.go".to_string())]);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].identity.0, "go-linux-amd64");
    }

    #[test]
    fn test_only_nested_module_keeps_its_exact_compiler_world() {
        let mut model = go_model();
        let mut execution = model.executions[0].clone();
        execution.execution_id = "test-tools-linux".to_string();
        execution.invocation_anchor_repository_path = "tools/go.mod".to_string();
        execution.covered_manifest_repository_paths = vec!["tools/go.mod".to_string()];
        let mut target = model.targets[0].clone();
        target.execution_id = execution.execution_id.clone();
        target.manifest_repository_path = execution.invocation_anchor_repository_path.clone();
        target.source_repository_paths.clear();
        target.ignored_source_repository_paths.clear();
        model.executions.push(execution);
        model.targets.push(target);
        let semantic_documents = BTreeSet::from([
            RepositoryPath("api/api_amd64.go".to_string()),
            RepositoryPath("tools/pkg/api_test.go".to_string()),
        ]);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();

        assert_eq!(plans.len(), 2);
        assert!(plans.iter().any(|plan| {
            plan.identity.0 == "test-tools-linux"
                && plan.compiler_project == Some(RepositoryPath("tools/go.mod".to_string()))
                && plan.selected_documents.is_empty()
                && plan.ignored_documents == semantic_documents
        }));
    }

    #[test]
    fn nested_go_modules_classify_each_others_required_sources() {
        let mut model = go_model();
        model.executions[0].execution_id = "root-linux".to_string();
        model.targets[0].execution_id = "root-linux".to_string();
        model.targets[0].source_repository_paths = vec!["api/root.go".to_string()];
        model.targets[0].ignored_source_repository_paths.clear();

        let mut nested_execution = model.executions[0].clone();
        nested_execution.execution_id = "example-linux".to_string();
        nested_execution.invocation_anchor_repository_path =
            "documentation/examples/remote_storage/go.mod".to_string();
        nested_execution.covered_manifest_repository_paths =
            vec!["documentation/examples/remote_storage/go.mod".to_string()];
        let mut nested_target = model.targets[0].clone();
        nested_target.execution_id = nested_execution.execution_id.clone();
        nested_target.manifest_repository_path =
            nested_execution.invocation_anchor_repository_path.clone();
        nested_target.source_repository_paths = vec![
            "documentation/examples/remote_storage/example_write_adapter/server.go".to_string(),
        ];
        model.executions.push(nested_execution);
        model.targets.push(nested_target);
        let semantic_documents = semantic_go_documents(&model);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();
        let root = plans
            .iter()
            .find(|plan| plan.identity.0 == "root-linux")
            .unwrap();
        let nested = plans
            .iter()
            .find(|plan| plan.identity.0 == "example-linux")
            .unwrap();

        assert_eq!(
            root.ignored_documents,
            BTreeSet::from([RepositoryPath(
                "documentation/examples/remote_storage/example_write_adapter/server.go".to_string()
            )])
        );
        assert_eq!(
            nested.ignored_documents,
            BTreeSet::from([RepositoryPath("api/root.go".to_string())])
        );
    }

    #[test]
    fn typescript_plan_uses_only_stable_compiler_world_dimensions() {
        let mut model = go_model();
        let execution = &mut model.executions[0];
        execution.execution_id = "typescript-world".to_string();
        execution.provider = IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi;
        execution.variant = IntentionalBoundaryProjectModelVariant::TypeScript {
            root_config_repository_path: Some("tsconfig.json".to_string()),
            root_source_repository_paths: vec!["src/index.ts".to_string()],
            compiler_version: "5.6.2".to_string(),
            projects: vec![
                crate::benchmark::release::IntentionalBoundaryProjectModelTypeScriptProject {
                    config_repository_path: Some("tsconfig.json".to_string()),
                    config_object_id: Some("c".repeat(40)),
                    config_reads: Vec::new(),
                    project_references: Vec::new(),
                    effective_compiler_options_json: "{}".to_string(),
                    source_repository_paths: vec!["src/index.ts".to_string()],
                },
            ],
            selected_source_repository_paths: vec!["src/index.ts".to_string()],
            ignored_source_repository_paths: vec!["src/browser.ts".to_string()],
        };
        let target = &mut model.targets[0];
        target.execution_id = execution.execution_id.clone();
        target.provider = IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi;

        let plans = typescript_semantic_variant_plans(&model).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].dimensions,
            BTreeMap::from([
                ("compiler_version".to_string(), "5.6.2".to_string()),
                ("root_config".to_string(), "tsconfig.json".to_string()),
            ])
        );
        assert_eq!(
            plans[0].compiler_project,
            Some(RepositoryPath("tsconfig.json".to_string()))
        );
    }

    #[test]
    fn typescript_loose_plan_retains_its_exact_root_sources() {
        let mut model = go_model();
        let execution = &mut model.executions[0];
        execution.execution_id = "typescript-loose-world".to_string();
        execution.provider = IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi;
        execution.variant = IntentionalBoundaryProjectModelVariant::TypeScript {
            root_config_repository_path: None,
            root_source_repository_paths: vec!["src/index.test.ts".to_string()],
            compiler_version: "5.6.2".to_string(),
            projects: vec![
                crate::benchmark::release::IntentionalBoundaryProjectModelTypeScriptProject {
                    config_repository_path: None,
                    config_object_id: None,
                    config_reads: Vec::new(),
                    project_references: Vec::new(),
                    effective_compiler_options_json: r#"{"noEmit":true}"#.to_string(),
                    source_repository_paths: vec!["src/index.test.ts".to_string()],
                },
            ],
            selected_source_repository_paths: vec!["src/index.test.ts".to_string()],
            ignored_source_repository_paths: vec!["src/index.ts".to_string()],
        };
        let target = &mut model.targets[0];
        target.execution_id = execution.execution_id.clone();
        target.provider = IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi;

        let plans = typescript_semantic_variant_plans(&model).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].compiler_project, None);
        assert_eq!(
            plans[0].compiler_query,
            SemanticIndexerCompilerQuery::ExactSources {
                source_documents: BTreeSet::from([RepositoryPath("src/index.test.ts".to_string())])
            }
        );
    }

    fn go_model() -> IntentionalBoundaryProjectModelCensus {
        let variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: vec!["enterprise".to_string()],
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Explicit {
                environment_variable: "GOAMD64".to_string(),
                value: "v3".to_string(),
            },
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        };
        IntentionalBoundaryProjectModelCensus {
            schema_version:
                crate::benchmark::release::INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
            project_model_contract: "fixture".to_string(),
            repository: "example/repo".to_string(),
            revision: "a".repeat(40),
            inventory_sha256: "b".repeat(64),
            executions: vec![IntentionalBoundaryProjectModelExecution {
                execution_id: "go-linux-amd64".to_string(),
                provider: IntentionalBoundaryProjectModelProvider::GoList,
                variant,
                equivalent_variants: Vec::new(),
                invocation_anchor_repository_path: "go.mod".to_string(),
                invocation_anchor_object_id: "c".repeat(40),
                toolchain_identity_sha256: "d".repeat(64),
                command_contract: "fixture".to_string(),
                normalized_model_sha256: "e".repeat(64),
                covered_manifest_repository_paths: vec!["go.mod".to_string()],
                target_count: 1,
            }],
            targets: vec![IntentionalBoundaryProjectModelTarget {
                target_id: "target".to_string(),
                execution_id: "go-linux-amd64".to_string(),
                provider: IntentionalBoundaryProjectModelProvider::GoList,
                manifest_repository_path: "go.mod".to_string(),
                manifest_object_id: "c".repeat(40),
                package_name: "example.test/api".to_string(),
                package_version: "git:fixture".to_string(),
                target_name: "example.test/api".to_string(),
                provider_kinds: vec!["package".to_string()],
                provider_output_types: vec!["package_archive".to_string()],
                source_repository_paths: vec!["api/api_amd64.go".to_string()],
                ignored_source_repository_paths: vec!["api/api_windows.go".to_string()],
                producer_tasks: Vec::new(),
                required_features: Vec::new(),
                target_status: IntentionalBoundaryProjectModelTargetStatus::Unresolved {
                    reason: IntentionalBoundaryProjectModelUnresolvedReason::SourceSetEmpty,
                    detail: "fixture".to_string(),
                },
            }],
            execution_count_by_provider: BTreeMap::from([(
                IntentionalBoundaryProjectModelProvider::GoList,
                1,
            )]),
            target_count_by_status: BTreeMap::from([("unresolved".to_string(), 1)]),
            project_model_census_sha256: "f".repeat(64),
        }
    }
}
