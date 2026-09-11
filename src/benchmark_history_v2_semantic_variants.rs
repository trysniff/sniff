use super::super::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelGoArchitecture,
    IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelVariant,
};
use crate::semantic_index::{RepositoryPath, SemanticIndexerVariantPlan, SemanticVariantId};
use std::cmp::Ordering;
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
    let mut plans = Vec::with_capacity(model.executions.len());
    let mut variants = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let semantic_modules = semantic_go_module_documents(model, semantic_documents)?;
    for execution in &model.executions {
        let IntentionalBoundaryProjectModelVariant::Go {
            goos,
            goarch,
            cgo_enabled,
            build_tags,
            architecture,
        } = &execution.variant
        else {
            return Err("historical-v2 Go variant ledger contains an untyped variant".to_string());
        };
        if !identities.insert(execution.execution_id.as_str()) {
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
            .collect::<BTreeSet<_>>();
        let module_documents = model
            .targets
            .iter()
            .filter(|target| {
                target.manifest_repository_path == execution.invocation_anchor_repository_path
            })
            .flat_map(|target| {
                target
                    .source_repository_paths
                    .iter()
                    .chain(&target.ignored_source_repository_paths)
            })
            .map(|path| RepositoryPath(path.clone()))
            .collect::<BTreeSet<_>>();
        let ignored_documents = module_documents
            .difference(&selected_documents)
            .cloned()
            .chain(targets.iter().flat_map(|target| {
                target
                    .ignored_source_repository_paths
                    .iter()
                    .map(|path| RepositoryPath(path.clone()))
            }))
            .collect::<BTreeSet<_>>();
        let tags = serde_json::to_string(build_tags)
            .map_err(|error| format!("failed to serialize Go build tags: {error}"))?;
        let architecture_dimension = match architecture {
            IntentionalBoundaryProjectModelGoArchitecture::Default => "default".to_string(),
            IntentionalBoundaryProjectModelGoArchitecture::Explicit {
                environment_variable,
                value,
            } => format!("{environment_variable}={value}"),
        };
        let dimensions = BTreeMap::from([
            ("architecture".to_string(), architecture_dimension),
            ("build_tags".to_string(), tags),
            ("cgo_enabled".to_string(), cgo_enabled.to_string()),
            ("goarch".to_string(), goarch.clone()),
            ("goos".to_string(), goos.clone()),
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
            identity: SemanticVariantId(execution.execution_id.clone()),
            dimensions,
            environment,
            compiler_project: Some(RepositoryPath(
                execution.invocation_anchor_repository_path.clone(),
            )),
            selected_documents,
            ignored_documents,
        };
        plan.validate()?;
        if semantic_modules.contains_key(&execution.invocation_anchor_repository_path) {
            variants.insert(plan.identity.clone(), execution.variant.clone());
            plans.push(plan);
        }
    }
    select_go_source_coverage_plans(plans, &variants, &semantic_modules)
}

fn select_go_source_coverage_plans(
    plans: Vec<SemanticIndexerVariantPlan>,
    variants: &BTreeMap<SemanticVariantId, IntentionalBoundaryProjectModelVariant>,
    semantic_modules: &BTreeMap<String, BTreeSet<RepositoryPath>>,
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    let projects = plans
        .iter()
        .map(|plan| {
            plan.compiler_project.clone().ok_or_else(|| {
                format!(
                    "historical-v2 Go compiler world {} has no module",
                    plan.identity.0
                )
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut selected = BTreeSet::new();
    for project in projects {
        let required_documents = semantic_modules
            .get(&project.0)
            .ok_or_else(|| {
                format!(
                    "historical-v2 Go module {} has no required source ledger",
                    project.0
                )
            })?
            .iter()
            .filter(|document| !document.0.ends_with("_test.go"))
            .cloned()
            .collect::<BTreeSet<_>>();
        let candidates = plans
            .iter()
            .enumerate()
            .filter(|(_, plan)| plan.compiler_project.as_ref() == Some(&project))
            .collect::<Vec<_>>();
        let baseline = candidates
            .iter()
            .min_by(|(_, left), (_, right)| compare_go_plans(left, right, variants))
            .map(|(index, _)| *index)
            .ok_or_else(|| {
                format!(
                    "historical-v2 Go module {} has no compiler world",
                    project.0
                )
            })?;
        selected.insert(baseline);

        let compiler_selected_documents = candidates
            .iter()
            .flat_map(|(_, plan)| plan.selected_documents.intersection(&required_documents))
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Some(document) = required_documents
            .difference(&compiler_selected_documents)
            .next()
        {
            return Err(format!(
                "historical-v2 Go module {} has no compiler world selecting required source {}",
                project.0, document.0
            ));
        }
        let mut uncovered = required_documents;
        for document in &plans[baseline].selected_documents {
            uncovered.remove(document);
        }
        while !uncovered.is_empty() {
            let next = candidates
                .iter()
                .filter(|(index, _)| !selected.contains(index))
                .map(|(index, plan)| {
                    let coverage = plan.selected_documents.intersection(&uncovered).count();
                    (*index, *plan, coverage)
                })
                .filter(|(_, _, coverage)| *coverage > 0)
                .max_by(|(_, left, left_coverage), (_, right, right_coverage)| {
                    left_coverage
                        .cmp(right_coverage)
                        .then_with(|| compare_go_plans(right, left, variants))
                })
                .map(|(index, _, _)| index)
                .ok_or_else(|| {
                    format!(
                        "historical-v2 Go module {} cannot cover every compiler-selected source",
                        project.0
                    )
                })?;
            selected.insert(next);
            for document in &plans[next].selected_documents {
                uncovered.remove(document);
            }
        }
    }

    let mut selected = plans
        .into_iter()
        .enumerate()
        .filter_map(|(index, plan)| selected.contains(&index).then_some(plan))
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(selected)
}

fn compare_go_plans(
    left: &SemanticIndexerVariantPlan,
    right: &SemanticIndexerVariantPlan,
    variants: &BTreeMap<SemanticVariantId, IntentionalBoundaryProjectModelVariant>,
) -> Ordering {
    let left_variant = variants
        .get(&left.identity)
        .expect("validated Go plans retain their compiler variants");
    let right_variant = variants
        .get(&right.identity)
        .expect("validated Go plans retain their compiler variants");
    go_variant_preference(left_variant)
        .cmp(&go_variant_preference(right_variant))
        .then_with(|| left.identity.cmp(&right.identity))
}

fn go_variant_preference(
    variant: &IntentionalBoundaryProjectModelVariant,
) -> (
    bool,
    bool,
    bool,
    bool,
    bool,
    &str,
    &str,
    &[String],
    &IntentionalBoundaryProjectModelGoArchitecture,
) {
    let IntentionalBoundaryProjectModelVariant::Go {
        goos,
        goarch,
        cgo_enabled,
        build_tags,
        architecture,
    } = variant
    else {
        unreachable!("Go semantic plans only retain Go variants");
    };
    let portable_baseline = goos == "linux"
        && goarch == "amd64"
        && !cgo_enabled
        && build_tags.is_empty()
        && matches!(
            architecture,
            IntentionalBoundaryProjectModelGoArchitecture::Default
        );
    (
        !portable_baseline,
        !build_tags.is_empty(),
        *cgo_enabled,
        !matches!(
            architecture,
            IntentionalBoundaryProjectModelGoArchitecture::Default
        ),
        goos != "linux",
        goos,
        goarch,
        build_tags,
        architecture,
    )
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
            BTreeSet::from([
                RepositoryPath("api/api_amd64.go".to_string()),
                RepositoryPath("api/api_windows.go".to_string()),
            ])
        );
    }

    #[test]
    fn redundant_go_platforms_collapse_to_the_portable_baseline() {
        let mut model = go_model();
        model.executions[0].execution_id = "linux-amd64".to_string();
        model.executions[0].variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
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
        };
        let mut freebsd_target = model.targets[0].clone();
        freebsd_target.execution_id = freebsd.execution_id.clone();
        model.executions.push(freebsd);
        model.targets.push(freebsd_target);
        let semantic_documents = semantic_go_documents(&model);

        let plans = go_semantic_variant_plans(&model, &semantic_documents).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].identity.0, "linux-amd64");
    }

    #[test]
    fn source_coverage_keeps_each_world_with_unique_repository_sources() {
        let mut model = go_model();
        model.executions[0].execution_id = "linux-amd64".to_string();
        model.executions[0].variant = IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
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
            BTreeSet::from(["linux-amd64", "linux-amd64-cgo", "windows-amd64"])
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
    fn sealed_go_project_model_reduces_to_complete_source_coverage() {
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
                && plan.ignored_documents.is_empty()
        }));
    }

    #[test]
    fn typescript_plan_uses_only_stable_compiler_world_dimensions() {
        let mut model = go_model();
        let execution = &mut model.executions[0];
        execution.execution_id = "typescript-world".to_string();
        execution.provider = IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi;
        execution.variant = IntentionalBoundaryProjectModelVariant::TypeScript {
            root_config_repository_path: Some("tsconfig.json".to_string()),
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
        };
        IntentionalBoundaryProjectModelCensus {
            schema_version: 7,
            project_model_contract: "fixture".to_string(),
            repository: "example/repo".to_string(),
            revision: "a".repeat(40),
            inventory_sha256: "b".repeat(64),
            executions: vec![IntentionalBoundaryProjectModelExecution {
                execution_id: "go-linux-amd64".to_string(),
                provider: IntentionalBoundaryProjectModelProvider::GoList,
                variant,
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
