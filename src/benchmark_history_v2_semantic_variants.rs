use super::super::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelGoArchitecture,
    IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelVariant,
};
use crate::semantic_index::{RepositoryPath, SemanticIndexerVariantPlan, SemanticVariantId};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn go_semantic_variant_plans(
    model: &IntentionalBoundaryProjectModelCensus,
) -> Result<Vec<SemanticIndexerVariantPlan>, String> {
    let mut plans = Vec::with_capacity(model.executions.len());
    let mut identities = BTreeSet::new();
    for execution in &model.executions {
        if execution.provider != IntentionalBoundaryProjectModelProvider::GoList {
            return Err(
                "historical-v2 Go variant ledger mixed project-model providers".to_string(),
            );
        }
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
            compiler_project: None,
            selected_documents,
            ignored_documents,
        };
        plan.validate()?;
        plans.push(plan);
    }
    plans.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(plans)
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

    #[test]
    fn exact_go_project_model_variant_becomes_a_semantic_execution_plan() {
        let model = go_model();

        let plans = go_semantic_variant_plans(&model).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].identity.0, "go-linux-amd64");
        assert_eq!(plans[0].environment["GOOS"], "linux");
        assert_eq!(plans[0].environment["GOAMD64"], "v3");
        assert_eq!(plans[0].environment["GOFLAGS"], "-tags=enterprise");
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

        let plans = go_semantic_variant_plans(&model).unwrap();
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
