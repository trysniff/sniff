use super::*;
use crate::benchmark::release::{
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelUnresolvedReason, IntentionalBoundaryProjectModelVariant,
};

fn model(
    targets: Vec<IntentionalBoundaryProjectModelTarget>,
) -> IntentionalBoundaryProjectModelCensus {
    let execution_ids = targets
        .iter()
        .map(|target| target.execution_id.clone())
        .collect::<BTreeSet<_>>();
    let executions = execution_ids
        .iter()
        .enumerate()
        .map(
            |(ordinal, execution_id)| IntentionalBoundaryProjectModelExecution {
                execution_id: execution_id.clone(),
                provider: IntentionalBoundaryProjectModelProvider::GoList,
                variant: IntentionalBoundaryProjectModelVariant::Go {
                    goos: if ordinal == 0 { "linux" } else { "windows" }.to_string(),
                    goarch: "amd64".to_string(),
                    cgo_enabled: false,
                    build_tags: Vec::new(),
                },
                invocation_anchor_repository_path: "go.mod".to_string(),
                invocation_anchor_object_id: "d".repeat(40),
                toolchain_identity_sha256: "e".repeat(64),
                command_contract: "fixture".to_string(),
                normalized_model_sha256: "f".repeat(64),
                covered_manifest_repository_paths: vec!["go.mod".to_string()],
                target_count: targets
                    .iter()
                    .filter(|target| target.execution_id == *execution_id)
                    .count(),
            },
        )
        .collect();
    IntentionalBoundaryProjectModelCensus {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
        project_model_contract: "fixture".to_string(),
        repository: "example/repo".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        executions,
        targets,
        execution_count_by_provider: BTreeMap::new(),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: "c".repeat(64),
    }
}

fn target(
    id: &str,
    import_path: &str,
    provider_kind: &str,
    source: &str,
) -> IntentionalBoundaryProjectModelTarget {
    let declaration_kind = if provider_kind == "main" {
        IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint
    } else {
        IntentionalBoundaryManifestDeclarationKind::PublishedModule
    };
    IntentionalBoundaryProjectModelTarget {
        target_id: id.to_string(),
        execution_id: "execution".to_string(),
        provider: IntentionalBoundaryProjectModelProvider::GoList,
        manifest_repository_path: "go.mod".to_string(),
        manifest_object_id: "d".repeat(40),
        package_name: "example.test/project".to_string(),
        package_version: "git:fixture".to_string(),
        target_name: import_path.to_string(),
        provider_kinds: vec![provider_kind.to_string()],
        provider_output_types: vec![if provider_kind == "main" {
            "executable".to_string()
        } else {
            "package_archive".to_string()
        }],
        source_repository_paths: vec![source.to_string()],
        ignored_source_repository_paths: Vec::new(),
        producer_tasks: Vec::new(),
        required_features: Vec::new(),
        target_status: IntentionalBoundaryProjectModelTargetStatus::Boundary {
            declaration_kind,
            target: IntentionalBoundaryManifestTarget::RepositoryPaths {
                repository_paths: vec![source.to_string()],
            },
        },
    }
}

#[test]
fn exposes_only_importable_library_packages() {
    let exposures = go_package_exposures(&model(vec![
        target(
            "public",
            "example.test/project/public",
            "package",
            "public/api.go",
        ),
        target(
            "internal",
            "example.test/project/internal/store",
            "package",
            "internal/store/store.go",
        ),
        target(
            "command",
            "example.test/project/cmd/tool",
            "main",
            "cmd/tool/main.go",
        ),
    ]))
    .unwrap();

    assert_eq!(exposures.len(), 3);
    assert!(
        exposures
            .iter()
            .find(|exposure| exposure.import_path.ends_with("/public"))
            .unwrap()
            .externally_reachable
    );
    for id in ["internal", "command"] {
        assert!(
            !exposures
                .iter()
                .find(|exposure| {
                    exposure
                        .variants
                        .iter()
                        .any(|variant| variant.target_id == id)
                })
                .unwrap()
                .externally_reachable
        );
    }
    assert!(
        exposures
            .iter()
            .all(|exposure| exposure.surface_slot_id.starts_with("h2gops-v1:"))
    );
}

#[test]
fn groups_repeated_package_ownership_without_flattening_variants() {
    let linux = target(
        "linux-target",
        "example.test/project/public",
        "package",
        "public/api.go",
    );
    let mut windows = target(
        "windows-target",
        "example.test/project/public",
        "package",
        "public/windows.go",
    );
    windows.execution_id = "windows-execution".to_string();
    windows.ignored_source_repository_paths = vec!["public/api.go".to_string()];
    let exposures = go_package_exposures(&model(vec![linux, windows])).unwrap();

    assert_eq!(exposures.len(), 1);
    assert_eq!(exposures[0].variants.len(), 2);
    assert_eq!(
        exposures[0].source_repository_paths,
        ["public/api.go", "public/windows.go"]
    );
    assert_ne!(
        exposures[0].variants[0].variant,
        exposures[0].variants[1].variant
    );
}

#[test]
fn package_slots_use_module_and_import_identity_not_source_paths() {
    let first =
        go_package_surface_slot_id("example.test/project", "example.test/project/public").unwrap();
    let moved =
        go_package_surface_slot_id("example.test/project", "example.test/project/public").unwrap();
    let other =
        go_package_surface_slot_id("example.test/project", "example.test/project/other").unwrap();

    assert_eq!(first, moved);
    assert_ne!(first, other);
}

#[test]
fn rejects_unresolved_or_multiply_owned_packages() {
    let mut unresolved = target(
        "unresolved",
        "example.test/project/public",
        "package",
        "public/api.go",
    );
    unresolved.target_status = IntentionalBoundaryProjectModelTargetStatus::Unresolved {
        reason: IntentionalBoundaryProjectModelUnresolvedReason::SourceSetEmpty,
        detail: "fixture".to_string(),
    };
    assert!(
        go_package_exposures(&model(vec![unresolved]))
            .unwrap_err()
            .contains("unresolved public exposure")
    );

    let error = go_package_exposures(&model(vec![
        target(
            "first",
            "example.test/project/first",
            "package",
            "shared.go",
        ),
        target(
            "second",
            "example.test/project/second",
            "package",
            "shared.go",
        ),
    ]))
    .unwrap_err();
    assert!(error.contains("more than one compiler package"), "{error}");
}
