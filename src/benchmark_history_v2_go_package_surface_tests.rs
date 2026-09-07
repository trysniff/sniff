use super::*;
use crate::benchmark::release::{
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundaryProjectModelUnresolvedReason,
};

fn model(
    targets: Vec<IntentionalBoundaryProjectModelTarget>,
) -> IntentionalBoundaryProjectModelCensus {
    IntentionalBoundaryProjectModelCensus {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
        project_model_contract: "fixture".to_string(),
        repository: "example/repo".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        executions: Vec::new(),
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
            .find(|exposure| exposure.target_id == "public")
            .unwrap()
            .externally_reachable
    );
    for id in ["internal", "command"] {
        assert!(
            !exposures
                .iter()
                .find(|exposure| exposure.target_id == id)
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
