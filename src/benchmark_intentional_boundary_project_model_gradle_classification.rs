use super::producers::validate_producer_tasks;
use crate::benchmark::release::{
    BoundaryGitEntryKind, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryProjectModelProvider as Provider,
    IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelUnresolvedReason as UnresolvedReason,
    IntentionalBoundaryRepositoryInventory,
};

pub(super) fn classify_target(
    inventory: &IntentionalBoundaryRepositoryInventory,
    provider_kinds: &[String],
    source_repository_paths: &[String],
) -> TargetStatus {
    if source_repository_paths.is_empty() {
        return unresolved(
            UnresolvedReason::SourceSetEmpty,
            "Gradle project has no Tooling API production source files".to_string(),
        );
    }
    for repository_path in source_repository_paths {
        let Some(entry) = inventory
            .tracked_entries
            .iter()
            .find(|entry| entry.repository_path == *repository_path)
        else {
            return unresolved(
                UnresolvedReason::SourceNotTracked,
                "Gradle production source is not present in the immutable Git inventory"
                    .to_string(),
            );
        };
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            return unresolved(
                UnresolvedReason::SourceNotRegularBlob,
                "Gradle production source is not a regular Git blob".to_string(),
            );
        }
    }
    let has_application = provider_kinds.iter().any(|kind| kind == "application");
    let has_library = provider_kinds.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "gradle_plugin" | "java_library" | "publication"
        )
    });
    let has_unknown = provider_kinds.iter().any(|kind| {
        !matches!(
            kind.as_str(),
            "application" | "gradle_plugin" | "java_library" | "publication" | "unclassified"
        )
    });
    if has_unknown || provider_kinds == ["unclassified"] {
        return unresolved(
            UnresolvedReason::UnknownTargetKind,
            "Gradle project has no explicit application, library, plugin, or publication contract"
                .to_string(),
        );
    }
    if has_application == has_library {
        return unresolved(
            UnresolvedReason::ConflictingTargetKinds,
            "Gradle project has conflicting or missing boundary plugin roles".to_string(),
        );
    }
    boundary(
        if has_application {
            IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint
        } else {
            IntentionalBoundaryManifestDeclarationKind::PublishedModule
        },
        source_repository_paths,
    )
}

pub(super) fn output_types(provider_kinds: &[String]) -> Vec<String> {
    let mut values = Vec::new();
    if provider_kinds.iter().any(|kind| kind == "application") {
        values.push("jvm_application".to_string());
    }
    if provider_kinds.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "gradle_plugin" | "java_library" | "publication"
        )
    }) {
        values.push("jvm_library".to_string());
    }
    if values.is_empty() {
        values.push("jvm_classes".to_string());
    }
    values
}

pub(in crate::benchmark::release) fn validate_gradle_target_classification(
    inventory: &IntentionalBoundaryRepositoryInventory,
    target: &IntentionalBoundaryProjectModelTarget,
) -> bool {
    target.provider == Provider::GradleToolingApi
        && target.required_features.is_empty()
        && target.provider_output_types == output_types(&target.provider_kinds)
        && validate_producer_tasks(target)
        && target.target_status
            == classify_target(
                inventory,
                &target.provider_kinds,
                &target.source_repository_paths,
            )
}

fn boundary(
    declaration_kind: IntentionalBoundaryManifestDeclarationKind,
    repository_paths: &[String],
) -> TargetStatus {
    TargetStatus::Boundary {
        declaration_kind,
        target: IntentionalBoundaryManifestTarget::RepositoryPaths {
            repository_paths: repository_paths.to_vec(),
        },
    }
}

fn unresolved(reason: UnresolvedReason, detail: String) -> TargetStatus {
    TargetStatus::Unresolved { reason, detail }
}
