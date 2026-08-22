use super::IntentionalBoundaryManifestProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ManifestDerivationErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
    ManifestShapeRejected,
    ManifestEncodingRejected,
    ManifestParserRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ManifestDerivationError {
    pub kind: ManifestDerivationErrorKind,
    pub provider: Option<IntentionalBoundaryManifestProvider>,
    pub repository_path: Option<String>,
    pub detail: String,
}

pub(super) fn manifest_invalid(detail: impl Into<String>) -> ManifestDerivationError {
    manifest_error(
        ManifestDerivationErrorKind::InvalidInput,
        None,
        None,
        detail,
    )
}

pub(super) fn manifest_shape_rejected(
    provider: IntentionalBoundaryManifestProvider,
    repository_path: &str,
    detail: impl Into<String>,
) -> ManifestDerivationError {
    manifest_error(
        ManifestDerivationErrorKind::ManifestShapeRejected,
        Some(provider),
        Some(repository_path),
        detail,
    )
}

pub(super) fn manifest_encoding_rejected(
    provider: IntentionalBoundaryManifestProvider,
    repository_path: &str,
    detail: impl Into<String>,
) -> ManifestDerivationError {
    manifest_error(
        ManifestDerivationErrorKind::ManifestEncodingRejected,
        Some(provider),
        Some(repository_path),
        detail,
    )
}

pub(super) fn manifest_parser_rejected(
    provider: IntentionalBoundaryManifestProvider,
    repository_path: &str,
    detail: impl Into<String>,
) -> ManifestDerivationError {
    manifest_error(
        ManifestDerivationErrorKind::ManifestParserRejected,
        Some(provider),
        Some(repository_path),
        detail,
    )
}

pub(super) fn manifest_infrastructure_unavailable(
    detail: impl Into<String>,
) -> ManifestDerivationError {
    manifest_error(
        ManifestDerivationErrorKind::InfrastructureUnavailable,
        None,
        None,
        detail,
    )
}

pub(super) fn manifest_infrastructure_failed(detail: impl Into<String>) -> ManifestDerivationError {
    manifest_error(
        ManifestDerivationErrorKind::InfrastructureFailed,
        None,
        None,
        detail,
    )
}

fn manifest_error(
    kind: ManifestDerivationErrorKind,
    provider: Option<IntentionalBoundaryManifestProvider>,
    repository_path: Option<&str>,
    detail: impl Into<String>,
) -> ManifestDerivationError {
    ManifestDerivationError {
        kind,
        provider,
        repository_path: repository_path.map(str::to_string),
        detail: detail.into(),
    }
}
