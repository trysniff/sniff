use super::intentional_boundary_inventory::read_intentional_boundary_git_blob_typed;
use super::intentional_boundary_manifest::{
    map_inventory_error, parse_static_manifest, provider_for_path,
};
use super::intentional_boundary_manifest_outcome::{
    ManifestDerivationError, ManifestDerivationErrorKind, manifest_encoding_rejected,
    manifest_invalid, manifest_shape_rejected,
};
use super::{
    BoundaryGitEntryKind, IntentionalBoundaryManifestExclusionReason,
    IntentionalBoundaryManifestFailureEvidence, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestStageError, IntentionalBoundaryManifestStageErrorKind,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundaryTrackedEntry,
};
use sha2::{Digest, Sha256};

const RETAINED_EVIDENCE_LIMIT: usize = 4 * 1024;

pub(super) enum ManifestPreflight {
    Clear,
    Excluded(Vec<IntentionalBoundaryManifestFailureEvidence>),
}

pub(super) fn preflight_manifest_entries(
    root: &std::path::Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Vec<ManifestDerivationError> {
    let mut errors = Vec::new();
    for entry in &inventory.tracked_entries {
        if let Some(provider) = provider_for_path(&entry.repository_path) {
            if let Err(error) = preflight_static_manifest(root, entry, provider) {
                errors.push(error);
            }
            continue;
        }
        if entry.repository_path.ends_with(".go")
            && let Err(error) = preflight_go_source(root, entry)
        {
            errors.push(error);
        }
    }
    errors
}

fn preflight_static_manifest(
    root: &std::path::Path,
    entry: &IntentionalBoundaryTrackedEntry,
    provider: IntentionalBoundaryManifestProvider,
) -> Result<(), ManifestDerivationError> {
    let source = read_utf8_manifest(root, entry, provider)?;
    parse_static_manifest(provider, &entry.repository_path, &source).map(|_| ())
}

fn preflight_go_source(
    root: &std::path::Path,
    entry: &IntentionalBoundaryTrackedEntry,
) -> Result<(), ManifestDerivationError> {
    read_utf8_manifest(
        root,
        entry,
        IntentionalBoundaryManifestProvider::GoGenerateSource,
    )
    .map(|_| ())
}

fn read_utf8_manifest(
    root: &std::path::Path,
    entry: &IntentionalBoundaryTrackedEntry,
    provider: IntentionalBoundaryManifestProvider,
) -> Result<String, ManifestDerivationError> {
    if entry.kind != BoundaryGitEntryKind::RegularBlob {
        return Err(manifest_shape_rejected(
            provider,
            &entry.repository_path,
            "intentional-boundary manifest input is not a regular Git blob",
        ));
    }
    let expected_length = entry.byte_length.ok_or_else(|| {
        manifest_invalid(format!(
            "intentional-boundary manifest input has no byte length: {}",
            entry.repository_path
        ))
    })?;
    let bytes = read_intentional_boundary_git_blob_typed(root, &entry.object_id, expected_length)
        .map_err(map_inventory_error)?;
    String::from_utf8(bytes).map_err(|_| {
        manifest_encoding_rejected(
            provider,
            &entry.repository_path,
            "intentional-boundary manifest input is not UTF-8",
        )
    })
}

pub(super) fn resolve_manifest_errors(
    errors: Vec<ManifestDerivationError>,
) -> Result<ManifestPreflight, IntentionalBoundaryManifestStageError> {
    let mut operational = Vec::new();
    let mut terminal = Vec::new();
    for error in errors {
        match error.kind {
            ManifestDerivationErrorKind::ManifestShapeRejected
            | ManifestDerivationErrorKind::ManifestEncodingRejected
            | ManifestDerivationErrorKind::ManifestParserRejected => {
                terminal.push(failure_evidence(error)?);
            }
            ManifestDerivationErrorKind::InvalidInput
            | ManifestDerivationErrorKind::InfrastructureUnavailable
            | ManifestDerivationErrorKind::InfrastructureFailed => operational.push(error),
        }
    }
    if !operational.is_empty() {
        return Err(operational_error(operational));
    }
    if terminal.is_empty() {
        return Ok(ManifestPreflight::Clear);
    }
    terminal.sort_by(failure_key);
    Ok(ManifestPreflight::Excluded(terminal))
}

fn failure_evidence(
    error: ManifestDerivationError,
) -> Result<IntentionalBoundaryManifestFailureEvidence, IntentionalBoundaryManifestStageError> {
    let reason = match error.kind {
        ManifestDerivationErrorKind::ManifestShapeRejected => {
            IntentionalBoundaryManifestExclusionReason::ManifestShapeRejected
        }
        ManifestDerivationErrorKind::ManifestEncodingRejected => {
            IntentionalBoundaryManifestExclusionReason::ManifestEncodingRejected
        }
        ManifestDerivationErrorKind::ManifestParserRejected => {
            IntentionalBoundaryManifestExclusionReason::ManifestParserRejected
        }
        ManifestDerivationErrorKind::InvalidInput
        | ManifestDerivationErrorKind::InfrastructureUnavailable
        | ManifestDerivationErrorKind::InfrastructureFailed => return Err(invalid(error.detail)),
    };
    let provider = error
        .provider
        .ok_or_else(|| invalid("terminal manifest failure omitted its provider"))?;
    let repository_path = error
        .repository_path
        .ok_or_else(|| invalid("terminal manifest failure omitted its repository path"))?;
    let (retained_detail, detail_truncated) = retain(&error.detail);
    Ok(IntentionalBoundaryManifestFailureEvidence {
        reason,
        provider,
        repository_path,
        detail_sha256: sha256(error.detail.as_bytes()),
        retained_detail,
        detail_truncated,
    })
}

pub(super) fn failure_key(
    left: &IntentionalBoundaryManifestFailureEvidence,
    right: &IntentionalBoundaryManifestFailureEvidence,
) -> std::cmp::Ordering {
    (
        &left.repository_path,
        left.provider,
        left.reason,
        &left.detail_sha256,
    )
        .cmp(&(
            &right.repository_path,
            right.provider,
            right.reason,
            &right.detail_sha256,
        ))
}

fn operational_error(
    mut errors: Vec<ManifestDerivationError>,
) -> IntentionalBoundaryManifestStageError {
    errors.sort_by(|left, right| {
        operational_priority(left.kind)
            .cmp(&operational_priority(right.kind))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    let kind = if errors
        .iter()
        .any(|error| error.kind == ManifestDerivationErrorKind::InvalidInput)
    {
        IntentionalBoundaryManifestStageErrorKind::InvalidInput
    } else if errors
        .iter()
        .any(|error| error.kind == ManifestDerivationErrorKind::InfrastructureFailed)
    {
        IntentionalBoundaryManifestStageErrorKind::InfrastructureFailed
    } else {
        IntentionalBoundaryManifestStageErrorKind::InfrastructureUnavailable
    };
    IntentionalBoundaryManifestStageError {
        kind,
        detail: errors
            .into_iter()
            .map(|error| error.detail)
            .collect::<Vec<_>>()
            .join("; additionally, "),
    }
}

fn operational_priority(kind: ManifestDerivationErrorKind) -> u8 {
    match kind {
        ManifestDerivationErrorKind::InvalidInput => 0,
        ManifestDerivationErrorKind::InfrastructureFailed => 1,
        ManifestDerivationErrorKind::InfrastructureUnavailable => 2,
        ManifestDerivationErrorKind::ManifestShapeRejected
        | ManifestDerivationErrorKind::ManifestEncodingRejected
        | ManifestDerivationErrorKind::ManifestParserRejected => 3,
    }
}

fn retain(value: &str) -> (String, bool) {
    if value.len() <= RETAINED_EVIDENCE_LIMIT {
        return (value.to_string(), false);
    }
    let mut end = RETAINED_EVIDENCE_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryManifestStageError {
    IntentionalBoundaryManifestStageError {
        kind: IntentionalBoundaryManifestStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
