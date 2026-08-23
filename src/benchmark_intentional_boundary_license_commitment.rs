use super::intentional_boundary_license_filename::{LicenseFilenameMatch, match_license_filename};
use super::{
    BoundaryGitEntryKind, IntentionalBoundaryLicenseArtifact,
    IntentionalBoundaryLicenseCandidateRejection, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryRepositoryInventory,
};
use std::collections::BTreeMap;

pub(super) fn validate_license_payload_commitment(
    inventory: &IntentionalBoundaryRepositoryInventory,
    stage: &IntentionalBoundaryLicenseCensusStage,
) -> Result<(), String> {
    let expected = inventory
        .tracked_entries
        .iter()
        .filter_map(|entry| {
            match_license_filename(&entry.repository_path)
                .map(|matched| (entry.repository_path.as_str(), (entry, matched)))
        })
        .collect::<BTreeMap<_, _>>();
    if expected.values().any(|(entry, _)| {
        !matches!(
            entry.kind,
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
        )
    }) {
        return Err("completed license census contains a non-blob candidate".to_string());
    }
    if stage.matched_candidate_count != expected.len()
        || stage.license_artifacts.is_empty()
        || !strict_artifact_order(&stage.license_artifacts)
        || !strict_rejection_order(&stage.rejected_candidates)
    {
        return Err("committed license candidate partition changed".to_string());
    }

    let mut observed = BTreeMap::new();
    for artifact in &stage.license_artifacts {
        validate_record(
            &expected,
            &artifact.repository_path,
            &artifact.object_id,
            artifact.byte_length,
            &artifact.content_sha256,
            artifact.filename_rule,
            artifact.filename_score_basis_points,
        )?;
        if observed
            .insert(artifact.repository_path.as_str(), ())
            .is_some()
        {
            return Err("committed license candidate is duplicated".to_string());
        }
    }
    for rejection in &stage.rejected_candidates {
        let IntentionalBoundaryLicenseCandidateRejection::EmptyOrWhitespace {
            repository_path,
            object_id,
            byte_length,
            content_sha256,
            filename_rule,
            filename_score_basis_points,
        } = rejection;
        validate_record(
            &expected,
            repository_path,
            object_id,
            *byte_length,
            content_sha256,
            *filename_rule,
            *filename_score_basis_points,
        )?;
        if observed.insert(repository_path.as_str(), ()).is_some() {
            return Err("committed license candidate is duplicated".to_string());
        }
    }
    if observed.len() != expected.len() || observed.keys().copied().ne(expected.keys().copied()) {
        return Err("committed license candidates do not cover the inventory".to_string());
    }
    Ok(())
}

fn validate_record(
    expected: &BTreeMap<
        &str,
        (
            &super::IntentionalBoundaryTrackedEntry,
            LicenseFilenameMatch,
        ),
    >,
    repository_path: &str,
    object_id: &str,
    byte_length: u64,
    content_sha256: &str,
    filename_rule: super::IntentionalBoundaryLicenseFilenameRule,
    filename_score_basis_points: u16,
) -> Result<(), String> {
    let Some((entry, matched)) = expected.get(repository_path) else {
        return Err("committed license candidate is not in the inventory".to_string());
    };
    if object_id != entry.object_id
        || Some(byte_length) != entry.byte_length
        || filename_rule != matched.rule
        || filename_score_basis_points != matched.score_basis_points
        || !is_lower_sha256(content_sha256)
    {
        return Err("committed license candidate metadata changed".to_string());
    }
    Ok(())
}

fn strict_artifact_order(artifacts: &[IntentionalBoundaryLicenseArtifact]) -> bool {
    artifacts
        .windows(2)
        .all(|pair| pair[0].repository_path < pair[1].repository_path)
}

fn strict_rejection_order(rejections: &[IntentionalBoundaryLicenseCandidateRejection]) -> bool {
    rejections
        .windows(2)
        .all(|pair| rejection_path(&pair[0]) < rejection_path(&pair[1]))
}

fn rejection_path(rejection: &IntentionalBoundaryLicenseCandidateRejection) -> &str {
    match rejection {
        IntentionalBoundaryLicenseCandidateRejection::EmptyOrWhitespace {
            repository_path, ..
        } => repository_path,
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
