use super::super::{
    PublicIdCensusFrameCommitment, read_public_id_census_artifact,
    validate_historical_v3_public_id_census_audit,
    validate_historical_v3_public_id_census_v2_audit,
};
use super::{
    CandidateSource, HistoricalV3CandidatePartition, HistoricalV3CandidateRepository,
    HistoricalV3PriorBenchmarkIdentitySeal, HistoricalV3Protocol, HistoricalV3SourceBindingAudit,
    HistoricalV3SourceRepositoryIdentity, format_utc_second, parse_historical_v3_source_frame,
    parse_utc_second, split_inclusive_utc_range, validate_historical_v3_protocol,
    validate_historical_v3_source_binding_audit,
};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

const MAX_FRAME_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn candidate_repositories(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    source: CandidateSource<'_>,
    source_binding_audit: &HistoricalV3SourceBindingAudit,
) -> Result<Vec<HistoricalV3CandidateRepository>, String> {
    let frame_bytes = match source {
        CandidateSource::Search(artifacts) => {
            validate_historical_v3_source_binding_audit(
                protocol,
                prior_identities,
                artifacts,
                source_binding_audit,
            )?;
            artifacts
                .iter()
                .map(|artifact| Cow::Borrowed(artifact.frame))
                .collect::<Vec<_>>()
        }
        CandidateSource::PublicIdCensus(census) => {
            validate_historical_v3_public_id_census_audit(
                protocol,
                prior_identities,
                census,
                source_binding_audit,
            )?;
            census_frame_bytes(census.artifact_root, &census.manifest.frames)?
        }
        CandidateSource::PublicIdCensusV2(census) => {
            validate_historical_v3_public_id_census_v2_audit(
                protocol,
                prior_identities,
                census,
                source_binding_audit,
            )?;
            census_frame_bytes(census.artifact_root, &census.manifest.frames)?
        }
    };
    let excluded = prior_identities
        .repositories
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut repositories = Vec::new();
    for (language, frame) in protocol.languages.iter().copied().zip(frame_bytes) {
        for HistoricalV3SourceRepositoryIdentity {
            name_with_owner,
            repository_id,
            ..
        } in parse_historical_v3_source_frame(&frame)?
        {
            if !excluded.contains(name_with_owner.as_str()) {
                repositories.push(HistoricalV3CandidateRepository {
                    language,
                    repository_id,
                    name_with_owner,
                });
            }
        }
    }
    if repositories.is_empty() {
        return Err("historical-v3 candidate repository census is empty".to_string());
    }
    Ok(repositories)
}

fn census_frame_bytes(
    artifact_root: &Path,
    frames: &[PublicIdCensusFrameCommitment],
) -> Result<Vec<Cow<'static, [u8]>>, String> {
    frames
        .iter()
        .map(|frame| {
            let bytes = read_public_id_census_artifact(
                artifact_root,
                &frame.artifact_path,
                MAX_FRAME_BYTES,
            )?;
            if format!("{:x}", Sha256::digest(&bytes)) != frame.artifact_sha256 {
                return Err(
                    "historical-v3 census frame changed during candidate loading".to_string(),
                );
            }
            Ok(Cow::Owned(bytes))
        })
        .collect()
}

pub(super) fn initial_partitions(
    protocol: &HistoricalV3Protocol,
    repositories: &[HistoricalV3CandidateRepository],
) -> Result<VecDeque<HistoricalV3CandidatePartition>, String> {
    validate_historical_v3_protocol(protocol)?;
    let start = parse_utc_second(&protocol.candidate_window.merged_at_or_after_utc)?;
    let end_exclusive = parse_utc_second(&protocol.candidate_window.merged_before_utc)?;
    if start >= end_exclusive {
        return Err("historical-v3 candidate window is empty".to_string());
    }
    let end_inclusive = format_utc_second(end_exclusive - 1)?;
    Ok(repositories
        .iter()
        .map(|repository| HistoricalV3CandidatePartition {
            language: repository.language,
            repository_id: repository.repository_id,
            name_with_owner: repository.name_with_owner.clone(),
            path: "root".to_string(),
            merged_at_or_after_utc: protocol.candidate_window.merged_at_or_after_utc.clone(),
            merged_at_or_before_utc: end_inclusive.clone(),
        })
        .collect())
}

pub(super) fn split_partition(
    partition: &HistoricalV3CandidatePartition,
) -> Result<
    (
        HistoricalV3CandidatePartition,
        HistoricalV3CandidatePartition,
    ),
    String,
> {
    let (left_range, right_range) = split_inclusive_utc_range(
        &partition.merged_at_or_after_utc,
        &partition.merged_at_or_before_utc,
    )
    .map_err(|_| {
        "historical-v3 one-second partition exceeds GitHub's 1,000-result ceiling".to_string()
    })?;
    let mut left = partition.clone();
    left.path.push('L');
    left.merged_at_or_after_utc = left_range.0;
    left.merged_at_or_before_utc = left_range.1;
    let mut right = partition.clone();
    right.path.push('R');
    right.merged_at_or_after_utc = right_range.0;
    right.merged_at_or_before_utc = right_range.1;
    Ok((left, right))
}
