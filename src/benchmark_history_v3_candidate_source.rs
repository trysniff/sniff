use super::{
    HistoricalV3CandidatePartition, HistoricalV3CandidateRepository,
    HistoricalV3PriorBenchmarkIdentitySeal, HistoricalV3Protocol, HistoricalV3SourceBindingAudit,
    HistoricalV3SourceFrameArtifact, HistoricalV3SourceRepositoryIdentity, format_utc_second,
    parse_historical_v3_source_frame, parse_utc_second, split_inclusive_utc_range,
    validate_historical_v3_protocol, validate_historical_v3_source_binding_audit,
};
use std::collections::{HashSet, VecDeque};

pub(super) fn candidate_repositories(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    source_artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
    source_binding_audit: &HistoricalV3SourceBindingAudit,
) -> Result<Vec<HistoricalV3CandidateRepository>, String> {
    validate_historical_v3_source_binding_audit(
        protocol,
        prior_identities,
        source_artifacts,
        source_binding_audit,
    )?;
    let excluded = prior_identities
        .repositories
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut repositories = Vec::new();
    for (language, artifact) in protocol.languages.iter().copied().zip(source_artifacts) {
        for HistoricalV3SourceRepositoryIdentity {
            name_with_owner,
            repository_id,
        } in parse_historical_v3_source_frame(artifact.frame)?
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
