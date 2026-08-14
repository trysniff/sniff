use super::non_blind_history_artifacts::RankArtifactWriter;
use super::{
    HistoricalAssessmentEvidence, HistoricalEvidenceKind, HistoricalRepositoryCandidate,
    HistoricalRepositoryFacts, HistoricalSnapshotRoots, HistoricalSourceDeltaCensus,
    ProvenanceArtifact, RankedHistoricalCommit, SourceSnapshot,
};
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
pub(super) struct SourceDeltaEvidence<'a> {
    pub(super) parent_revision: &'a str,
    pub(super) commit_revision: &'a str,
    pub(super) diffs: Vec<DiffEvidence>,
    pub(super) census: &'a HistoricalSourceDeltaCensus,
}

#[derive(Serialize)]
pub(super) struct DiffEvidence {
    pub(super) previous_path: Option<String>,
    pub(super) path: String,
    pub(super) artifact_path: String,
    pub(super) sha256: String,
    pub(super) hunks: Vec<super::HistoricalDiffHunk>,
}

pub(super) struct CapturedSources {
    pub(super) before: Vec<SourceSnapshot>,
    pub(super) after: Vec<SourceSnapshot>,
    pub(super) removed_after_paths: Vec<String>,
}

pub(super) fn capture_license(
    artifacts: &RankArtifactWriter,
    candidate: &HistoricalRepositoryCandidate,
    selected: &RankedHistoricalCommit,
    snapshots: &HistoricalSnapshotRoots,
    license_path: Option<&str>,
    observed_at: &str,
) -> Result<(Option<ProvenanceArtifact>, HistoricalAssessmentEvidence), String> {
    let source = format!(
        "https://{}/blob/{}/{}",
        candidate.repository,
        selected.commit_sha,
        license_path.unwrap_or("LICENSE")
    );
    let Some(license_path) = license_path else {
        let evidence = artifacts.evidence_json(
            HistoricalEvidenceKind::License,
            source,
            observed_at,
            "license-missing.json",
            &serde_json::json!({"license_path": null}),
        )?;
        return Ok((None, evidence));
    };
    let bytes = fs::read(snapshots.commit.join(license_path))
        .map_err(|error| format!("failed to read historical license {license_path}: {error}"))?;
    let artifact = artifacts.provenance_artifact(
        &format!("license/{license_path}"),
        &bytes,
        format!("tracked license at commit {}", selected.commit_sha),
    )?;
    let evidence = HistoricalAssessmentEvidence {
        kind: HistoricalEvidenceKind::License,
        source,
        observed_at: observed_at.to_string(),
        artifact_path: artifact.artifact_path.clone(),
        sha256: artifact.sha256.clone(),
    };
    Ok((Some(artifact), evidence))
}

pub(super) fn capture_sources(
    artifacts: &RankArtifactWriter,
    candidate: &HistoricalRepositoryCandidate,
    selected: &RankedHistoricalCommit,
    snapshots: &HistoricalSnapshotRoots,
    census: &HistoricalSourceDeltaCensus,
) -> Result<CapturedSources, String> {
    let repository = format!("https://{}", candidate.repository);
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut removed_after_paths = Vec::new();
    for path in &census.production_paths {
        if path.parent_sha256.is_some() {
            let repository_path = path.previous_path.as_deref().unwrap_or(&path.path);
            before.push(artifacts.source_snapshot(
                &snapshots.parent,
                &repository,
                &selected.parent_sha,
                repository_path,
                "before",
            )?);
        }
        if path.commit_sha256.is_some() {
            after.push(artifacts.source_snapshot(
                &snapshots.commit,
                &repository,
                &selected.commit_sha,
                &path.path,
                "after",
            )?);
        } else {
            removed_after_paths.push(path.path.clone());
        }
    }
    Ok(CapturedSources {
        before,
        after,
        removed_after_paths,
    })
}

pub(super) fn apply_census(
    facts: &mut HistoricalRepositoryFacts,
    census: &HistoricalSourceDeltaCensus,
) {
    facts.supported_project_shape = Some(census.supported_project_shape);
    facts.qualifying_production_change = census.qualifying_production_change;
    facts.parent_method_counts = census.parent_method_counts.clone();
    facts.parent_method_count = census.parent_method_count;
    facts.affected_methods = census.affected_methods.clone();
    facts.quota_language = census.quota_language.clone();
    facts.source_non_whitespace_lines_before = census.source_non_whitespace_lines_before;
    facts.source_non_whitespace_lines_after = census.source_non_whitespace_lines_after;
    facts.production_paths = census.production_paths.clone();
    facts.license_path = census.license_path.clone();
}
