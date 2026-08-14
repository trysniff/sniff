use super::non_blind_history_artifacts::RankArtifactWriter;
use super::non_blind_history_assessment::{
    derive_historical_exclusion, derive_historical_source_exclusion,
};
use super::non_blind_history_candidate_evidence::{
    DiffEvidence, SourceDeltaEvidence, apply_census, capture_license, capture_sources,
};
use super::non_blind_history_candidate_support::{
    InaccessibleProbe, RepositoryRefsEvidence, base_facts, cleanup_rank_work, facts_from_discovery,
    observation_timestamp, probe_inaccessible, provenance_id, remove_generated_rank_work,
};
use super::non_blind_history_candidate_test::{apply_recipe, apply_test_execution};
use super::{
    HistoricalAssessmentDisposition, HistoricalAssessmentEvidence, HistoricalCloneOutcome,
    HistoricalEvidenceKind, HistoricalExclusionReason, HistoricalRepositoryAssessment,
    HistoricalRepositoryCandidate, HistoricalRepositoryFacts, HistoricalSelectedProvenance,
    HistoricalTestOutcome, HistoricalTestRecipeStatus, NonBlindSelectionPolicy,
    capture_historical_diffs, census_historical_source_delta, discover_historical_test_recipe,
    inspect_historical_git_repository, materialize_historical_snapshots, run_historical_test,
};
use reqwest::Client;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub(super) trait HistoricalRepositoryCloner {
    fn clone_repository(
        &self,
        repository: &str,
        destination: &Path,
    ) -> Result<HistoricalCloneOutcome, String>;
}

pub(super) struct NetworkHistoricalCloner;

impl HistoricalRepositoryCloner for NetworkHistoricalCloner {
    fn clone_repository(
        &self,
        repository: &str,
        destination: &Path,
    ) -> Result<HistoricalCloneOutcome, String> {
        super::clone_complete_historical_repository(repository, destination)
    }
}

pub(super) struct CandidateRuntime<'a, C> {
    pub(super) policy: &'a NonBlindSelectionPolicy,
    pub(super) state_root: &'a Path,
    pub(super) work_root: &'a Path,
    pub(super) selected_counts: &'a BTreeMap<String, usize>,
    pub(super) http: &'a Client,
    pub(super) cloner: &'a C,
}

pub(super) struct PendingHistoricalAssessment {
    pub(super) assessment: HistoricalRepositoryAssessment,
    artifacts: RankArtifactWriter,
}

impl PendingHistoricalAssessment {
    pub(super) fn publish(self, task_sha256: &str) -> Result<(), String> {
        self.artifacts.publish(task_sha256, &self.assessment)
    }
}

pub(super) async fn assess_candidate<C: HistoricalRepositoryCloner>(
    runtime: &CandidateRuntime<'_, C>,
    candidate: &HistoricalRepositoryCandidate,
) -> Result<PendingHistoricalAssessment, String> {
    let observed_at = observation_timestamp()?;
    let artifacts =
        RankArtifactWriter::create(runtime.state_root, runtime.work_root, candidate.rank)?;
    let rank_work = runtime
        .work_root
        .join(format!("rank-{:04}", candidate.rank));
    remove_generated_rank_work(runtime.work_root, &rank_work)?;
    fs::create_dir(&rank_work).map_err(|error| {
        format!(
            "failed to create historical rank work {}: {error}",
            rank_work.display()
        )
    })?;
    let repository_root = rank_work.join("repository");
    let clone = runtime
        .cloner
        .clone_repository(&candidate.repository, &repository_root);
    let pending = match clone {
        Ok(HistoricalCloneOutcome::Empty) => assess_empty(candidate, artifacts, &observed_at),
        Ok(HistoricalCloneOutcome::Complete) => assess_complete(
            runtime,
            candidate,
            artifacts,
            &observed_at,
            &repository_root,
            &rank_work,
        ),
        Err(clone_error) => match probe_inaccessible(runtime.http, &candidate.repository).await? {
            Some(probe) => assess_inaccessible(candidate, artifacts, &observed_at, &probe),
            None => Err(clone_error),
        },
    };
    let cleanup = cleanup_rank_work(runtime.work_root, &rank_work, &repository_root);
    match (pending, cleanup) {
        (Ok(pending), Ok(())) => Ok(pending),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup also failed: {cleanup}")),
    }
}

fn assess_empty(
    candidate: &HistoricalRepositoryCandidate,
    artifacts: RankArtifactWriter,
    observed_at: &str,
) -> Result<PendingHistoricalAssessment, String> {
    let facts = base_facts(&candidate.repository, true, true);
    let refs = RepositoryRefsEvidence {
        repository: &candidate.repository,
        state: "empty",
        discovery: None,
        inaccessible_probe: None,
    };
    let evidence = vec![artifacts.evidence_json(
        HistoricalEvidenceKind::RepositoryRefs,
        format!("https://{}", candidate.repository),
        observed_at,
        "repository-refs.json",
        &refs,
    )?];
    finish_candidate(
        candidate,
        facts,
        evidence,
        None,
        artifacts,
        Some(HistoricalExclusionReason::EmptyRepository),
    )
}

fn assess_inaccessible(
    candidate: &HistoricalRepositoryCandidate,
    artifacts: RankArtifactWriter,
    observed_at: &str,
    probe: &InaccessibleProbe,
) -> Result<PendingHistoricalAssessment, String> {
    let facts = base_facts(&candidate.repository, false, false);
    let refs = RepositoryRefsEvidence {
        repository: &candidate.repository,
        state: "inaccessible",
        discovery: None,
        inaccessible_probe: Some(probe),
    };
    let evidence = vec![artifacts.evidence_json(
        HistoricalEvidenceKind::RepositoryRefs,
        &probe.url,
        observed_at,
        "repository-refs.json",
        &refs,
    )?];
    finish_candidate(
        candidate,
        facts,
        evidence,
        None,
        artifacts,
        Some(HistoricalExclusionReason::Inaccessible),
    )
}

fn assess_complete<C: HistoricalRepositoryCloner>(
    runtime: &CandidateRuntime<'_, C>,
    candidate: &HistoricalRepositoryCandidate,
    artifacts: RankArtifactWriter,
    observed_at: &str,
    repository_root: &Path,
    rank_work: &Path,
) -> Result<PendingHistoricalAssessment, String> {
    let discovery =
        inspect_historical_git_repository(runtime.policy, &candidate.repository, repository_root)?;
    let mut facts = facts_from_discovery(&discovery);
    let mut evidence = vec![artifacts.evidence_json(
        HistoricalEvidenceKind::RepositoryRefs,
        format!("https://{}", candidate.repository),
        observed_at,
        "repository-refs.json",
        &RepositoryRefsEvidence {
            repository: &candidate.repository,
            state: "complete",
            discovery: Some(&discovery),
            inaccessible_probe: None,
        },
    )?];
    evidence.push(artifacts.evidence_json(
        HistoricalEvidenceKind::CommitMetadata,
        format!(
            "https://{}/commits/{}",
            candidate.repository, discovery.default_branch_head
        ),
        observed_at,
        "commit-metadata.json",
        &discovery,
    )?);
    let Some(selected) = discovery.selected_commit.as_ref() else {
        return finish_candidate(
            candidate,
            facts,
            evidence,
            None,
            artifacts,
            Some(HistoricalExclusionReason::NoMatchingCommit),
        );
    };

    let snapshot_root = rank_work.join("snapshots");
    let snapshots = materialize_historical_snapshots(
        repository_root,
        &selected.parent_sha,
        &selected.commit_sha,
        &snapshot_root,
    )?;
    let diffs = capture_historical_diffs(
        repository_root,
        &selected.parent_sha,
        &selected.commit_sha,
        &selected.changed_paths,
    )?;
    let hunks = diffs
        .iter()
        .flat_map(|diff| diff.hunks.iter().cloned())
        .collect::<Vec<_>>();
    let census = census_historical_source_delta(
        &selected.parent_sha,
        &selected.commit_sha,
        &snapshots.parent,
        &snapshots.commit,
        &hunks,
    )?;
    apply_census(&mut facts, &census);
    evidence.push(artifacts.evidence_json(
        HistoricalEvidenceKind::SourceCensus,
        "sniffbench-historical-source-census-v1",
        observed_at,
        "source-census.json",
        &census,
    )?);
    let mut diff_evidence = Vec::new();
    for (index, diff) in diffs.into_iter().enumerate() {
        let artifact =
            artifacts.write_bytes(&format!("diffs/{:04}.patch", index + 1), &diff.bytes)?;
        diff_evidence.push(DiffEvidence {
            previous_path: diff.previous_path,
            path: diff.path,
            artifact_path: artifact.artifact_path,
            sha256: artifact.sha256,
            hunks: diff.hunks,
        });
    }
    evidence.push(artifacts.evidence_json(
        HistoricalEvidenceKind::SourceDelta,
        format!(
            "https://{}/compare/{}...{}",
            candidate.repository, selected.parent_sha, selected.commit_sha
        ),
        observed_at,
        "source-delta.json",
        &SourceDeltaEvidence {
            parent_revision: &selected.parent_sha,
            commit_revision: &selected.commit_sha,
            diffs: diff_evidence,
            census: &census,
        },
    )?);

    let (license, license_evidence) = capture_license(
        &artifacts,
        candidate,
        selected,
        &snapshots,
        census.license_path.as_deref(),
        observed_at,
    )?;
    evidence.push(license_evidence);
    if let Some(reason) = derive_historical_source_exclusion(&facts, runtime.policy)? {
        return finish_candidate(candidate, facts, evidence, None, artifacts, Some(reason));
    }

    let captured_sources = capture_sources(&artifacts, candidate, selected, &snapshots, &census)?;
    let recipe = discover_historical_test_recipe(&snapshots.parent, &snapshots.commit)?;
    evidence.push(artifacts.evidence_json(
        HistoricalEvidenceKind::TestRecipe,
        "sniffbench-non-blind-history-assessment-v1/test_recipe",
        observed_at,
        "test-recipe.json",
        &recipe,
    )?);
    apply_recipe(&mut facts, &recipe);
    if recipe.status != HistoricalTestRecipeStatus::Selected {
        let exclusion =
            derive_historical_exclusion(&facts, runtime.policy, runtime.selected_counts)?;
        return finish_candidate(candidate, facts, evidence, None, artifacts, exclusion);
    }
    let test_command = recipe
        .command
        .as_ref()
        .ok_or_else(|| "selected historical recipe has no command".to_string())?;

    let parent_execution = run_historical_test(
        &snapshots.parent,
        &selected.parent_sha,
        &recipe.preparation_commands,
        test_command,
    )?;
    let parent_artifact = apply_test_execution(
        &artifacts,
        &mut facts,
        &mut evidence,
        observed_at,
        "parent",
        HistoricalEvidenceKind::ParentTest,
        parent_execution,
    )?;
    if facts.test_outcome.is_some() {
        let exclusion =
            derive_historical_exclusion(&facts, runtime.policy, runtime.selected_counts)?;
        return finish_candidate(candidate, facts, evidence, None, artifacts, exclusion);
    }

    let commit_execution = run_historical_test(
        &snapshots.commit,
        &selected.commit_sha,
        &recipe.preparation_commands,
        test_command,
    )?;
    let commit_artifact = apply_test_execution(
        &artifacts,
        &mut facts,
        &mut evidence,
        observed_at,
        "commit",
        HistoricalEvidenceKind::CommitTest,
        commit_execution,
    )?;
    if facts.test_outcome.is_none() {
        facts.test_outcome = Some(HistoricalTestOutcome::Passed);
    }
    let exclusion = derive_historical_exclusion(&facts, runtime.policy, runtime.selected_counts)?;
    let provenance = if exclusion.is_none() {
        Some(HistoricalSelectedProvenance {
            provenance_id: provenance_id(&candidate.repository, &selected.commit_sha),
            upstream_url: format!("https://{}", candidate.repository),
            upstream_revision: selected.commit_sha.clone(),
            upstream_record_id: selected.commit_sha.clone(),
            before: captured_sources.before,
            after: captured_sources.after,
            removed_after_paths: captured_sources.removed_after_paths,
            license: license
                .ok_or_else(|| "selected historical source lost its license".to_string())?,
            behavioral_evidence: vec![
                parent_artifact.ok_or_else(|| {
                    "selected historical source lost parent test evidence".to_string()
                })?,
                commit_artifact.ok_or_else(|| {
                    "selected historical source lost commit test evidence".to_string()
                })?,
            ],
        })
    } else {
        None
    };
    finish_candidate(candidate, facts, evidence, provenance, artifacts, exclusion)
}

fn finish_candidate(
    candidate: &HistoricalRepositoryCandidate,
    facts: HistoricalRepositoryFacts,
    evidence: Vec<HistoricalAssessmentEvidence>,
    selected_provenance: Option<HistoricalSelectedProvenance>,
    artifacts: RankArtifactWriter,
    exclusion: Option<HistoricalExclusionReason>,
) -> Result<PendingHistoricalAssessment, String> {
    let disposition = if exclusion.is_some() {
        HistoricalAssessmentDisposition::Excluded
    } else {
        HistoricalAssessmentDisposition::Selected
    };
    if disposition == HistoricalAssessmentDisposition::Selected && selected_provenance.is_none() {
        return Err("historical candidate reached selection without sealed provenance".to_string());
    }
    Ok(PendingHistoricalAssessment {
        assessment: HistoricalRepositoryAssessment {
            candidate: candidate.clone(),
            facts: Some(facts),
            evidence,
            disposition: Some(disposition),
            exclusion_reason: exclusion,
            selected_provenance,
        },
        artifacts,
    })
}
