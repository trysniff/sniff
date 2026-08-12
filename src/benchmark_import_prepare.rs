use super::schema::{PreparedOutcome, PreparedRunIdentity};
use crate::benchmark::{BenchmarkCorpus, BenchmarkEvidence, SourceSnapshot};
use crate::completed_run::CompletedRunArtifact;
use crate::product_contract::SlopPattern;
use crate::slop_cases::{CaseEvidence, ProofLevel, SlopCase};
use crate::types::FindingTier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

type SourceGroupKey = (String, String);

pub(super) fn prepare_artifacts(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
    artifact_paths: &[PathBuf],
) -> Result<(PreparedRunIdentity, Vec<PreparedOutcome>), String> {
    let artifacts = artifact_paths
        .iter()
        .map(read_completed_artifact)
        .collect::<Result<Vec<_>, _>>()?;
    let groups = analysis_source_groups(corpus);
    let assignments = assign_artifacts(&artifacts, &groups)?;
    let prepared = prepared_identity(&artifacts, &assignments)?;
    let outcomes = prepared_outcomes(corpus, &artifacts, &assignments, corpus_root)?;
    Ok((prepared, outcomes))
}

pub(super) fn normalize_artifact_paths(
    corpus_root: &Path,
    artifact_paths: &[PathBuf],
) -> Result<Vec<String>, String> {
    let root = fs::canonicalize(corpus_root).map_err(|error| {
        format!(
            "failed to resolve benchmark corpus root {}: {error}",
            corpus_root.display()
        )
    })?;
    let mut normalized = Vec::with_capacity(artifact_paths.len());
    let mut unique = HashSet::with_capacity(artifact_paths.len());
    for artifact_path in artifact_paths {
        let resolved = fs::canonicalize(artifact_path).map_err(|error| {
            format!(
                "failed to resolve completed-run artifact {}: {error}",
                artifact_path.display()
            )
        })?;
        let relative = resolved.strip_prefix(&root).map_err(|_| {
            format!(
                "completed-run artifact {} must be inside the benchmark corpus bundle {}",
                resolved.display(),
                root.display()
            )
        })?;
        let path = relative.to_string_lossy().replace('\\', "/");
        if path.is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "completed-run artifact path is not a safe bundle-relative path: {path}"
            ));
        }
        if !unique.insert(path.clone()) {
            return Err(format!(
                "completed-run artifact is supplied more than once: {path}"
            ));
        }
        normalized.push(path);
    }
    Ok(normalized)
}

fn analysis_source_groups(
    corpus: &BenchmarkCorpus,
) -> BTreeMap<SourceGroupKey, Vec<SourceSnapshot>> {
    let mut groups = BTreeMap::<SourceGroupKey, Vec<SourceSnapshot>>::new();
    for source in &corpus.analysis_sources {
        groups
            .entry((source.repository.clone(), source.revision.clone()))
            .or_default()
            .push(source.clone());
    }
    for sources in groups.values_mut() {
        sources.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    }
    groups
}

fn assign_artifacts(
    artifacts: &[CompletedRunArtifact],
    groups: &BTreeMap<SourceGroupKey, Vec<SourceSnapshot>>,
) -> Result<Vec<SourceGroupKey>, String> {
    if artifacts.len() != groups.len() {
        return Err(format!(
            "benchmark source inventory has {} repository revisions but {} completed artifacts were supplied",
            groups.len(),
            artifacts.len()
        ));
    }
    let mut assigned = HashSet::new();
    let mut result = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let inventory = artifact
            .source_files
            .iter()
            .map(|source| (source.repository_path.as_str(), source.sha256.as_str()))
            .collect::<HashSet<_>>();
        let matches = groups
            .iter()
            .filter(|(_, sources)| {
                let expected = sources
                    .iter()
                    .map(|source| (source.repository_path.as_str(), source.sha256.as_str()))
                    .collect::<HashSet<_>>();
                inventory == expected
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "completed artifact {} matches {} frozen repository revisions; expected exactly one",
                artifact.run_id,
                matches.len()
            ));
        }
        let key = matches[0].clone();
        if !assigned.insert(key.clone()) {
            return Err(format!(
                "multiple completed artifacts match {} at {}",
                key.0, key.1
            ));
        }
        result.push(key);
    }
    Ok(result)
}

fn prepared_identity(
    artifacts: &[CompletedRunArtifact],
    assignments: &[SourceGroupKey],
) -> Result<PreparedRunIdentity, String> {
    let first = artifacts
        .first()
        .ok_or_else(|| "benchmark preparation has no artifacts".to_string())?;
    for artifact in &artifacts[1..] {
        if artifact.sniff_version != first.sniff_version
            || artifact.provider != first.provider
            || artifact.model != first.model
            || artifact.prompt_contract_version != first.prompt_contract_version
        {
            return Err(
                "completed artifacts use different tool/provider/model/prompt contracts"
                    .to_string(),
            );
        }
    }
    let mut revisions = assignments
        .iter()
        .map(|(repository, revision)| format!("{repository}@{revision}"))
        .collect::<Vec<_>>();
    revisions.sort();
    checked_sum_identity(artifacts, revisions.join(";"))
}

fn checked_sum_identity(
    artifacts: &[CompletedRunArtifact],
    source_revision: String,
) -> Result<PreparedRunIdentity, String> {
    let first = &artifacts[0];
    Ok(PreparedRunIdentity {
        tool_version: first.sniff_version.clone(),
        source_revision,
        provider: first.provider.clone(),
        model: first.model.clone(),
        prompt_contract_version: first.prompt_contract_version.clone(),
        completed_artifact_ids: artifacts.iter().map(|item| item.run_id.clone()).collect(),
        execution_commitments_sha256: artifacts
            .iter()
            .map(|item| item.execution_commitment_sha256.clone())
            .collect(),
        cross_scan_reused_units: artifacts.iter().try_fold(0usize, |total, item| {
            total
                .checked_add(item.coverage.cross_scan_reused_units)
                .ok_or_else(|| "benchmark reused-unit count overflowed".to_string())
        })?,
        analyzed_method_count: artifacts.iter().try_fold(0usize, |total, item| {
            total
                .checked_add(item.coverage.methods_completed)
                .ok_or_else(|| "benchmark analyzed-method count overflowed".to_string())
        })?,
        input_tokens: checked_token_sum(artifacts, |item| item.usage.input_tokens)?,
        cached_input_tokens: checked_token_sum(artifacts, |item| item.usage.cached_input_tokens)?,
        output_tokens: checked_token_sum(artifacts, |item| item.usage.output_tokens)?,
    })
}

fn checked_token_sum<F>(artifacts: &[CompletedRunArtifact], field: F) -> Result<u64, String>
where
    F: Fn(&CompletedRunArtifact) -> usize,
{
    artifacts.iter().try_fold(0u64, |total, item| {
        let value = u64::try_from(field(item))
            .map_err(|_| "benchmark token count does not fit u64".to_string())?;
        total
            .checked_add(value)
            .ok_or_else(|| "benchmark token count overflowed".to_string())
    })
}

fn prepared_outcomes(
    corpus: &BenchmarkCorpus,
    artifacts: &[CompletedRunArtifact],
    assignments: &[SourceGroupKey],
    corpus_root: &Path,
) -> Result<Vec<PreparedOutcome>, String> {
    let groups = assignments
        .iter()
        .enumerate()
        .map(|(index, key)| (key, &artifacts[index]))
        .collect::<HashMap<_, _>>();
    let mut outcomes = Vec::new();
    for (key, artifact) in groups {
        let source_map = source_map_for_assignment(corpus, key, artifact, corpus_root)?;
        let mut covered_units = HashSet::new();
        for case in &artifact.report.slop_cases {
            covered_units.extend(case.affected_units.iter().cloned());
            outcomes.push(outcome_from_case(artifact, case, &source_map)?);
        }
        for record in artifact
            .report
            .method_review_records
            .iter()
            .filter(|record| record.verdict.tier == FindingTier::Unresolved)
            .filter(|record| !covered_units.contains(&record.unit_id))
        {
            outcomes.push(PreparedOutcome {
                outcome_id: format!("{}:method:{}", artifact.run_id, record.unit_id),
                finding_fingerprint: None,
                tier: FindingTier::Unresolved,
                pattern: SlopPattern::None.as_str().to_string(),
                mechanism: record.verdict.reason.clone(),
                evidence: Vec::new(),
                proof_level: 0,
            });
        }
    }
    outcomes.sort_by(|left, right| left.outcome_id.cmp(&right.outcome_id));
    let unique = outcomes
        .iter()
        .map(|outcome| outcome.outcome_id.as_str())
        .collect::<HashSet<_>>();
    if unique.len() != outcomes.len() {
        return Err("prepared benchmark outcomes repeat an identity".to_string());
    }
    Ok(outcomes)
}

fn source_map_for_assignment(
    corpus: &BenchmarkCorpus,
    key: &SourceGroupKey,
    artifact: &CompletedRunArtifact,
    corpus_root: &Path,
) -> Result<HashMap<String, (SourceSnapshot, String)>, String> {
    let selected = corpus
        .analysis_sources
        .iter()
        .filter(|source| source.repository == key.0 && source.revision == key.1)
        .collect::<Vec<_>>();
    let artifact_inventory = artifact
        .source_files
        .iter()
        .map(|source| (source.repository_path.as_str(), source.sha256.as_str()))
        .collect::<HashSet<_>>();
    let selected_inventory = selected
        .iter()
        .map(|source| (source.repository_path.as_str(), source.sha256.as_str()))
        .collect::<HashSet<_>>();
    if artifact_inventory != selected_inventory {
        return Err(format!(
            "completed artifact {} no longer matches {} at {}",
            artifact.run_id, key.0, key.1
        ));
    }
    let mut result = HashMap::new();
    for source in selected {
        let path = corpus_root.join(&source.artifact_path);
        let text = fs::read_to_string(&path).map_err(|error| {
            format!(
                "failed to read frozen analysis source {}: {error}",
                path.display()
            )
        })?;
        let actual = format!("{:x}", Sha256::digest(text.as_bytes()));
        if !actual.eq_ignore_ascii_case(&source.sha256) {
            return Err(format!(
                "frozen analysis source {} changed after validation",
                source.artifact_path
            ));
        }
        if result
            .insert(source.repository_path.clone(), (source.clone(), text))
            .is_some()
        {
            return Err(format!(
                "frozen analysis source inventory repeats {}",
                source.repository_path
            ));
        }
    }
    Ok(result)
}

fn outcome_from_case(
    artifact: &CompletedRunArtifact,
    case: &SlopCase,
    source_map: &HashMap<String, (SourceSnapshot, String)>,
) -> Result<PreparedOutcome, String> {
    let evidence = case
        .evidence
        .iter()
        .map(|evidence| benchmark_evidence(evidence, source_map))
        .collect::<Result<Vec<_>, _>>()?;
    if matches!(case.tier, FindingTier::Slop | FindingTier::KindaSlop) && evidence.is_empty() {
        return Err(format!(
            "completed finding {} has no exact source evidence",
            case.case_id
        ));
    }
    Ok(PreparedOutcome {
        outcome_id: format!("{}:case:{}", artifact.run_id, case.case_id),
        finding_fingerprint: matches!(case.tier, FindingTier::Slop | FindingTier::KindaSlop)
            .then(|| sha256_json(case))
            .transpose()?,
        tier: case.tier,
        pattern: case.pattern.as_str().to_string(),
        mechanism: case.mechanism.clone(),
        evidence,
        proof_level: proof_level(case.proof_level),
    })
}

fn benchmark_evidence(
    evidence: &CaseEvidence,
    sources: &HashMap<String, (SourceSnapshot, String)>,
) -> Result<BenchmarkEvidence, String> {
    let normalized = evidence.file_path.replace('\\', "/");
    let (source, text) = sources.get(&normalized).ok_or_else(|| {
        format!(
            "finding evidence references {} outside its completed source inventory",
            evidence.file_path
        )
    })?;
    let lines = text.lines().collect::<Vec<_>>();
    let selected = lines
        .get(evidence.start_line.saturating_sub(1)..evidence.end_line)
        .ok_or_else(|| format!("finding evidence range is outside {}", evidence.file_path))?;
    if evidence.start_line == 0
        || evidence.quote.trim().is_empty()
        || !selected
            .join("\n")
            .contains(&evidence.quote.replace("\r\n", "\n"))
    {
        return Err(format!(
            "finding evidence quote does not match {}:{}-{}",
            evidence.file_path, evidence.start_line, evidence.end_line
        ));
    }
    Ok(BenchmarkEvidence {
        artifact_path: source.artifact_path.clone(),
        source_sha256: source.sha256.clone(),
        start_line: evidence.start_line,
        end_line: evidence.end_line,
        quote: evidence.quote.clone(),
    })
}

fn read_completed_artifact(path: &PathBuf) -> Result<CompletedRunArtifact, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "failed to read completed-run artifact {}: {error}",
            path.display()
        )
    })?;
    let artifact: CompletedRunArtifact = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "failed to parse completed-run artifact {}: {error}",
            path.display()
        )
    })?;
    artifact.verify()?;
    Ok(artifact)
}

fn proof_level(level: ProofLevel) -> u8 {
    match level {
        ProofLevel::P0SourceReasoning => 0,
        ProofLevel::P1CompilerValidated => 1,
        ProofLevel::P2TestsValidated => 2,
        ProofLevel::P3SurfaceValidated => 3,
        ProofLevel::P4DifferentialValidated => 4,
        ProofLevel::P5ClosedWorldValidated => 5,
    }
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize benchmark identity: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
