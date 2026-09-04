#[cfg(test)]
use super::history_v2_qualification_methods::method_overlaps_hunks;
use super::history_v2_qualification_methods::{
    checked_add_lines, collect_side_methods, production_method_count,
};
use super::history_v2_qualification_roles::classify_snapshot_roles;
use super::history_v2_qualification_surface::public_surface_delta;
use super::non_blind_history_git::changed_paths;
use super::{
    HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION, HistoricalRevisionSide,
    HistoricalV2AssessmentIdentity, HistoricalV2AssessmentIdentityInputs,
    HistoricalV2Qualification, HistoricalV2QualificationExclusionReason,
    HistoricalV2QualificationOutcome, HistoricalV2QualifiedPath, HistoricalV2SelectedPayload,
    HistoricalV2SourceFile, HistoricalV2SourceRole, HistoricalV2SourceRoleDecision,
    HistoricalV2SourceSnapshotCensus, capture_historical_diffs, classify_historical_v2_patch,
    validate_historical_v2_assessment_identity,
    validate_historical_v2_assessment_identity_commitment, validate_historical_v2_protocol,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const QUALIFICATION_CONTRACT: &str = "sniffbench-historical-v2-qualification-v2";

pub fn qualify_historical_v2_assessment(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<HistoricalV2Qualification, String> {
    validate_historical_v2_assessment_identity_commitment(inputs, identity)?;
    qualify_validated(inputs, identity)
}

pub fn validate_historical_v2_qualification_commitment(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<(), String> {
    let expected = qualify_historical_v2_assessment(inputs, identity)?;
    if qualification != &expected {
        return Err("historical-v2 qualification changed".to_string());
    }
    Ok(())
}

pub async fn validate_historical_v2_qualification(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<(), String> {
    validate_historical_v2_assessment_identity(inputs, identity).await?;
    let expected = qualify_validated(inputs, identity)?;
    if qualification != &expected {
        return Err("historical-v2 qualification changed after compiler replay".to_string());
    }
    Ok(())
}

fn qualify_validated(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<HistoricalV2Qualification, String> {
    qualify_evidence(
        &QualificationEvidenceInputs {
            protocol_bytes: inputs.protocol_bytes,
            payloads: inputs.payloads,
            materialization: inputs.materialization,
            materialized_roots: inputs.materialized_roots,
            source_census: inputs.source_census,
            semantic_census: inputs.semantic_census,
        },
        identity,
    )
}

struct QualificationEvidenceInputs<'a> {
    protocol_bytes: &'a [u8],
    payloads: &'a super::HistoricalV2SelectedPayloads,
    materialization: &'a super::HistoricalV2Materialization,
    materialized_roots: &'a super::HistoricalV2MaterializedRoots,
    source_census: &'a super::HistoricalV2SourceCensus,
    semantic_census: &'a super::HistoricalV2SemanticCensus,
}

fn qualify_evidence(
    inputs: &QualificationEvidenceInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<HistoricalV2Qualification, String> {
    let protocol = validate_historical_v2_protocol(inputs.protocol_bytes)?;
    let payload = selected_payload(inputs.payloads, identity)?;
    let patch_facts = classify_historical_v2_patch(&payload.patch)
        .map_err(|reason| format!("historical-v2 selected patch became invalid: {reason:?}"))?;
    if patch_facts.language != identity.language {
        return Err("historical-v2 qualification language changed from its slot".to_string());
    }

    let changed = changed_paths(
        &inputs.materialized_roots.repository_root,
        &inputs.materialization.base_revision,
        &inputs.materialization.patched_commit_oid,
    )?;
    let git_changed_paths = changed
        .iter()
        .filter(|path| path_language(&path.path) == Some(identity.language.as_str()))
        .map(|path| path.path.clone())
        .collect::<Vec<_>>();
    let mut reasons = BTreeSet::new();
    if patch_facts.changed_paths != git_changed_paths {
        reasons.insert(HistoricalV2QualificationExclusionReason::PatchAndGitPathsDisagree);
    }

    let captured = capture_historical_diffs(
        &inputs.materialized_roots.repository_root,
        &inputs.materialization.base_revision,
        &inputs.materialization.patched_commit_oid,
        &changed,
    )?;
    let captured = captured
        .iter()
        .map(|diff| (diff.path.as_str(), diff))
        .collect::<BTreeMap<_, _>>();
    let base_roles = classify_snapshot_roles(
        &inputs.materialized_roots.base_root,
        &inputs.source_census.base,
        &inputs.semantic_census.base,
    )?;
    let patched_roles = classify_snapshot_roles(
        &inputs.materialized_roots.patched_root,
        &inputs.source_census.patched,
        &inputs.semantic_census.patched,
    )?;
    let repository_production_method_count =
        production_method_count(&inputs.source_census.base, &base_roles)?;
    let bounds = &protocol.protocol.selection.repository_method_bounds;
    if repository_production_method_count < bounds.minimum {
        reasons.insert(HistoricalV2QualificationExclusionReason::RepositoryMethodCountBelowMinimum);
    }
    if repository_production_method_count > bounds.maximum {
        reasons.insert(HistoricalV2QualificationExclusionReason::RepositoryMethodCountAboveMaximum);
    }

    let mut qualified_paths = Vec::new();
    let mut changed_methods = BTreeMap::new();
    let mut unresolved_methods = BTreeMap::new();
    let mut before = 0_usize;
    let mut after = 0_usize;
    let mut production_path_count = 0_usize;
    for path in &patch_facts.changed_paths {
        let changed_path = changed.iter().find(|changed| changed.path == *path);
        let previous_path = changed_path
            .and_then(|changed| changed.previous_path.as_deref())
            .unwrap_or(path);
        let base_file = source_file(&inputs.source_census.base, previous_path);
        let patched_file = source_file(&inputs.source_census.patched, path);
        if base_file.is_none() && patched_file.is_none() {
            reasons
                .insert(HistoricalV2QualificationExclusionReason::ChangedSourceMissingFromCensus);
        }
        let base_role = base_file.and_then(|_| base_roles.get(previous_path).copied());
        let patched_role = patched_file.and_then(|_| patched_roles.get(path).copied());
        let production = production_role(base_role, patched_role, &mut reasons);
        let hunks = captured
            .get(path.as_str())
            .map_or_else(Vec::new, |diff| diff.hunks.clone());
        if production {
            production_path_count += 1;
            before = checked_add_lines(before, base_file)?;
            after = checked_add_lines(after, patched_file)?;
            collect_side_methods(
                HistoricalRevisionSide::Parent,
                previous_path,
                base_file,
                &inputs.semantic_census.base,
                &hunks,
                &mut changed_methods,
                &mut unresolved_methods,
            );
            collect_side_methods(
                HistoricalRevisionSide::Commit,
                path,
                patched_file,
                &inputs.semantic_census.patched,
                &hunks,
                &mut changed_methods,
                &mut unresolved_methods,
            );
        }
        qualified_paths.push(HistoricalV2QualifiedPath {
            previous_path: changed_path.and_then(|changed| changed.previous_path.clone()),
            path: path.clone(),
            base_role,
            patched_role,
            production_role_stable: production,
            base_non_whitespace_lines: base_file.map_or(0, |file| file.non_whitespace_lines),
            patched_non_whitespace_lines: patched_file.map_or(0, |file| file.non_whitespace_lines),
            hunks,
        });
    }

    if production_path_count == 0 {
        reasons.insert(HistoricalV2QualificationExclusionReason::NoChangedProductionPaths);
    }
    if !unresolved_methods.is_empty() {
        reasons.insert(HistoricalV2QualificationExclusionReason::ChangedProductionMethodUnresolved);
    }
    if !changed_methods
        .values()
        .any(|method| method.side == HistoricalRevisionSide::Parent)
    {
        reasons.insert(HistoricalV2QualificationExclusionReason::NoChangedBaseProductionMethods);
    }
    if after >= before {
        reasons.insert(HistoricalV2QualificationExclusionReason::NoNetProductionReduction);
    }

    let public_surface = public_surface_delta(
        &inputs.semantic_census.base,
        &inputs.semantic_census.patched,
    )?;
    if !public_surface.preserved {
        reasons.insert(HistoricalV2QualificationExclusionReason::PublicSurfaceChanged);
    }
    let reasons = reasons.into_iter().collect::<Vec<_>>();
    let outcome = if reasons.is_empty() {
        HistoricalV2QualificationOutcome::Qualified
    } else {
        HistoricalV2QualificationOutcome::Excluded { reasons }
    };
    seal_qualification(HistoricalV2Qualification {
        schema_version: HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION,
        qualification_contract: QUALIFICATION_CONTRACT.to_string(),
        assessment_identity_sha256: identity.assessment_identity_sha256.clone(),
        language: identity.language.clone(),
        slot_number: identity.slot_number,
        patch_changed_paths: patch_facts.changed_paths,
        git_changed_paths,
        qualified_paths,
        repository_production_method_count,
        repository_method_minimum: bounds.minimum,
        repository_method_maximum: bounds.maximum,
        changed_methods: changed_methods.into_values().collect(),
        unresolved_changed_methods: unresolved_methods.into_values().collect(),
        production_non_whitespace_lines_before: before,
        production_non_whitespace_lines_after: after,
        public_surface,
        outcome,
        qualification_sha256: String::new(),
    })
}

fn selected_payload<'a>(
    payloads: &'a super::HistoricalV2SelectedPayloads,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<&'a HistoricalV2SelectedPayload, String> {
    payloads
        .records
        .iter()
        .find(|payload| {
            payload.language == identity.language && payload.slot_number == identity.slot_number
        })
        .ok_or_else(|| "historical-v2 qualification payload is absent".to_string())
}

fn source_file<'a>(
    snapshot: &'a HistoricalV2SourceSnapshotCensus,
    path: &str,
) -> Option<&'a HistoricalV2SourceFile> {
    snapshot
        .source_files
        .iter()
        .find(|file| file.repository_path == path)
}

fn production_role(
    base: Option<HistoricalV2SourceRoleDecision>,
    patched: Option<HistoricalV2SourceRoleDecision>,
    reasons: &mut BTreeSet<HistoricalV2QualificationExclusionReason>,
) -> bool {
    let base_production =
        base.map(|decision| decision.role) == Some(HistoricalV2SourceRole::Production);
    let patched_production =
        patched.map(|decision| decision.role) == Some(HistoricalV2SourceRole::Production);
    if base.is_some() && patched.is_some() && base_production != patched_production {
        reasons.insert(HistoricalV2QualificationExclusionReason::ProductionRoleChanged);
        return false;
    }
    base_production || patched_production
}

fn path_language(path: &str) -> Option<&'static str> {
    match path.to_ascii_lowercase().rsplit_once('.')?.1 {
        "go" => Some("go"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        "kt" | "kts" => Some("kotlin"),
        "py" | "pyi" => Some("python"),
        "rs" => Some("rust"),
        "ts" | "tsx" | "mts" | "cts" => Some("typescript"),
        _ => None,
    }
}

fn seal_qualification(
    mut qualification: HistoricalV2Qualification,
) -> Result<HistoricalV2Qualification, String> {
    if !qualification.qualification_sha256.is_empty() {
        return Err("historical-v2 qualification is already sealed".to_string());
    }
    qualification.qualification_sha256 = qualification_sha256(&qualification)?;
    Ok(qualification)
}

fn qualification_sha256(qualification: &HistoricalV2Qualification) -> Result<String, String> {
    let mut committed = qualification.clone();
    committed.qualification_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 qualification: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v2_qualification_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "benchmark_history_v2_qualification_integration_tests.rs"]
mod integration_tests;
