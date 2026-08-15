use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[path = "benchmark_intentional_boundary_source_bundle_artifacts.rs"]
mod artifacts;
use artifacts::*;

#[path = "benchmark_intentional_boundary_source_bundle_material.rs"]
mod material;
use material::*;

const SOURCE_BUNDLE_CONTRACT: &str = "sniffbench-intentional-boundary-source-only-v1";
const REVIEW_ITEM_CONTRACT: &str = "sniffbench-intentional-boundary-review-item-v1";
const SOURCE_REPOSITORY_CONTRACT: &str = "sniffbench-intentional-boundary-source-repository-v1";
const MANIFEST_NAME: &str = "manifest.json";
const SOURCE_BUNDLE_TOTAL_SLOTS: usize = 16;

pub struct IntentionalBoundarySourceMaterial<'a> {
    pub root: &'a Path,
    pub inventory: &'a IntentionalBoundaryRepositoryInventory,
    pub source_census: &'a IntentionalBoundarySourceCensus,
}

pub fn create_intentional_boundary_source_bundle(
    policy_bytes: &[u8],
    protocol: &ValidatedIntentionalBoundaryProtocol,
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
    selection: &IntentionalBoundarySlotSelection,
    materials: &[IntentionalBoundarySourceMaterial<'_>],
    output_root: &Path,
) -> Result<IntentionalBoundarySourceBundle, String> {
    if output_root.exists() {
        return Err(format!(
            "intentional-boundary source bundle already exists: {}",
            output_root.display()
        ));
    }
    let bundle = build_source_bundle(policy_bytes, protocol, task, frame, selection, materials)?;
    let temporary_root = temporary_bundle_root(output_root)?;
    fs::create_dir(&temporary_root).map_err(|error| {
        format!("failed to create temporary intentional-boundary source bundle: {error}")
    })?;
    let result = materialize_bundle(&temporary_root, &bundle, materials).and_then(|()| {
        fs::rename(&temporary_root, output_root).map_err(|error| {
            format!("failed to publish intentional-boundary source bundle: {error}")
        })
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary_root);
    }
    result?;
    validate_intentional_boundary_source_bundle(
        policy_bytes,
        protocol,
        task,
        frame,
        selection,
        materials,
        output_root,
        &bundle,
    )?;
    Ok(bundle)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_source_bundle(
    policy_bytes: &[u8],
    protocol: &ValidatedIntentionalBoundaryProtocol,
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
    selection: &IntentionalBoundarySlotSelection,
    materials: &[IntentionalBoundarySourceMaterial<'_>],
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
) -> Result<(), String> {
    let expected = build_source_bundle(policy_bytes, protocol, task, frame, selection, materials)?;
    if bundle != &expected {
        return Err("intentional-boundary source-only bundle changed".to_string());
    }
    validate_persisted_bundle(bundle_root, bundle)
}

pub fn validate_intentional_boundary_source_bundle_artifacts(
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
) -> Result<(), String> {
    validate_persisted_bundle(bundle_root, bundle)
}

fn build_source_bundle(
    policy_bytes: &[u8],
    protocol: &ValidatedIntentionalBoundaryProtocol,
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
    selection: &IntentionalBoundarySlotSelection,
    materials: &[IntentionalBoundarySourceMaterial<'_>],
) -> Result<IntentionalBoundarySourceBundle, String> {
    validate_intentional_boundary_slot_selection(policy_bytes, protocol, task, frame, selection)?;
    let candidates = frame
        .candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let selected = selection
        .slots
        .iter()
        .filter_map(|slot| match &slot.outcome {
            IntentionalBoundarySlotOutcome::Selected { candidate_id, .. } => Some(candidate_id),
            IntentionalBoundarySlotOutcome::Unfilled { .. } => None,
        })
        .map(|candidate_id| {
            candidates
                .get(candidate_id.as_str())
                .copied()
                .ok_or_else(|| {
                    format!(
                        "intentional-boundary source selection invents candidate {candidate_id}"
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let required_repositories = selected
        .iter()
        .map(|candidate| (candidate.repository.as_str(), candidate.revision.as_str()))
        .collect::<BTreeSet<_>>();
    let material_map = validate_materials(materials, &required_repositories, frame)?;

    let mut repositories = required_repositories
        .iter()
        .map(|&(repository, revision)| {
            let material = material_map
                .get(&(repository, revision))
                .expect("validated source material");
            source_repository(selection, material)
        })
        .collect::<Result<Vec<_>, _>>()?;
    repositories.sort_by(|left, right| left.source_repository_id.cmp(&right.source_repository_id));
    let repositories_by_identity = repositories
        .iter()
        .map(|repository| {
            (
                (repository.repository.as_str(), repository.revision.as_str()),
                repository,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut review_items = selected
        .iter()
        .map(|candidate| {
            let material = material_map
                .get(&(candidate.repository.as_str(), candidate.revision.as_str()))
                .expect("validated source material");
            let repository = repositories_by_identity
                .get(&(candidate.repository.as_str(), candidate.revision.as_str()))
                .expect("validated source repository");
            source_review_item(selection, candidate, material, repository)
        })
        .collect::<Result<Vec<_>, _>>()?;
    review_items.sort_by(|left, right| left.review_item_id.cmp(&right.review_item_id));
    if review_items
        .windows(2)
        .any(|pair| pair[0].review_item_id == pair[1].review_item_id)
    {
        return Err("intentional-boundary source bundle repeated a review item".to_string());
    }

    let mut bundle = IntentionalBoundarySourceBundle {
        schema_version: INTENTIONAL_BOUNDARY_SOURCE_BUNDLE_SCHEMA_VERSION,
        bundle_contract: SOURCE_BUNDLE_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        policy_sha256: task.policy_sha256.clone(),
        frame_task_sha256: task.task_sha256.clone(),
        candidate_frame_sha256: frame.frame_sha256.clone(),
        selection_sha256: selection.selection_sha256.clone(),
        selected_slot_count: selection.selected_candidate_count,
        unfilled_slot_count: selection.unfilled_slot_count,
        repositories,
        review_items,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = bundle_sha256(&bundle)?;
    Ok(bundle)
}

fn source_review_item(
    selection: &IntentionalBoundarySlotSelection,
    candidate: &IntentionalBoundaryCandidate,
    material: &IntentionalBoundarySourceMaterial<'_>,
    repository: &IntentionalBoundarySourceRepository,
) -> Result<IntentionalBoundarySourceReviewItem, String> {
    let source_file = material
        .source_census
        .source_files
        .iter()
        .find(|file| file.repository_path == candidate.repository_path)
        .ok_or_else(|| {
            format!(
                "intentional-boundary selected source disappeared: {}",
                candidate.repository_path
            )
        })?;
    let method = source_file
        .methods
        .iter()
        .find(|method| method.parser_unit_id == candidate.parser_unit_id)
        .ok_or_else(|| {
            format!(
                "intentional-boundary selected method disappeared: {}",
                candidate.repository_path
            )
        })?;
    let source_artifact_path = repository
        .artifacts
        .iter()
        .find(|artifact| artifact.repository_path == candidate.repository_path)
        .and_then(|artifact| artifact.artifact_path.clone())
        .ok_or_else(|| {
            format!(
                "intentional-boundary selected source has no review artifact: {}",
                candidate.repository_path
            )
        })?;
    let review_item_id = format!(
        "ibi-v1:{}",
        hash_json(&(
            REVIEW_ITEM_CONTRACT,
            &selection.selection_sha256,
            &candidate.candidate_id,
        ))?
    );
    Ok(IntentionalBoundarySourceReviewItem {
        review_item_id,
        source_repository_id: repository.source_repository_id.clone(),
        repository: candidate.repository.clone(),
        revision: candidate.revision.clone(),
        repository_path: candidate.repository_path.clone(),
        source_artifact_path,
        language: source_file.language.clone(),
        symbol_name: method.symbol_name.clone(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: method.source_sha256.clone(),
    })
}

fn bundle_sha256(bundle: &IntentionalBoundarySourceBundle) -> Result<String, String> {
    hash_json(&(
        bundle.schema_version,
        &bundle.bundle_contract,
        &bundle.protocol_sha256,
        &bundle.policy_sha256,
        &bundle.frame_task_sha256,
        &bundle.candidate_frame_sha256,
        &bundle.selection_sha256,
        bundle.selected_slot_count,
        bundle.unfilled_slot_count,
        &bundle.repositories,
        &bundle.review_items,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit intentional-boundary source bundle: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_source_bundle_tests.rs"]
mod tests;
