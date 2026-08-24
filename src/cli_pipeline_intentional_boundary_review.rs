use crate::benchmark::IntentionalBoundaryRankStageJournal;
use crate::benchmark::{
    IntentionalBoundaryCandidateFrame, IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization, IntentionalBoundaryMaterializationError,
    IntentionalBoundaryMaterializationErrorKind, IntentionalBoundaryRankStageArtifact,
    IntentionalBoundaryRankStageError, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySlotOutcome, IntentionalBoundarySourceCensus,
    IntentionalBoundarySourceMaterial, IntentionalBoundaryStoredRankStage,
    ValidatedIntentionalBoundaryProtocol, create_intentional_boundary_source_bundle,
    rematerialize_intentional_boundary_repository, select_intentional_boundary_slots,
    validate_intentional_boundary_candidate_frame, validate_intentional_boundary_frame_task,
    validate_intentional_boundary_materialization, validate_intentional_boundary_protocol,
    validate_intentional_boundary_source_bundle_artifacts,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

#[path = "cli_pipeline_intentional_boundary_review_labels.rs"]
mod labels;
pub(crate) use labels::{
    IntentionalBoundaryLabelInputs, audit_intentional_boundary_labels,
    intentional_boundary_label_status, prepare_intentional_boundary_labels,
    prepare_intentional_boundary_resolution, resolve_intentional_boundary_labels_cli,
    validate_intentional_boundary_labels,
};

#[path = "cli_pipeline_intentional_boundary_review_support.rs"]
mod support;
use support::{
    absolute_path, canonical_path, existing_plain_directory, invalid_data, new_directory_path,
    read_json, read_source_bundle, require_plain_directory,
};

pub(crate) struct IntentionalBoundarySourceBundleInputs<'a> {
    pub policy_path: &'a str,
    pub population_path: &'a str,
    pub blind_seal_path: &'a str,
    pub protocol_path: &'a str,
    pub task_path: &'a str,
    pub frame_path: &'a str,
    pub state_directory: &'a str,
    pub checkout_directory: &'a str,
    pub output_directory: &'a str,
}

pub(crate) fn prepare_intentional_boundary_source_bundle(
    inputs: IntentionalBoundarySourceBundleInputs<'_>,
) -> Result<i32, Box<dyn Error>> {
    let output_root = new_directory_path(inputs.output_directory, "source bundle")?;
    let frozen = load_frozen_inputs(
        inputs.policy_path,
        inputs.population_path,
        inputs.blind_seal_path,
        inputs.protocol_path,
        inputs.task_path,
        inputs.frame_path,
    )?;
    let selected_ranks = selected_ranks(&frozen.frame, &frozen.selection)?;
    let state_root = existing_plain_directory(inputs.state_directory, "rank state")?;
    let checkout_root = inspect_checkout_root(inputs.checkout_directory, &selected_ranks)?;
    reject_overlapping_roots(&state_root, &checkout_root, &output_root)?;
    let recorded = selected_ranks
        .iter()
        .map(|rank| load_recorded_source(&state_root, &frozen.task, *rank))
        .collect::<Result<Vec<_>, _>>()?;
    publish_checkout_root(&checkout_root, &selected_ranks)?;
    let mut prepared = Vec::with_capacity(recorded.len());
    for source in recorded {
        let checkout = checkout_root.join(checkout_name(source.population_rank));
        if checkout.exists() {
            validate_intentional_boundary_materialization(
                &frozen.task,
                &source.materialization,
                &checkout,
            )
            .map_err(materialization_error)?;
        } else {
            rematerialize_intentional_boundary_repository(
                &frozen.task,
                &source.materialization,
                &checkout,
            )
            .map_err(materialization_error)?;
        }
        prepared.push(PreparedSource {
            root: checkout,
            inventory: source.inventory,
            source_census: source.source_census,
        });
    }
    let materials = prepared
        .iter()
        .map(|source| IntentionalBoundarySourceMaterial {
            root: &source.root,
            inventory: &source.inventory,
            source_census: &source.source_census,
        })
        .collect::<Vec<_>>();
    let bundle = create_intentional_boundary_source_bundle(
        &frozen.policy,
        &frozen.protocol,
        &frozen.task,
        &frozen.frame,
        &frozen.selection,
        &materials,
        &output_root,
    )
    .map_err(|error| invalid_data("source-only bundle cannot be created", error))?;
    eprintln!(
        "Intentional-boundary source-only bundle written to {}. Selected slots: {}. Unfilled slots: {}. Repositories: {}. Bundle commitment: {}",
        output_root.display(),
        bundle.selected_slot_count,
        bundle.unfilled_slot_count,
        bundle.repositories.len(),
        bundle.bundle_sha256
    );
    Ok(0)
}

pub(crate) fn validate_intentional_boundary_source_bundle_cli(
    bundle_directory: &str,
) -> Result<i32, Box<dyn Error>> {
    let (root, bundle) = read_source_bundle(bundle_directory)?;
    validate_intentional_boundary_source_bundle_artifacts(&root, &bundle)
        .map_err(|error| invalid_data("source-only bundle is invalid", error))?;
    eprintln!(
        "Verified intentional-boundary source-only bundle {}. Review items: {}. Bundle commitment: {}",
        root.display(),
        bundle.review_items.len(),
        bundle.bundle_sha256
    );
    Ok(0)
}

struct FrozenInputs {
    policy: Vec<u8>,
    protocol: ValidatedIntentionalBoundaryProtocol,
    task: IntentionalBoundaryFrameTask,
    frame: IntentionalBoundaryCandidateFrame,
    selection: crate::benchmark::IntentionalBoundarySlotSelection,
}

fn load_frozen_inputs(
    policy_path: &str,
    population_path: &str,
    blind_seal_path: &str,
    protocol_path: &str,
    task_path: &str,
    frame_path: &str,
) -> Result<FrozenInputs, Box<dyn Error>> {
    let policy = fs::read(policy_path)?;
    let population = fs::read(population_path)?;
    let blind_seal = fs::read(blind_seal_path)?;
    let protocol_bytes = fs::read(protocol_path)?;
    let protocol =
        validate_intentional_boundary_protocol(&policy, &population, &blind_seal, &protocol_bytes)
            .map_err(|error| invalid_data("intentional-boundary protocol is invalid", error))?;
    let task = read_json::<IntentionalBoundaryFrameTask>(Path::new(task_path))?;
    validate_intentional_boundary_frame_task(
        &policy,
        &population,
        &blind_seal,
        &protocol_bytes,
        &task,
    )
    .map_err(|error| invalid_data("intentional-boundary frame task is invalid", error))?;
    let frame = read_json::<IntentionalBoundaryCandidateFrame>(Path::new(frame_path))?;
    validate_intentional_boundary_candidate_frame(&task, &frame)
        .map_err(|error| invalid_data("intentional-boundary candidate frame is invalid", error))?;
    let selection = select_intentional_boundary_slots(&policy, &protocol, &task, &frame)
        .map_err(|error| invalid_data("intentional-boundary slots cannot be selected", error))?;
    Ok(FrozenInputs {
        policy,
        protocol,
        task,
        frame,
        selection,
    })
}

fn selected_ranks(
    frame: &IntentionalBoundaryCandidateFrame,
    selection: &crate::benchmark::IntentionalBoundarySlotSelection,
) -> Result<BTreeSet<usize>, IoError> {
    let candidates = frame
        .candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut ranks = BTreeSet::new();
    for candidate_id in selection
        .slots
        .iter()
        .filter_map(|slot| match &slot.outcome {
            IntentionalBoundarySlotOutcome::Selected { candidate_id, .. } => Some(candidate_id),
            IntentionalBoundarySlotOutcome::Unfilled { .. } => None,
        })
    {
        let candidate = candidates.get(candidate_id.as_str()).ok_or_else(|| {
            invalid_data(
                "intentional-boundary selection is invalid",
                format!("selected candidate {candidate_id} disappeared"),
            )
        })?;
        let rank = frame
            .rank_records
            .iter()
            .find(|record| {
                record.repository_task.repository == candidate.repository
                    && matches!(
                        &record.outcome,
                        crate::benchmark::IntentionalBoundaryFrameRankOutcome::Analyzed {
                            candidate_census,
                            ..
                        } if candidate_census.revision == candidate.revision
                    )
            })
            .map(|record| record.repository_task.population_rank)
            .ok_or_else(|| {
                invalid_data(
                    "intentional-boundary selection is invalid",
                    format!(
                        "selected source {} has no analyzed rank",
                        candidate.repository
                    ),
                )
            })?;
        ranks.insert(rank);
    }
    Ok(ranks)
}

struct RecordedSource {
    population_rank: usize,
    materialization: IntentionalBoundaryMaterialization,
    inventory: IntentionalBoundaryRepositoryInventory,
    source_census: IntentionalBoundarySourceCensus,
}

fn load_recorded_source(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
) -> Result<RecordedSource, IoError> {
    let journal = IntentionalBoundaryRankStageJournal::open(state_root, task, population_rank)
        .map_err(rank_stage_error)?;
    if journal.next_stage().map_err(rank_stage_error)?.is_some() {
        return Err(invalid_data(
            "selected rank journal is incomplete",
            format!("rank {population_rank}"),
        ));
    }
    let materialization = find_artifact(journal.history(), |artifact| match artifact {
        IntentionalBoundaryRankStageArtifact::Materialization(value) => Some(value.clone()),
        _ => None,
    })
    .ok_or_else(|| missing_stage(population_rank, "materialization"))?;
    let inventory = find_artifact(journal.history(), |artifact| match artifact {
        IntentionalBoundaryRankStageArtifact::Inventory(value) => Some(value.clone()),
        _ => None,
    })
    .ok_or_else(|| missing_stage(population_rank, "inventory"))?;
    let source_census = find_artifact(journal.history(), |artifact| match artifact {
        IntentionalBoundaryRankStageArtifact::SourceCensus(value) => {
            Some(value.source_census.clone())
        }
        _ => None,
    })
    .ok_or_else(|| missing_stage(population_rank, "source census"))?;
    Ok(RecordedSource {
        population_rank,
        materialization,
        inventory,
        source_census,
    })
}

fn find_artifact<T>(
    history: &[IntentionalBoundaryStoredRankStage],
    extract: impl Fn(&IntentionalBoundaryRankStageArtifact) -> Option<T>,
) -> Option<T> {
    history.iter().find_map(|stage| extract(&stage.artifact))
}

struct PreparedSource {
    root: PathBuf,
    inventory: IntentionalBoundaryRepositoryInventory,
    source_census: IntentionalBoundarySourceCensus,
}

fn inspect_checkout_root(path: &str, selected_ranks: &BTreeSet<usize>) -> Result<PathBuf, IoError> {
    let root = absolute_path(Path::new(path))?;
    if root.exists() {
        require_plain_directory(&root, "exact checkout root")?;
        validate_checkout_entries(&root, selected_ranks)?;
        canonical_path(&root)
    } else {
        let parent = root
            .parent()
            .ok_or_else(|| invalid_data("exact checkout root is invalid", "path has no parent"))?;
        require_plain_directory(parent, "exact checkout parent")?;
        let parent = canonical_path(parent)?;
        let name = root.file_name().ok_or_else(|| {
            invalid_data("exact checkout root is invalid", "path has no file name")
        })?;
        Ok(parent.join(name))
    }
}

fn publish_checkout_root(root: &Path, selected_ranks: &BTreeSet<usize>) -> Result<(), IoError> {
    if root.exists() {
        require_plain_directory(root, "exact checkout root")?;
        return validate_checkout_entries(root, selected_ranks);
    }
    fs::create_dir(root).map_err(|error| {
        IoError::new(
            error.kind(),
            format!(
                "failed to create exact checkout root {}: {error}",
                root.display()
            ),
        )
    })
}

fn validate_checkout_entries(root: &Path, selected_ranks: &BTreeSet<usize>) -> Result<(), IoError> {
    let expected = selected_ranks
        .iter()
        .map(|rank| checkout_name(*rank))
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            invalid_data("exact checkout root is invalid", "entry name is not UTF-8")
        })?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !expected.contains(&name) || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid_data(
                "exact checkout root is invalid",
                format!("unexpected entry {name}"),
            ));
        }
    }
    Ok(())
}

fn reject_overlapping_roots(
    state_root: &Path,
    checkout_root: &Path,
    output_root: &Path,
) -> Result<(), IoError> {
    let output_parent =
        canonical_path(output_root.parent().ok_or_else(|| {
            invalid_data("source bundle output is invalid", "path has no parent")
        })?)?;
    let output =
        output_parent.join(output_root.file_name().ok_or_else(|| {
            invalid_data("source bundle output is invalid", "path has no file name")
        })?);
    if roots_overlap(state_root, checkout_root)
        || roots_overlap(state_root, &output)
        || roots_overlap(checkout_root, &output)
    {
        return Err(invalid_data(
            "intentional-boundary roots overlap",
            "state, checkout, and output roots must be disjoint",
        ));
    }
    Ok(())
}

fn roots_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn checkout_name(population_rank: usize) -> String {
    format!("rank-{population_rank:04}")
}

fn missing_stage(population_rank: usize, stage: &str) -> IoError {
    invalid_data(
        "selected rank journal is invalid",
        format!("rank {population_rank} has no completed {stage} artifact"),
    )
}

fn rank_stage_error(error: IntentionalBoundaryRankStageError) -> IoError {
    let kind = match error.kind {
        crate::benchmark::IntentionalBoundaryRankStageErrorKind::InvalidInput => {
            ErrorKind::InvalidData
        }
        crate::benchmark::IntentionalBoundaryRankStageErrorKind::InfrastructureUnavailable => {
            ErrorKind::NotFound
        }
        crate::benchmark::IntentionalBoundaryRankStageErrorKind::InfrastructureFailed => {
            ErrorKind::Other
        }
    };
    IoError::new(kind, error.detail)
}

fn materialization_error(error: IntentionalBoundaryMaterializationError) -> IoError {
    let kind = match error.kind {
        IntentionalBoundaryMaterializationErrorKind::InvalidInput => ErrorKind::InvalidData,
        IntentionalBoundaryMaterializationErrorKind::InfrastructureUnavailable => {
            ErrorKind::NotFound
        }
        IntentionalBoundaryMaterializationErrorKind::InfrastructureFailed => ErrorKind::Other,
    };
    IoError::new(kind, error.detail)
}

#[cfg(test)]
#[path = "cli_pipeline_intentional_boundary_review_tests.rs"]
mod tests;
