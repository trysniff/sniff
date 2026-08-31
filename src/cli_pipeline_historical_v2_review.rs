use super::benchmark_run::write_new_file;
use crate::benchmark::{
    HistoricalV2ExclusionManifest, HistoricalV2Frame, HistoricalV2LabelAudit,
    HistoricalV2LabelWorksheet, HistoricalV2ResolutionWorksheet, HistoricalV2SelectedPayloads,
    HistoricalV2SlotSelection, HistoricalV2SourceReviewBundle,
    HistoricalV2SourceReviewBundleInputs, ValidatedHistoricalV2Protocol,
    audit_historical_v2_label_reviews, create_historical_v2_source_review_bundle,
    prepare_historical_v2_label_resolution, prepare_historical_v2_label_review,
    resolve_historical_v2_label, validate_historical_v2_final_label,
    validate_historical_v2_label_audit, validate_historical_v2_label_resolution,
    validate_historical_v2_label_review, validate_historical_v2_protocol,
    validate_historical_v2_source_review_bundle,
};
use serde::de::DeserializeOwned;
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

pub(super) const MAX_PROTOCOL_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_JSON_BYTES: u64 = 512 * 1024 * 1024;
const REVIEW_MANIFEST: &str = "manifest.json";

pub(crate) struct HistoricalV2SourceReviewInputs<'a> {
    pub protocol_path: &'a str,
    pub artifact_root: &'a str,
    pub frame_path: &'a str,
    pub exclusions_path: &'a str,
    pub selection_path: &'a str,
    pub payloads_path: &'a str,
    pub state_root: &'a str,
    pub work_root: &'a str,
    pub harness_repository_root: &'a str,
    pub language: &'a str,
    pub slot_number: usize,
    pub output_directory: &'a str,
}

pub(crate) fn prepare_historical_v2_source_review(
    inputs: HistoricalV2SourceReviewInputs<'_>,
) -> Result<i32, Box<dyn Error>> {
    let protocol_bytes = read_plain_file(
        Path::new(inputs.protocol_path),
        "historical-v2 protocol",
        MAX_PROTOCOL_BYTES,
    )?;
    validate_historical_v2_protocol(&protocol_bytes)
        .map_err(|error| invalid_data("historical-v2 protocol is invalid", error))?;
    let artifact_root = existing_plain_directory(inputs.artifact_root, "artifact root")?;
    let state_root = existing_plain_directory(inputs.state_root, "state root")?;
    let work_root = existing_plain_directory(inputs.work_root, "work root")?;
    let harness_root = existing_plain_directory(
        inputs.harness_repository_root,
        "execution harness repository",
    )?;
    let output_root = new_directory_path(inputs.output_directory, "source review bundle")?;
    reject_overlapping_roots(
        &output_root,
        [&artifact_root, &state_root, &work_root, &harness_root],
    )?;
    let frame =
        read_json::<HistoricalV2Frame>(Path::new(inputs.frame_path), "historical-v2 frame")?;
    let exclusions = read_json::<HistoricalV2ExclusionManifest>(
        Path::new(inputs.exclusions_path),
        "historical-v2 exclusions",
    )?;
    let selection = read_json::<HistoricalV2SlotSelection>(
        Path::new(inputs.selection_path),
        "historical-v2 selection",
    )?;
    let payloads = read_json::<HistoricalV2SelectedPayloads>(
        Path::new(inputs.payloads_path),
        "historical-v2 selected payloads",
    )?;
    let bundle = create_historical_v2_source_review_bundle(
        &HistoricalV2SourceReviewBundleInputs {
            protocol_bytes: &protocol_bytes,
            artifact_root: &artifact_root,
            frame: &frame,
            exclusions: &exclusions,
            selection: &selection,
            payloads: &payloads,
            state_root: &state_root,
            work_root: &work_root,
            harness_repository_root: &harness_root,
            language: inputs.language,
            slot_number: inputs.slot_number,
        },
        &output_root,
    )
    .map_err(|error| invalid_data("historical-v2 source review cannot be prepared", error))?;
    eprintln!(
        "Historical-v2 source-only review bundle written to {}. Language: {}. Slot: {}. Changed methods: {}. Bundle commitment: {}",
        output_root.display(),
        bundle.language,
        inputs.slot_number,
        bundle.changed_methods.len(),
        bundle.bundle_sha256
    );
    Ok(0)
}

pub(crate) fn validate_historical_v2_source_review_cli(
    protocol_path: &str,
    bundle_directory: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_review(protocol_path, bundle_directory)?;
    eprintln!(
        "Verified historical-v2 source-only review bundle {}. Language: {}. Changed methods: {}. Bundle commitment: {}",
        loaded.root.display(),
        loaded.bundle.language,
        loaded.bundle.changed_methods.len(),
        loaded.bundle.bundle_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_historical_v2_labels(
    protocol_path: &str,
    bundle_directory: &str,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_review(protocol_path, bundle_directory)?;
    let worksheet =
        prepare_historical_v2_label_review(&loaded.protocol, &loaded.root, &loaded.bundle)
            .map_err(|error| invalid_data("historical-v2 labels cannot be prepared", error))?;
    write_json_new(output_path, &worksheet)?;
    eprintln!(
        "Source-only historical-v2 worksheet written to {output_path}. Complete it independently without Sniff output, dataset judgments, model assistance, or another reviewer's labels."
    );
    Ok(0)
}

pub(crate) fn validate_historical_v2_labels(
    protocol_path: &str,
    bundle_directory: &str,
    review_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_review(protocol_path, bundle_directory)?;
    let worksheet = read_json::<HistoricalV2LabelWorksheet>(
        Path::new(review_path),
        "historical-v2 label worksheet",
    )?;
    validate_historical_v2_label_review(&loaded.protocol, &loaded.root, &loaded.bundle, &worksheet)
        .map_err(|error| invalid_data("historical-v2 label worksheet is invalid", error))?;
    let reviewer = worksheet
        .reviewer
        .as_ref()
        .expect("validated historical-v2 reviewer");
    eprintln!(
        "Verified complete historical-v2 worksheet {review_path}. Reviewer: {}. Review item: {}.",
        reviewer.reviewer_id, worksheet.task.review_item_id
    );
    Ok(0)
}

pub(crate) struct HistoricalV2LabelInputs<'a> {
    pub protocol_path: &'a str,
    pub bundle_directory: &'a str,
    pub review_paths: &'a [String],
}

pub(crate) fn audit_historical_v2_labels(
    inputs: HistoricalV2LabelInputs<'_>,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_label_inputs(inputs)?;
    let audit = audit_historical_v2_label_reviews(
        &loaded.review.protocol,
        &loaded.review.root,
        &loaded.review.bundle,
        &loaded.worksheets,
    )
    .map_err(|error| invalid_data("historical-v2 labels cannot be audited", error))?;
    write_json_new(output_path, &audit)?;
    eprintln!(
        "Historical-v2 label audit written to {output_path}. Status: {:?}. Audit commitment: {}",
        audit.status, audit.audit_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_historical_v2_resolution(
    inputs: HistoricalV2LabelInputs<'_>,
    audit_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_label_inputs(inputs)?;
    let audit =
        read_json::<HistoricalV2LabelAudit>(Path::new(audit_path), "historical-v2 label audit")?;
    let resolution = prepare_historical_v2_label_resolution(
        &loaded.review.protocol,
        &loaded.review.root,
        &loaded.review.bundle,
        &loaded.worksheets,
        &audit,
    )
    .map_err(|error| invalid_data("historical-v2 resolution cannot be prepared", error))?;
    write_json_new(output_path, &resolution)?;
    eprintln!(
        "Historical-v2 resolution worksheet written to {output_path}. Distinct resolver required: {}.",
        resolution.item.decision.is_some()
    );
    Ok(0)
}

pub(crate) fn resolve_historical_v2_labels_cli(
    inputs: HistoricalV2LabelInputs<'_>,
    audit_path: &str,
    resolution_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_label_inputs(inputs)?;
    let audit =
        read_json::<HistoricalV2LabelAudit>(Path::new(audit_path), "historical-v2 label audit")?;
    validate_historical_v2_label_audit(
        &loaded.review.protocol,
        &loaded.review.root,
        &loaded.review.bundle,
        &loaded.worksheets,
        &audit,
    )
    .map_err(|error| invalid_data("historical-v2 label audit is invalid", error))?;
    let resolution = read_json::<HistoricalV2ResolutionWorksheet>(
        Path::new(resolution_path),
        "historical-v2 label resolution",
    )?;
    validate_historical_v2_label_resolution(
        &loaded.review.protocol,
        &loaded.review.root,
        &loaded.review.bundle,
        &loaded.worksheets,
        &audit,
        &resolution,
    )
    .map_err(|error| invalid_data("historical-v2 label resolution is invalid", error))?;
    let label = resolve_historical_v2_label(
        &loaded.review.protocol,
        &loaded.review.root,
        &loaded.review.bundle,
        &loaded.worksheets,
        &audit,
        &resolution,
    )
    .map_err(|error| invalid_data("historical-v2 label cannot be resolved", error))?;
    validate_historical_v2_final_label(
        &loaded.review.protocol,
        &loaded.review.root,
        &loaded.review.bundle,
        &loaded.worksheets,
        &audit,
        &resolution,
        &label,
    )
    .map_err(|error| invalid_data("historical-v2 final label is invalid", error))?;
    write_json_new(output_path, &label)?;
    eprintln!(
        "Immutable historical-v2 final label written to {output_path}. Outcome: {:?}. Final commitment: {}",
        label.outcome, label.final_sha256
    );
    Ok(0)
}

pub(super) struct LoadedReview {
    pub(super) protocol: ValidatedHistoricalV2Protocol,
    pub(super) root: PathBuf,
    pub(super) bundle: HistoricalV2SourceReviewBundle,
}

struct LoadedLabelInputs {
    review: LoadedReview,
    worksheets: Vec<HistoricalV2LabelWorksheet>,
}

fn load_label_inputs(
    inputs: HistoricalV2LabelInputs<'_>,
) -> Result<LoadedLabelInputs, Box<dyn Error>> {
    let review = load_review(inputs.protocol_path, inputs.bundle_directory)?;
    let worksheets = inputs
        .review_paths
        .iter()
        .map(|path| {
            read_json::<HistoricalV2LabelWorksheet>(
                Path::new(path),
                "historical-v2 label worksheet",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LoadedLabelInputs { review, worksheets })
}

pub(super) fn load_review(
    protocol_path: &str,
    bundle_directory: &str,
) -> Result<LoadedReview, Box<dyn Error>> {
    let protocol_bytes = read_plain_file(
        Path::new(protocol_path),
        "historical-v2 protocol",
        MAX_PROTOCOL_BYTES,
    )?;
    let protocol = validate_historical_v2_protocol(&protocol_bytes)
        .map_err(|error| invalid_data("historical-v2 protocol is invalid", error))?;
    let root = existing_plain_directory(bundle_directory, "source review bundle")?;
    let bundle = read_json::<HistoricalV2SourceReviewBundle>(
        &root.join(REVIEW_MANIFEST),
        "historical-v2 source review manifest",
    )?;
    validate_historical_v2_source_review_bundle(&root, &bundle)
        .map_err(|error| invalid_data("historical-v2 source review is invalid", error))?;
    if protocol.protocol_sha256 != bundle.protocol_sha256 {
        return Err(invalid_data(
            "historical-v2 source review is invalid",
            "bundle is bound to another protocol",
        )
        .into());
    }
    Ok(LoadedReview {
        protocol,
        root,
        bundle,
    })
}

pub(super) fn read_json<T: DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<T, Box<dyn Error>> {
    let bytes = read_plain_file(path, label, MAX_JSON_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(&format!("{label} is invalid"), error).into())
}

pub(super) fn read_plain_file(
    path: &Path,
    label: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, IoError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_data(label, "expected a plain file"));
    }
    if metadata.len() > maximum_bytes {
        return Err(invalid_data(
            label,
            format!("file exceeds the {maximum_bytes}-byte limit"),
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read {label} {}: {error}", path.display()),
        )
    })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid_data(label, "file changed while it was read"));
    }
    Ok(bytes)
}

pub(super) fn existing_plain_directory(path: &str, label: &str) -> Result<PathBuf, IoError> {
    let input = Path::new(path);
    require_plain_directory(input, label)?;
    let canonical = fs::canonicalize(input).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to resolve {label} {path}: {error}"),
        )
    })?;
    require_plain_directory(&canonical, label)?;
    normalize_platform_path(canonical)
}

pub(super) fn require_plain_directory(path: &Path, label: &str) -> Result<(), IoError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_data(label, "expected a plain directory"));
    }
    Ok(())
}

fn new_directory_path(path: &str, label: &str) -> Result<PathBuf, IoError> {
    let requested = normalize_platform_path(std::path::absolute(path)?)?;
    if requested.exists() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            format!("{label} already exists: {}", requested.display()),
        ));
    }
    let parent = requested
        .parent()
        .ok_or_else(|| invalid_data(label, "path has no parent"))?;
    require_plain_directory(parent, &format!("{label} parent"))?;
    let parent = normalize_platform_path(fs::canonicalize(parent)?)?;
    require_plain_directory(&parent, &format!("{label} parent"))?;
    let file_name = requested
        .file_name()
        .ok_or_else(|| invalid_data(label, "path has no final component"))?;
    let resolved = parent.join(file_name);
    if resolved.exists() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            format!("{label} already exists: {}", resolved.display()),
        ));
    }
    Ok(resolved)
}

fn reject_overlapping_roots<'a>(
    output: &Path,
    inputs: impl IntoIterator<Item = &'a PathBuf>,
) -> Result<(), IoError> {
    for input in inputs {
        if output.starts_with(input) || input.starts_with(output) {
            return Err(invalid_data(
                "historical-v2 source review roots overlap",
                format!("{} and {}", output.display(), input.display()),
            ));
        }
    }
    Ok(())
}

fn write_json_new(path: &str, value: &impl serde::Serialize) -> Result<(), Box<dyn Error>> {
    write_new_file(Path::new(path), &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub(super) fn invalid_data(context: &str, detail: impl std::fmt::Display) -> IoError {
    IoError::new(ErrorKind::InvalidData, format!("{context}: {detail}"))
}

#[cfg(windows)]
fn normalize_platform_path(path: PathBuf) -> Result<PathBuf, IoError> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid_data("Windows path is invalid", "path is not UTF-8"))?;
    if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{unc}")));
    }
    if let Some(local) = value.strip_prefix(r"\\?\") {
        return Ok(PathBuf::from(local));
    }
    Ok(path)
}

#[cfg(not(windows))]
fn normalize_platform_path(path: PathBuf) -> Result<PathBuf, IoError> {
    Ok(path)
}

#[cfg(test)]
#[path = "cli_pipeline_historical_v2_review_tests.rs"]
mod tests;
