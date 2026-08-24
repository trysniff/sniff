use super::support::{invalid_data, read_json, read_source_bundle, write_json_new};
use crate::benchmark::{
    IntentionalBoundaryLabelAudit, IntentionalBoundaryLabelWorksheet,
    IntentionalBoundaryResolutionWorksheet, ValidatedIntentionalBoundaryProtocol,
    audit_intentional_boundary_label_reviews, inspect_intentional_boundary_label_review_progress,
    prepare_intentional_boundary_label_resolution, prepare_intentional_boundary_label_review,
    resolve_intentional_boundary_labels, validate_intentional_boundary_label_audit,
    validate_intentional_boundary_label_review, validate_intentional_boundary_protocol,
    validate_intentional_boundary_source_bundle_artifacts,
};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn prepare_intentional_boundary_labels(
    bundle_directory: &str,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let (root, bundle) = read_source_bundle(bundle_directory)?;
    let worksheet = prepare_intentional_boundary_label_review(&root, &bundle)
        .map_err(|error| invalid_data("label worksheet cannot be prepared", error))?;
    write_json_new(output_path, &worksheet)?;
    eprintln!(
        "Source-only intentional-boundary worksheet written to {output_path}. Review items: {}. Complete it without Sniff output or another reviewer's labels.",
        worksheet.items.len()
    );
    Ok(0)
}

pub(crate) fn validate_intentional_boundary_labels(
    bundle_directory: &str,
    review_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let (root, bundle) = read_source_bundle(bundle_directory)?;
    let worksheet = read_json::<IntentionalBoundaryLabelWorksheet>(Path::new(review_path))?;
    validate_intentional_boundary_label_review(&root, &bundle, &worksheet)
        .map_err(|error| invalid_data("label worksheet is invalid", error))?;
    let reviewer = worksheet
        .reviewer
        .as_ref()
        .expect("validated intentional-boundary reviewer");
    eprintln!(
        "Verified complete intentional-boundary worksheet {review_path}. Reviewer: {}. Review items: {}.",
        reviewer.reviewer_id,
        worksheet.items.len()
    );
    Ok(0)
}

pub(crate) fn intentional_boundary_label_status(
    bundle_directory: &str,
    review_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let (root, bundle) = read_source_bundle(bundle_directory)?;
    let worksheet = read_json::<IntentionalBoundaryLabelWorksheet>(Path::new(review_path))?;
    let progress = inspect_intentional_boundary_label_review_progress(&root, &bundle, &worksheet)
        .map_err(|error| invalid_data("label worksheet is invalid", error))?;
    println!("{}", serde_json::to_string_pretty(&progress)?);
    Ok(0)
}

pub(crate) struct IntentionalBoundaryLabelInputs<'a> {
    pub policy_path: &'a str,
    pub population_path: &'a str,
    pub blind_seal_path: &'a str,
    pub protocol_path: &'a str,
    pub bundle_directory: &'a str,
    pub review_paths: &'a [String],
}

pub(crate) fn audit_intentional_boundary_labels(
    inputs: IntentionalBoundaryLabelInputs<'_>,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_label_inputs(inputs)?;
    let audit = audit_intentional_boundary_label_reviews(
        &loaded.protocol,
        &loaded.root,
        &loaded.bundle,
        &loaded.worksheets,
    )
    .map_err(|error| invalid_data("label worksheets cannot be audited", error))?;
    write_json_new(output_path, &audit)?;
    eprintln!(
        "Intentional-boundary label audit written to {output_path}. Accepted: {}. Rejected: {}. Disputed: {}. Audit commitment: {}",
        audit.accepted_count, audit.rejected_count, audit.disputed_count, audit.audit_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_intentional_boundary_resolution(
    inputs: IntentionalBoundaryLabelInputs<'_>,
    audit_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_label_inputs(inputs)?;
    let audit = read_json::<IntentionalBoundaryLabelAudit>(Path::new(audit_path))?;
    let resolution = prepare_intentional_boundary_label_resolution(
        &loaded.protocol,
        &loaded.root,
        &loaded.bundle,
        &loaded.worksheets,
        &audit,
    )
    .map_err(|error| invalid_data("label resolution cannot be prepared", error))?;
    write_json_new(output_path, &resolution)?;
    let disputes = resolution
        .items
        .iter()
        .filter(|item| item.decision.is_some())
        .count();
    eprintln!(
        "Intentional-boundary resolution worksheet written to {output_path}. Disputes requiring a distinct resolver: {disputes}."
    );
    Ok(0)
}

pub(crate) fn resolve_intentional_boundary_labels_cli(
    inputs: IntentionalBoundaryLabelInputs<'_>,
    audit_path: &str,
    resolution_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let loaded = load_label_inputs(inputs)?;
    let audit = read_json::<IntentionalBoundaryLabelAudit>(Path::new(audit_path))?;
    validate_intentional_boundary_label_audit(
        &loaded.protocol,
        &loaded.root,
        &loaded.bundle,
        &loaded.worksheets,
        &audit,
    )
    .map_err(|error| invalid_data("label audit is invalid", error))?;
    let resolution =
        read_json::<IntentionalBoundaryResolutionWorksheet>(Path::new(resolution_path))?;
    let final_labels = resolve_intentional_boundary_labels(
        &loaded.protocol,
        &loaded.root,
        &loaded.bundle,
        &loaded.worksheets,
        &audit,
        &resolution,
    )
    .map_err(|error| invalid_data("labels cannot be resolved", error))?;
    write_json_new(output_path, &final_labels)?;
    eprintln!(
        "Immutable intentional-boundary labels written to {output_path}. Accepted: {}. Closed: {}. Unfilled: {}. Final commitment: {}",
        final_labels.accepted_count,
        final_labels.closed_count,
        final_labels.unfilled_slot_count,
        final_labels.final_sha256
    );
    Ok(0)
}

struct LoadedLabelInputs {
    protocol: ValidatedIntentionalBoundaryProtocol,
    root: PathBuf,
    bundle: crate::benchmark::IntentionalBoundarySourceBundle,
    worksheets: Vec<IntentionalBoundaryLabelWorksheet>,
}

fn load_label_inputs(
    inputs: IntentionalBoundaryLabelInputs<'_>,
) -> Result<LoadedLabelInputs, Box<dyn Error>> {
    let policy = fs::read(inputs.policy_path)?;
    let population = fs::read(inputs.population_path)?;
    let blind_seal = fs::read(inputs.blind_seal_path)?;
    let protocol_bytes = fs::read(inputs.protocol_path)?;
    let protocol =
        validate_intentional_boundary_protocol(&policy, &population, &blind_seal, &protocol_bytes)
            .map_err(|error| invalid_data("intentional-boundary protocol is invalid", error))?;
    let (root, bundle) = read_source_bundle(inputs.bundle_directory)?;
    validate_intentional_boundary_source_bundle_artifacts(&root, &bundle)
        .map_err(|error| invalid_data("source-only bundle is invalid", error))?;
    if protocol.protocol_sha256 != bundle.protocol_sha256 {
        return Err(invalid_data(
            "source-only bundle is invalid",
            "bundle is bound to another intentional-boundary protocol",
        )
        .into());
    }
    let worksheets = inputs
        .review_paths
        .iter()
        .map(|path| read_json::<IntentionalBoundaryLabelWorksheet>(Path::new(path)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LoadedLabelInputs {
        protocol,
        root,
        bundle,
        worksheets,
    })
}
