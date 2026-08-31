use super::historical_v2_review::{
    MAX_PROTOCOL_BYTES, existing_plain_directory, invalid_data, load_review, read_json,
    read_plain_file, require_plain_directory,
};
use crate::benchmark::{
    HistoricalV2CorpusBundleInputs, HistoricalV2ExclusionManifest, HistoricalV2FinalLabel,
    HistoricalV2Frame, HistoricalV2LabelAudit, HistoricalV2LabelWorksheet,
    HistoricalV2ReleaseGateInputs, HistoricalV2ResolutionWorksheet,
    HistoricalV2ReviewedSlotArtifacts, HistoricalV2SlotSelection, HistoricalV2SourceReviewBundle,
    ValidatedHistoricalV2Protocol, build_historical_v2_release_evidence,
    create_historical_v2_corpus_bundle, load_historical_v2_corpus_bundle,
    load_historical_v2_release_evidence, validate_historical_v2_final_label,
    validate_historical_v2_protocol, validate_historical_v2_release_evidence,
    write_historical_v2_release_evidence,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Component, Path, PathBuf};

const REVIEWS_DIRECTORY: &str = "reviews";
const LABELS_DIRECTORY: &str = "labels";
const REVIEW_A: &str = "review-a.json";
const REVIEW_B: &str = "review-b.json";
const AUDIT: &str = "audit.json";
const RESOLUTION: &str = "resolution.json";
const FINAL_LABEL: &str = "final-label.json";
const LABEL_FILES: [&str; 5] = [REVIEW_A, REVIEW_B, AUDIT, RESOLUTION, FINAL_LABEL];

pub(crate) struct HistoricalV2AggregateInputs<'a> {
    pub protocol_path: &'a str,
    pub artifact_root: &'a str,
    pub frame_path: &'a str,
    pub exclusions_path: &'a str,
    pub selection_path: &'a str,
    pub state_root: &'a str,
    pub corpus_root: &'a str,
    pub evidence_path: &'a str,
}

pub(crate) struct HistoricalV2CorpusPublishInputs<'a> {
    pub aggregate: HistoricalV2AggregateInputs<'a>,
    pub output_path: &'a str,
}

pub(crate) fn build_historical_v2_release_evidence_cli(
    inputs: HistoricalV2AggregateInputs<'_>,
) -> Result<i32, Box<dyn Error>> {
    let loaded = LoadedAggregate::load(&inputs)?;
    let output = new_file_under_root(
        &loaded.corpus_root,
        Path::new(inputs.evidence_path),
        "historical-v2 release evidence",
    )?;
    let evidence = loaded.with_gate(build_historical_v2_release_evidence)?;
    loaded.with_gate(|gate| write_historical_v2_release_evidence(gate, &evidence, &output))?;
    eprintln!(
        "Historical-v2 release evidence written to {}. Status: {:?}. Accepted: {}. Execution-excluded: {}. Review-closed: {}. Evidence commitment: {}",
        output.display(),
        evidence.status,
        evidence.accepted_count,
        evidence.execution_excluded_count,
        evidence.review_closed_count,
        evidence.evidence_sha256
    );
    Ok(0)
}

pub(crate) fn validate_historical_v2_release_evidence_cli(
    inputs: HistoricalV2AggregateInputs<'_>,
) -> Result<i32, Box<dyn Error>> {
    let loaded = LoadedAggregate::load(&inputs)?;
    let evidence_path = existing_file_under_root(
        &loaded.corpus_root,
        Path::new(inputs.evidence_path),
        "historical-v2 release evidence",
    )?;
    let evidence = load_historical_v2_release_evidence(&loaded.protocol_bytes, &evidence_path)
        .map_err(|error| invalid_data("historical-v2 release evidence is invalid", error))?;
    loaded
        .with_gate(|gate| validate_historical_v2_release_evidence(gate, &evidence))
        .map_err(|error| invalid_data("historical-v2 release evidence is invalid", error))?;
    eprintln!(
        "Verified historical-v2 release evidence {}. Status: {:?}. Accepted: {}. Evidence commitment: {}",
        evidence_path.display(),
        evidence.status,
        evidence.accepted_count,
        evidence.evidence_sha256
    );
    Ok(0)
}

pub(crate) fn publish_historical_v2_corpus_cli(
    inputs: HistoricalV2CorpusPublishInputs<'_>,
) -> Result<i32, Box<dyn Error>> {
    let loaded = LoadedAggregate::load(&inputs.aggregate)?;
    let evidence_path = existing_file_under_root(
        &loaded.corpus_root,
        Path::new(inputs.aggregate.evidence_path),
        "historical-v2 release evidence",
    )?;
    let output = new_file_under_root(
        &loaded.corpus_root,
        Path::new(inputs.output_path),
        "historical-v2 corpus bundle",
    )?;
    let evidence = load_historical_v2_release_evidence(&loaded.protocol_bytes, &evidence_path)
        .map_err(|error| invalid_data("historical-v2 release evidence is invalid", error))?;
    let bundle = loaded.with_gate(|gate| {
        create_historical_v2_corpus_bundle(
            &HistoricalV2CorpusBundleInputs {
                gate_inputs: gate,
                release_evidence: &evidence,
                corpus_root: &loaded.corpus_root,
                release_evidence_path: &evidence_path,
            },
            &output,
        )
    })?;
    eprintln!(
        "Immutable historical-v2 corpus bundle written to {}. Accepted cases: {}. Bundle commitment: {}",
        output.display(),
        bundle.accepted_count,
        bundle.bundle_sha256
    );
    Ok(0)
}

pub(crate) fn validate_historical_v2_corpus_cli(
    protocol_path: &str,
    corpus_root: &str,
    bundle_path: &str,
) -> Result<i32, Box<dyn Error>> {
    let protocol_bytes = read_plain_file(
        Path::new(protocol_path),
        "historical-v2 protocol",
        MAX_PROTOCOL_BYTES,
    )?;
    validate_historical_v2_protocol(&protocol_bytes)
        .map_err(|error| invalid_data("historical-v2 protocol is invalid", error))?;
    let corpus_root = existing_plain_directory(corpus_root, "historical-v2 corpus root")?;
    let bundle_path = existing_file_under_root(
        &corpus_root,
        Path::new(bundle_path),
        "historical-v2 corpus bundle",
    )?;
    let bundle = load_historical_v2_corpus_bundle(&protocol_bytes, &corpus_root, &bundle_path)
        .map_err(|error| invalid_data("historical-v2 corpus bundle is invalid", error))?;
    eprintln!(
        "Verified historical-v2 corpus bundle {}. Accepted cases: {}. Bundle commitment: {}",
        bundle_path.display(),
        bundle.accepted_count,
        bundle.bundle_sha256
    );
    Ok(0)
}

struct LoadedAggregate {
    protocol_bytes: Vec<u8>,
    artifact_root: PathBuf,
    frame: HistoricalV2Frame,
    exclusions: HistoricalV2ExclusionManifest,
    selection: HistoricalV2SlotSelection,
    state_root: PathBuf,
    corpus_root: PathBuf,
    reviewed: Vec<LoadedReviewedSlot>,
}

impl LoadedAggregate {
    fn load(inputs: &HistoricalV2AggregateInputs<'_>) -> Result<Self, Box<dyn Error>> {
        let protocol_bytes = read_plain_file(
            Path::new(inputs.protocol_path),
            "historical-v2 protocol",
            MAX_PROTOCOL_BYTES,
        )?;
        let protocol = validate_historical_v2_protocol(&protocol_bytes)
            .map_err(|error| invalid_data("historical-v2 protocol is invalid", error))?;
        let artifact_root = existing_plain_directory(inputs.artifact_root, "artifact root")?;
        let state_root = existing_plain_directory(inputs.state_root, "state root")?;
        let corpus_root =
            existing_plain_directory(inputs.corpus_root, "historical-v2 corpus root")?;
        reject_overlapping_roots([&artifact_root, &state_root, &corpus_root])?;
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
        let reviewed = load_review_set(inputs.protocol_path, &protocol, &corpus_root)?;
        Ok(Self {
            protocol_bytes,
            artifact_root,
            frame,
            exclusions,
            selection,
            state_root,
            corpus_root,
            reviewed,
        })
    }

    fn with_gate<T>(
        &self,
        operation: impl FnOnce(&HistoricalV2ReleaseGateInputs<'_>) -> Result<T, String>,
    ) -> Result<T, Box<dyn Error>> {
        let reviewed = self
            .reviewed
            .iter()
            .map(LoadedReviewedSlot::borrowed)
            .collect::<Vec<_>>();
        let gate = HistoricalV2ReleaseGateInputs {
            protocol_bytes: &self.protocol_bytes,
            artifact_root: &self.artifact_root,
            frame: &self.frame,
            exclusions: &self.exclusions,
            selection: &self.selection,
            state_root: &self.state_root,
            reviewed_slots: &reviewed,
        };
        operation(&gate).map_err(|error| {
            invalid_data("historical-v2 aggregate review is invalid", error).into()
        })
    }
}

struct LoadedReviewedSlot {
    language: String,
    slot_number: usize,
    bundle_root: PathBuf,
    bundle: HistoricalV2SourceReviewBundle,
    worksheets: Vec<HistoricalV2LabelWorksheet>,
    audit: HistoricalV2LabelAudit,
    resolution: HistoricalV2ResolutionWorksheet,
    final_label: HistoricalV2FinalLabel,
}

impl LoadedReviewedSlot {
    fn borrowed(&self) -> HistoricalV2ReviewedSlotArtifacts<'_> {
        HistoricalV2ReviewedSlotArtifacts {
            language: &self.language,
            slot_number: self.slot_number,
            bundle_root: &self.bundle_root,
            bundle: &self.bundle,
            worksheets: &self.worksheets,
            audit: &self.audit,
            resolution: &self.resolution,
            final_label: &self.final_label,
        }
    }
}

fn load_review_set(
    protocol_path: &str,
    protocol: &ValidatedHistoricalV2Protocol,
    corpus_root: &Path,
) -> Result<Vec<LoadedReviewedSlot>, Box<dyn Error>> {
    let reviews_root = corpus_root.join(REVIEWS_DIRECTORY);
    let labels_root = corpus_root.join(LABELS_DIRECTORY);
    require_plain_directory(&reviews_root, "historical-v2 reviews root")?;
    require_plain_directory(&labels_root, "historical-v2 labels root")?;
    let reviews = directory_names(&reviews_root, "historical-v2 reviews root")?;
    let labels = directory_names(&labels_root, "historical-v2 labels root")?;
    if reviews != labels {
        return Err(invalid_data(
            "historical-v2 aggregate review is invalid",
            "source-review and label package identities differ",
        )
        .into());
    }
    reviews
        .into_iter()
        .map(|identity| {
            load_reviewed_slot(
                protocol_path,
                protocol,
                &reviews_root,
                &labels_root,
                &identity,
            )
        })
        .collect()
}

fn load_reviewed_slot(
    protocol_path: &str,
    protocol: &ValidatedHistoricalV2Protocol,
    reviews_root: &Path,
    labels_root: &Path,
    identity: &str,
) -> Result<LoadedReviewedSlot, Box<dyn Error>> {
    let (language, slot_number) = parse_slot_identity(protocol, identity)?;
    let bundle_path = reviews_root.join(identity);
    let labels_path = labels_root.join(identity);
    let bundle_path_text = bundle_path
        .to_str()
        .ok_or_else(|| invalid_data("historical-v2 review path", "path is not UTF-8"))?;
    let loaded = load_review(protocol_path, bundle_path_text)?;
    if loaded.bundle.language != language {
        return Err(invalid_data(
            "historical-v2 aggregate review is invalid",
            format!(
                "{identity} contains a {} source bundle",
                loaded.bundle.language
            ),
        )
        .into());
    }
    require_exact_label_files(&labels_path)?;
    let worksheets = vec![
        read_json::<HistoricalV2LabelWorksheet>(
            &labels_path.join(REVIEW_A),
            "historical-v2 reviewer A worksheet",
        )?,
        read_json::<HistoricalV2LabelWorksheet>(
            &labels_path.join(REVIEW_B),
            "historical-v2 reviewer B worksheet",
        )?,
    ];
    let audit =
        read_json::<HistoricalV2LabelAudit>(&labels_path.join(AUDIT), "historical-v2 label audit")?;
    let resolution = read_json::<HistoricalV2ResolutionWorksheet>(
        &labels_path.join(RESOLUTION),
        "historical-v2 resolution",
    )?;
    let final_label = read_json::<HistoricalV2FinalLabel>(
        &labels_path.join(FINAL_LABEL),
        "historical-v2 final label",
    )?;
    validate_historical_v2_final_label(
        &loaded.protocol,
        &loaded.root,
        &loaded.bundle,
        &worksheets,
        &audit,
        &resolution,
        &final_label,
    )
    .map_err(|error| invalid_data("historical-v2 reviewed slot is invalid", error))?;
    Ok(LoadedReviewedSlot {
        language,
        slot_number,
        bundle_root: loaded.root,
        bundle: loaded.bundle,
        worksheets,
        audit,
        resolution,
        final_label,
    })
}

fn parse_slot_identity(
    protocol: &ValidatedHistoricalV2Protocol,
    identity: &str,
) -> Result<(String, usize), IoError> {
    let (language, number) = identity
        .rsplit_once('-')
        .ok_or_else(|| invalid_data("historical-v2 review identity", identity))?;
    let slot_number = number
        .parse::<usize>()
        .map_err(|_| invalid_data("historical-v2 review identity", identity))?;
    if format!("{language}-{slot_number:03}") != identity
        || slot_number == 0
        || slot_number > protocol.protocol.selection.slots_per_language
        || !protocol
            .protocol
            .selection
            .supported_languages
            .iter()
            .any(|supported| supported == language)
    {
        return Err(invalid_data("historical-v2 review identity", identity));
    }
    Ok((language.to_string(), slot_number))
}

fn directory_names(root: &Path, label: &str) -> Result<BTreeSet<String>, IoError> {
    fs::read_dir(root)
        .map_err(|error| IoError::new(error.kind(), format!("failed to read {label}: {error}")))?
        .map(|entry| {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid_data(label, "expected only plain directories"));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_data(label, "entry name is not UTF-8"))
        })
        .collect()
}

fn require_exact_label_files(root: &Path) -> Result<(), IoError> {
    require_plain_directory(root, "historical-v2 label package")?;
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid_data(
                "historical-v2 label package",
                "expected only plain files",
            ));
        }
        actual.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_data("historical-v2 label package", "non-UTF-8 file"))?,
        );
    }
    let expected = LABEL_FILES.into_iter().map(str::to_string).collect();
    if actual != expected {
        return Err(invalid_data(
            "historical-v2 label package",
            "required files are missing or replaced",
        ));
    }
    Ok(())
}

fn reject_overlapping_roots<'a>(
    roots: impl IntoIterator<Item = &'a PathBuf>,
) -> Result<(), IoError> {
    let roots = roots.into_iter().collect::<Vec<_>>();
    for (index, left) in roots.iter().enumerate() {
        for right in roots.iter().skip(index + 1) {
            if left.starts_with(right) || right.starts_with(left) {
                return Err(invalid_data(
                    "historical-v2 aggregate roots overlap",
                    format!("{} and {}", left.display(), right.display()),
                ));
            }
        }
    }
    Ok(())
}

fn new_file_under_root(root: &Path, path: &Path, label: &str) -> Result<PathBuf, IoError> {
    if path.exists() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            format!("{label} already exists: {}", path.display()),
        ));
    }
    resolved_file_under_root(root, path, label, false)
}

fn existing_file_under_root(root: &Path, path: &Path, label: &str) -> Result<PathBuf, IoError> {
    resolved_file_under_root(root, path, label, true)
}

fn resolved_file_under_root(
    root: &Path,
    path: &Path,
    label: &str,
    must_exist: bool,
) -> Result<PathBuf, IoError> {
    let root_text = root
        .to_str()
        .ok_or_else(|| invalid_data(label, "corpus root is not UTF-8"))?;
    let root = existing_plain_directory(root_text, "historical-v2 corpus root")?;
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid_data(label, "path has no parent"))?;
    let parent_text = parent
        .to_str()
        .ok_or_else(|| invalid_data(label, "parent path is not UTF-8"))?;
    let parent = existing_plain_directory(parent_text, &format!("{label} parent"))?;
    let file_name = absolute
        .file_name()
        .ok_or_else(|| invalid_data(label, "path has no final component"))?;
    if !matches!(
        absolute.components().next_back(),
        Some(Component::Normal(_))
    ) {
        return Err(invalid_data(label, "path has an unsafe final component"));
    }
    let resolved = parent.join(file_name);
    if !resolved.starts_with(&root) {
        return Err(invalid_data(label, "path is outside the corpus root"));
    }
    if must_exist {
        let metadata = fs::symlink_metadata(&resolved)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid_data(label, "expected a plain file"));
        }
    } else if resolved.exists() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            format!("{label} already exists: {}", resolved.display()),
        ));
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "cli_pipeline_historical_v2_release_tests.rs"]
mod tests;
