use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const SNAPSHOT_PROGRESS_SCHEMA_VERSION: u32 = 5;
const SNAPSHOT_PROGRESS_CONTRACT: &str = "historical-v2-semantic-snapshot-progress-v5";
const SNAPSHOT_FILE: &str = "snapshot.json";
const SNAPSHOT_TEMP_FILE: &str = "snapshot.json.tmp";
const CONTRIBUTIONS_DIRECTORY: &str = "contributions";
const CONTRIBUTION_PROGRESS_SCHEMA_VERSION: u32 = 1;
const CONTRIBUTION_PROGRESS_CONTRACT: &str =
    "historical-v2-semantic-variant-contribution-progress-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotCheckpoint {
    schema_version: u32,
    progress_contract: String,
    materialization_sha256: String,
    source_census_sha256: String,
    side: HistoricalV2SemanticSnapshotSide,
    revision: String,
    source_snapshot_census_sha256: String,
    changed_indexers: Vec<SemanticIndexerKind>,
    required_document_paths: Vec<String>,
    payload_sha256: String,
    payload: HistoricalV2SemanticSnapshotCensus,
    checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContributionCheckpoint {
    schema_version: u32,
    progress_contract: String,
    materialization_sha256: String,
    source_census_sha256: String,
    side: HistoricalV2SemanticSnapshotSide,
    revision: String,
    source_snapshot_census_sha256: String,
    changed_indexers: Vec<SemanticIndexerKind>,
    required_document_paths: Vec<String>,
    indexer: HistoricalV2SemanticIndexerVariantCensus,
    payload_sha256: String,
    payload: assembly::HistoricalV2SemanticVariantContribution,
    checkpoint_sha256: String,
}

pub(super) struct HistoricalV2SemanticProgress {
    root: PathBuf,
}

impl HistoricalV2SemanticProgress {
    pub(super) fn open(root: &Path) -> Result<Self, String> {
        ensure_plain_directory(root)?;
        for side in [
            HistoricalV2SemanticSnapshotSide::Base,
            HistoricalV2SemanticSnapshotSide::Patched,
        ] {
            ensure_plain_directory(&root.join(side_name(side)))?;
            ensure_plain_directory(&root.join(side_name(side)).join(CONTRIBUTIONS_DIRECTORY))?;
        }
        require_entries(
            root,
            &["base", "patched"],
            "semantic snapshot progress root",
        )?;
        let progress = Self {
            root: root.to_path_buf(),
        };
        progress.validate_side_entries(HistoricalV2SemanticSnapshotSide::Base)?;
        progress.validate_side_entries(HistoricalV2SemanticSnapshotSide::Patched)?;
        Ok(progress)
    }

    pub(super) fn recover_existing(
        root: &Path,
    ) -> Result<Vec<HistoricalV2SemanticProgressRecovery>, String> {
        match std::fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => {
                return Err(format!(
                    "failed to inspect historical-v2 semantic progress root: {error}"
                ));
            }
        }
        let progress = Self::open(root)?;
        let mut recovered = Vec::new();
        for side in [
            HistoricalV2SemanticSnapshotSide::Base,
            HistoricalV2SemanticSnapshotSide::Patched,
        ] {
            remove_incomplete_file(&progress.side_root(side).join(SNAPSHOT_TEMP_FILE))?;
            progress.remove_contribution_temps(side)?;
            recovered.extend(
                crate::semantic_indexer_runner::recover_semantic_indexer_progress(
                    &progress.side_root(side),
                )?
                .into_iter()
                .map(|progress| HistoricalV2SemanticProgressRecovery { side, progress }),
            );
            progress.validate_side_entries(side)?;
        }
        Ok(recovered)
    }

    pub(super) fn indexer_root(&self, side: HistoricalV2SemanticSnapshotSide) -> PathBuf {
        self.side_root(side)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn load_contribution(
        &self,
        materialization: &HistoricalV2Materialization,
        source_census: &HistoricalV2SourceCensus,
        side: HistoricalV2SemanticSnapshotSide,
        source: &HistoricalV2SourceSnapshotCensus,
        changed_indexers: &BTreeSet<SemanticIndexerKind>,
        required_document_paths: &BTreeSet<String>,
        indexer: &HistoricalV2SemanticIndexerVariantCensus,
    ) -> Result<Option<assembly::HistoricalV2SemanticVariantContribution>, String> {
        let path = self.contribution_path(side, indexer)?;
        remove_incomplete_file(&temporary_path(&path))?;
        self.validate_side_entries(side)?;
        if !path.exists() {
            return Ok(None);
        }
        let checkpoint: ContributionCheckpoint =
            read_checkpoint(&path, "semantic contribution checkpoint")?;
        validate_contribution_checkpoint(
            &checkpoint,
            materialization,
            source_census,
            side,
            source,
            changed_indexers,
            required_document_paths,
            indexer,
        )?;
        Ok(Some(checkpoint.payload))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_contribution(
        &self,
        materialization: &HistoricalV2Materialization,
        source_census: &HistoricalV2SourceCensus,
        side: HistoricalV2SemanticSnapshotSide,
        source: &HistoricalV2SourceSnapshotCensus,
        changed_indexers: &BTreeSet<SemanticIndexerKind>,
        required_document_paths: &BTreeSet<String>,
        indexer: &HistoricalV2SemanticIndexerVariantCensus,
        payload: assembly::HistoricalV2SemanticVariantContribution,
    ) -> Result<assembly::HistoricalV2SemanticVariantContribution, String> {
        assembly::validate_variant_contribution(&payload, indexer)?;
        self.validate_side_entries(side)?;
        let path = self.contribution_path(side, indexer)?;
        if path.exists() {
            return Err(format!(
                "historical-v2 semantic contribution checkpoint already exists for {}",
                contribution_label(indexer)
            ));
        }
        let mut checkpoint = ContributionCheckpoint {
            schema_version: CONTRIBUTION_PROGRESS_SCHEMA_VERSION,
            progress_contract: CONTRIBUTION_PROGRESS_CONTRACT.to_string(),
            materialization_sha256: materialization.materialization_sha256.clone(),
            source_census_sha256: source_census.source_census_sha256.clone(),
            side,
            revision: source.revision.clone(),
            source_snapshot_census_sha256: source.snapshot_census_sha256.clone(),
            changed_indexers: changed_indexers.iter().copied().collect(),
            required_document_paths: required_document_paths.iter().cloned().collect(),
            indexer: indexer.clone(),
            payload_sha256: canonical_sha256(&payload)?,
            payload,
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint)?;
        let bytes = serde_json::to_vec(&checkpoint).map_err(|error| {
            format!("failed to serialize historical-v2 semantic contribution progress: {error}")
        })?;
        write_atomic_new(&path, &bytes)?;
        Ok(checkpoint.payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn load_snapshot(
        &self,
        materialization: &HistoricalV2Materialization,
        source_census: &HistoricalV2SourceCensus,
        side: HistoricalV2SemanticSnapshotSide,
        source: &HistoricalV2SourceSnapshotCensus,
        changed_indexers: &BTreeSet<SemanticIndexerKind>,
        required_document_paths: &BTreeSet<String>,
    ) -> Result<Option<HistoricalV2SemanticSnapshotCensus>, String> {
        remove_incomplete_file(&self.side_root(side).join(SNAPSHOT_TEMP_FILE))?;
        self.validate_side_entries(side)?;
        let path = self.side_root(side).join(SNAPSHOT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let checkpoint: SnapshotCheckpoint =
            read_checkpoint(&path, "semantic snapshot checkpoint")?;
        validate_checkpoint(
            &checkpoint,
            materialization,
            source_census,
            side,
            source,
            changed_indexers,
            required_document_paths,
        )?;
        Ok(Some(checkpoint.payload))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_snapshot(
        &self,
        materialization: &HistoricalV2Materialization,
        source_census: &HistoricalV2SourceCensus,
        side: HistoricalV2SemanticSnapshotSide,
        source: &HistoricalV2SourceSnapshotCensus,
        changed_indexers: &BTreeSet<SemanticIndexerKind>,
        required_document_paths: &BTreeSet<String>,
        payload: &HistoricalV2SemanticSnapshotCensus,
    ) -> Result<(), String> {
        self.validate_side_entries(side)?;
        let path = self.side_root(side).join(SNAPSHOT_FILE);
        if path.exists() {
            return Err(format!(
                "historical-v2 semantic snapshot checkpoint already exists for {}",
                side_name(side)
            ));
        }
        let mut checkpoint = SnapshotCheckpoint {
            schema_version: SNAPSHOT_PROGRESS_SCHEMA_VERSION,
            progress_contract: SNAPSHOT_PROGRESS_CONTRACT.to_string(),
            materialization_sha256: materialization.materialization_sha256.clone(),
            source_census_sha256: source_census.source_census_sha256.clone(),
            side,
            revision: source.revision.clone(),
            source_snapshot_census_sha256: source.snapshot_census_sha256.clone(),
            changed_indexers: changed_indexers.iter().copied().collect(),
            required_document_paths: required_document_paths.iter().cloned().collect(),
            payload_sha256: canonical_sha256(payload)?,
            payload: payload.clone(),
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint)?;
        let bytes = serde_json::to_vec(&checkpoint).map_err(|error| {
            format!("failed to serialize historical-v2 semantic snapshot progress: {error}")
        })?;
        write_atomic_new(&path, &bytes)
    }

    fn side_root(&self, side: HistoricalV2SemanticSnapshotSide) -> PathBuf {
        self.root.join(side_name(side))
    }

    fn contribution_root(&self, side: HistoricalV2SemanticSnapshotSide) -> PathBuf {
        self.side_root(side).join(CONTRIBUTIONS_DIRECTORY)
    }

    fn contribution_path(
        &self,
        side: HistoricalV2SemanticSnapshotSide,
        indexer: &HistoricalV2SemanticIndexerVariantCensus,
    ) -> Result<PathBuf, String> {
        contribution_identity(indexer).map(|identity| {
            self.contribution_root(side)
                .join(format!("{identity}.json"))
        })
    }

    fn remove_contribution_temps(
        &self,
        side: HistoricalV2SemanticSnapshotSide,
    ) -> Result<(), String> {
        for entry in std::fs::read_dir(self.contribution_root(side)).map_err(|error| {
            format!("failed to inspect historical-v2 semantic contributions: {error}")
        })? {
            let entry = entry.map_err(|error| {
                format!("failed to inspect historical-v2 semantic contribution: {error}")
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                "historical-v2 semantic contribution has a non-UTF-8 name".to_string()
            })?;
            if name.ends_with(".json.tmp") {
                remove_incomplete_file(&entry.path())?;
            }
        }
        Ok(())
    }

    fn validate_side_entries(&self, side: HistoricalV2SemanticSnapshotSide) -> Result<(), String> {
        require_allowed_entries(
            &self.side_root(side),
            &[
                "go",
                "typescript",
                CONTRIBUTIONS_DIRECTORY,
                SNAPSHOT_FILE,
                SNAPSHOT_TEMP_FILE,
            ],
            "historical-v2 semantic side progress",
        )?;
        validate_contribution_entries(&self.contribution_root(side))
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_contribution_checkpoint(
    checkpoint: &ContributionCheckpoint,
    materialization: &HistoricalV2Materialization,
    source_census: &HistoricalV2SourceCensus,
    side: HistoricalV2SemanticSnapshotSide,
    source: &HistoricalV2SourceSnapshotCensus,
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
    indexer: &HistoricalV2SemanticIndexerVariantCensus,
) -> Result<(), String> {
    if checkpoint.schema_version != CONTRIBUTION_PROGRESS_SCHEMA_VERSION
        || checkpoint.progress_contract != CONTRIBUTION_PROGRESS_CONTRACT
        || checkpoint.materialization_sha256 != materialization.materialization_sha256
        || checkpoint.source_census_sha256 != source_census.source_census_sha256
        || checkpoint.side != side
        || checkpoint.revision != source.revision
        || checkpoint.source_snapshot_census_sha256 != source.snapshot_census_sha256
        || checkpoint.changed_indexers != changed_indexers.iter().copied().collect::<Vec<_>>()
        || checkpoint.required_document_paths
            != required_document_paths.iter().cloned().collect::<Vec<_>>()
        || &checkpoint.indexer != indexer
        || !is_sha256(&checkpoint.payload_sha256)
        || checkpoint.payload_sha256 != canonical_sha256(&checkpoint.payload)?
        || !is_sha256(&checkpoint.checkpoint_sha256)
    {
        return Err(format!(
            "historical-v2 semantic contribution {} changed immutable evidence",
            contribution_label(indexer)
        ));
    }
    assembly::validate_variant_contribution(&checkpoint.payload, indexer)?;
    let mut projection = checkpoint.clone();
    projection.checkpoint_sha256.clear();
    if checkpoint.checkpoint_sha256 != canonical_sha256(&projection)? {
        return Err(format!(
            "historical-v2 semantic contribution {} commitment changed",
            contribution_label(indexer)
        ));
    }
    Ok(())
}

fn contribution_identity(
    indexer: &HistoricalV2SemanticIndexerVariantCensus,
) -> Result<String, String> {
    canonical_sha256(&(indexer.census.indexer, &indexer.variant))
}

fn contribution_label(indexer: &HistoricalV2SemanticIndexerVariantCensus) -> String {
    format!("{:?}/{:?}", indexer.census.indexer, indexer.variant)
}

fn temporary_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tmp", path.to_string_lossy()))
}

fn validate_contribution_entries(root: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(root).map_err(|error| {
        format!("failed to inspect historical-v2 semantic contributions: {error}")
    })? {
        let entry = entry.map_err(|error| {
            format!("failed to inspect historical-v2 semantic contribution: {error}")
        })?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("failed to inspect historical-v2 semantic contribution entry: {error}")
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "historical-v2 semantic contribution has a non-UTF-8 name".to_string())?;
        let identity = name
            .strip_suffix(".json")
            .or_else(|| name.strip_suffix(".json.tmp"));
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || identity.is_none_or(|identity| !is_sha256(identity))
        {
            return Err(format!(
                "historical-v2 semantic contributions contain an invalid entry {name}"
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_checkpoint(
    checkpoint: &SnapshotCheckpoint,
    materialization: &HistoricalV2Materialization,
    source_census: &HistoricalV2SourceCensus,
    side: HistoricalV2SemanticSnapshotSide,
    source: &HistoricalV2SourceSnapshotCensus,
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
) -> Result<(), String> {
    if checkpoint.schema_version != SNAPSHOT_PROGRESS_SCHEMA_VERSION
        || checkpoint.progress_contract != SNAPSHOT_PROGRESS_CONTRACT
        || checkpoint.materialization_sha256 != materialization.materialization_sha256
        || checkpoint.source_census_sha256 != source_census.source_census_sha256
        || checkpoint.side != side
        || checkpoint.revision != source.revision
        || checkpoint.source_snapshot_census_sha256 != source.snapshot_census_sha256
        || checkpoint.changed_indexers != changed_indexers.iter().copied().collect::<Vec<_>>()
        || checkpoint.required_document_paths
            != required_document_paths.iter().cloned().collect::<Vec<_>>()
        || checkpoint.payload_sha256 != canonical_sha256(&checkpoint.payload)?
        || !is_sha256(&checkpoint.checkpoint_sha256)
    {
        return Err(format!(
            "historical-v2 {} semantic snapshot checkpoint changed immutable evidence",
            side_name(side)
        ));
    }
    let mut projection = checkpoint.clone();
    projection.checkpoint_sha256.clear();
    if checkpoint.checkpoint_sha256 != canonical_sha256(&projection)? {
        return Err(format!(
            "historical-v2 {} semantic snapshot checkpoint commitment changed",
            side_name(side)
        ));
    }
    Ok(())
}

fn side_name(side: HistoricalV2SemanticSnapshotSide) -> &'static str {
    match side {
        HistoricalV2SemanticSnapshotSide::Base => "base",
        HistoricalV2SemanticSnapshotSide::Patched => "patched",
    }
}

#[path = "benchmark_history_v2_semantic_progress_io.rs"]
mod io;

use io::{
    ensure_plain_directory, read_checkpoint, remove_incomplete_file, require_allowed_entries,
    require_entries, write_atomic_new,
};

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            format!("failed to serialize historical-v2 semantic progress commitment: {error}")
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
#[path = "benchmark_history_v2_semantic_progress_tests.rs"]
mod tests;
