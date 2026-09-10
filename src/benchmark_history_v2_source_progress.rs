use super::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const SOURCE_PROGRESS_SCHEMA_VERSION: u32 = 1;
const SOURCE_PROGRESS_CONTRACT: &str = "historical-v2-source-progress-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HistoricalV2SourceProgressUnit {
    Inventory,
    Inspection,
    ParserCensus,
    CargoProjectModel,
    GoProjectModel,
    GradleProjectModel,
    TypeScriptProjectModel,
    NodePackageSurfaces,
    NodeConsumerProfiles,
    PythonDistributionSurfaces,
    Snapshot,
}

impl HistoricalV2SourceProgressUnit {
    fn all() -> &'static [Self] {
        &[
            Self::Inventory,
            Self::Inspection,
            Self::ParserCensus,
            Self::CargoProjectModel,
            Self::GoProjectModel,
            Self::GradleProjectModel,
            Self::TypeScriptProjectModel,
            Self::NodePackageSurfaces,
            Self::NodeConsumerProfiles,
            Self::PythonDistributionSurfaces,
            Self::Snapshot,
        ]
    }

    fn stem(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Inspection => "inspection",
            Self::ParserCensus => "parser-census",
            Self::CargoProjectModel => "cargo-project-model",
            Self::GoProjectModel => "go-project-model",
            Self::GradleProjectModel => "gradle-project-model",
            Self::TypeScriptProjectModel => "typescript-project-model",
            Self::NodePackageSurfaces => "node-package-surfaces",
            Self::NodeConsumerProfiles => "node-consumer-profiles",
            Self::PythonDistributionSurfaces => "python-distribution-surfaces",
            Self::Snapshot => "snapshot",
        }
    }

    fn file_name(self) -> String {
        format!("{}.json", self.stem())
    }

    fn temp_file_name(self) -> String {
        format!("{}.json.tmp", self.stem())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceProgressCheckpoint {
    schema_version: u32,
    progress_contract: String,
    materialization_sha256: String,
    canonical_repository: String,
    side: HistoricalV2SourceSnapshotSide,
    revision: String,
    unit: HistoricalV2SourceProgressUnit,
    dependency_sha256s: Vec<String>,
    payload_sha256: String,
    payload: serde_json::Value,
    checkpoint_sha256: String,
}

#[derive(Debug)]
pub(super) struct HistoricalV2SourceProgress {
    root: PathBuf,
}

impl HistoricalV2SourceProgress {
    pub(super) fn open(root: &Path) -> Result<Self, String> {
        io::ensure_plain_directory(root)?;
        for side in [
            HistoricalV2SourceSnapshotSide::Base,
            HistoricalV2SourceSnapshotSide::Patched,
        ] {
            io::ensure_plain_directory(&root.join(side_name(side)))?;
        }
        io::require_entries(root, &["base", "patched"], "source progress root")?;
        let progress = Self {
            root: root.to_path_buf(),
        };
        for side in [
            HistoricalV2SourceSnapshotSide::Base,
            HistoricalV2SourceSnapshotSide::Patched,
        ] {
            progress.validate_side_entries(side)?;
            progress.remove_incomplete_units(side)?;
            progress.validate_side_entries(side)?;
        }
        Ok(progress)
    }

    pub(super) fn recover_existing(root: &Path) -> Result<(), String> {
        match std::fs::symlink_metadata(root) {
            Ok(_) => Self::open(root).map(|_| ()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "failed to inspect historical-v2 source progress root: {error}"
            )),
        }
    }

    pub(super) fn load<T: DeserializeOwned>(
        &self,
        materialization: &HistoricalV2Materialization,
        side: HistoricalV2SourceSnapshotSide,
        revision: &str,
        unit: HistoricalV2SourceProgressUnit,
        dependency_sha256s: &[String],
    ) -> Result<Option<T>, String> {
        self.validate_side_entries(side)?;
        let path = self.side_root(side).join(unit.file_name());
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "failed to inspect historical-v2 source progress checkpoint: {error}"
                ));
            }
            Ok(_) => {}
        }
        let checkpoint: SourceProgressCheckpoint = io::read_checkpoint(&path)?;
        validate_checkpoint(
            &checkpoint,
            materialization,
            side,
            revision,
            unit,
            dependency_sha256s,
        )?;
        serde_json::from_value(checkpoint.payload)
            .map(Some)
            .map_err(|error| {
                format!(
                    "historical-v2 {} {} source progress payload changed type: {error}",
                    side_name(side),
                    unit.stem()
                )
            })
    }

    pub(super) fn publish<T: Serialize>(
        &self,
        materialization: &HistoricalV2Materialization,
        side: HistoricalV2SourceSnapshotSide,
        revision: &str,
        unit: HistoricalV2SourceProgressUnit,
        dependency_sha256s: &[String],
        payload: &T,
    ) -> Result<(), String> {
        self.validate_side_entries(side)?;
        require_sha256s(dependency_sha256s)?;
        let payload = serde_json::to_value(payload).map_err(|error| {
            format!("failed to serialize historical-v2 source progress payload: {error}")
        })?;
        let mut checkpoint = SourceProgressCheckpoint {
            schema_version: SOURCE_PROGRESS_SCHEMA_VERSION,
            progress_contract: SOURCE_PROGRESS_CONTRACT.to_string(),
            materialization_sha256: materialization.materialization_sha256.clone(),
            canonical_repository: materialization.canonical_repository.clone(),
            side,
            revision: revision.to_string(),
            unit,
            dependency_sha256s: dependency_sha256s.to_vec(),
            payload_sha256: canonical_sha256(&payload)?,
            payload,
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint)?;
        let bytes = serde_json::to_vec(&checkpoint).map_err(|error| {
            format!("failed to serialize historical-v2 source progress checkpoint: {error}")
        })?;
        let path = self.side_root(side).join(unit.file_name());
        let temp = self.side_root(side).join(unit.temp_file_name());
        io::write_atomic_new(&path, &temp, &bytes)
    }

    fn side_root(&self, side: HistoricalV2SourceSnapshotSide) -> PathBuf {
        self.root.join(side_name(side))
    }

    fn remove_incomplete_units(&self, side: HistoricalV2SourceSnapshotSide) -> Result<(), String> {
        for unit in HistoricalV2SourceProgressUnit::all() {
            io::remove_incomplete_file(&self.side_root(side).join(unit.temp_file_name()))?;
        }
        Ok(())
    }

    fn validate_side_entries(&self, side: HistoricalV2SourceSnapshotSide) -> Result<(), String> {
        let allowed = HistoricalV2SourceProgressUnit::all()
            .iter()
            .flat_map(|unit| [unit.file_name(), unit.temp_file_name()])
            .collect::<Vec<_>>();
        let allowed = allowed.iter().map(String::as_str).collect::<Vec<_>>();
        io::require_allowed_entries(
            &self.side_root(side),
            &allowed,
            "historical-v2 source side progress",
        )
    }
}

fn validate_checkpoint(
    checkpoint: &SourceProgressCheckpoint,
    materialization: &HistoricalV2Materialization,
    side: HistoricalV2SourceSnapshotSide,
    revision: &str,
    unit: HistoricalV2SourceProgressUnit,
    dependency_sha256s: &[String],
) -> Result<(), String> {
    require_sha256s(dependency_sha256s)?;
    if checkpoint.schema_version != SOURCE_PROGRESS_SCHEMA_VERSION
        || checkpoint.progress_contract != SOURCE_PROGRESS_CONTRACT
        || checkpoint.materialization_sha256 != materialization.materialization_sha256
        || checkpoint.canonical_repository != materialization.canonical_repository
        || checkpoint.side != side
        || checkpoint.revision != revision
        || checkpoint.unit != unit
        || checkpoint.dependency_sha256s != dependency_sha256s
        || checkpoint.payload_sha256 != canonical_sha256(&checkpoint.payload)?
        || !is_sha256(&checkpoint.checkpoint_sha256)
    {
        return Err(format!(
            "historical-v2 {} {} source progress changed immutable evidence",
            side_name(side),
            unit.stem()
        ));
    }
    let mut projection = checkpoint.clone();
    projection.checkpoint_sha256.clear();
    if checkpoint.checkpoint_sha256 != canonical_sha256(&projection)? {
        return Err(format!(
            "historical-v2 {} {} source progress commitment changed",
            side_name(side),
            unit.stem()
        ));
    }
    Ok(())
}

fn require_sha256s(values: &[String]) -> Result<(), String> {
    if values.iter().all(|value| is_sha256(value)) {
        Ok(())
    } else {
        Err("historical-v2 source progress dependency is not SHA-256".to_string())
    }
}

fn side_name(side: HistoricalV2SourceSnapshotSide) -> &'static str {
    match side {
        HistoricalV2SourceSnapshotSide::Base => "base",
        HistoricalV2SourceSnapshotSide::Patched => "patched",
    }
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            format!("failed to serialize historical-v2 source progress commitment: {error}")
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[path = "benchmark_history_v2_source_progress_io.rs"]
mod io;

#[cfg(test)]
#[path = "benchmark_history_v2_source_progress_tests.rs"]
mod tests;
