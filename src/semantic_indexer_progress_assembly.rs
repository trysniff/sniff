use super::*;
use std::io::Read;

pub(super) const ASSEMBLIES_DIRECTORY: &str = "assemblies";
const ASSEMBLY_CONTRACT: &str = "semantic-indexer-unit-assembly-progress-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticAssemblyUnitCommitment {
    unit_id: String,
    unit_input_sha256: String,
    checkpoint_file_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticAssemblyCheckpoint {
    schema_version: u32,
    progress_contract: String,
    scope_sha256: String,
    completed_units: Vec<SemanticAssemblyUnitCommitment>,
    payload_file_size: u64,
    payload_file_sha256: String,
    checkpoint_sha256: String,
}

pub(in crate::semantic_indexer_runner) struct SemanticProgressAssembly {
    pub(in crate::semantic_indexer_runner) completed_unit_count: usize,
    pub(in crate::semantic_indexer_runner) payload: SemanticIndex,
}

impl SemanticProgressStore {
    pub(in crate::semantic_indexer_runner) fn load_assembly(
        &self,
        repository_root: &Path,
    ) -> Result<Option<SemanticProgressAssembly>, String> {
        let Some(mut assembly) = self.load_assembly_normalized()? else {
            return Ok(None);
        };
        bind_repository_root(&mut assembly.payload, repository_root)?;
        Ok(Some(assembly))
    }

    pub(in crate::semantic_indexer_runner) fn publish_assembly(
        &self,
        completed_units: &[SemanticProgressUnit],
        repository_root: &Path,
        payload: &SemanticIndex,
    ) -> Result<(), String> {
        self.require_assembly_prefix(completed_units)?;
        self.remove_assembly_temps()?;
        self.validate_directory_entries()?;
        let completed_unit_count = completed_units.len();
        let path = self.assembly_path(completed_unit_count);
        if path.exists() {
            return Err(format!(
                "semantic assembly checkpoint {completed_unit_count} already exists"
            ));
        }
        let completed_units = completed_units
            .iter()
            .map(|unit| {
                Ok(SemanticAssemblyUnitCommitment {
                    unit_id: unit.unit_id.clone(),
                    unit_input_sha256: unit.input_sha256.clone(),
                    checkpoint_file_sha256: plain_file_sha256(&self.unit_path(unit))?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let payload = normalize_repository_root(payload, repository_root)?;
        let payload_path = self.assembly_payload_path(completed_unit_count);
        write_json_atomic_new(&payload_path, &payload)?;
        let payload_file_size = plain_file_size(&payload_path)?;
        let payload_file_sha256 = plain_file_sha256(&payload_path)?;
        let mut checkpoint = SemanticAssemblyCheckpoint {
            schema_version: PROGRESS_SCHEMA_VERSION,
            progress_contract: ASSEMBLY_CONTRACT.to_string(),
            scope_sha256: self.scope.scope_sha256.clone(),
            completed_units,
            payload_file_size,
            payload_file_sha256,
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint)?;
        write_atomic_new(
            &path,
            &serde_json::to_vec(&checkpoint).map_err(|error| {
                format!("failed to serialize semantic assembly checkpoint: {error}")
            })?,
        )?;
        self.prune_assemblies(completed_unit_count)?;
        if completed_unit_count == self.scope.units.len() {
            self.prune_completed_unit_checkpoints()?;
        }
        Ok(())
    }

    fn require_assembly_prefix(
        &self,
        completed_units: &[SemanticProgressUnit],
    ) -> Result<(), String> {
        if completed_units.is_empty()
            || completed_units.len() > self.scope.units.len()
            || completed_units != &self.scope.units[..completed_units.len()]
        {
            return Err(
                "semantic assembly units are not an exact non-empty scope prefix".to_string(),
            );
        }
        Ok(())
    }

    pub(super) fn assembly_path(&self, completed_unit_count: usize) -> PathBuf {
        self.root
            .join(ASSEMBLIES_DIRECTORY)
            .join(assembly_file_name(completed_unit_count))
    }

    pub(super) fn assembly_temp_path(&self, completed_unit_count: usize) -> PathBuf {
        PathBuf::from(format!(
            "{}.tmp",
            self.assembly_path(completed_unit_count).to_string_lossy()
        ))
    }

    pub(super) fn assembly_payload_path(&self, completed_unit_count: usize) -> PathBuf {
        self.root
            .join(ASSEMBLIES_DIRECTORY)
            .join(assembly_payload_file_name(completed_unit_count))
    }

    pub(super) fn assembly_payload_temp_path(&self, completed_unit_count: usize) -> PathBuf {
        PathBuf::from(format!(
            "{}.tmp",
            self.assembly_payload_path(completed_unit_count)
                .to_string_lossy()
        ))
    }

    pub(super) fn remove_assembly_temps(&self) -> Result<(), String> {
        for completed_unit_count in 1..=self.scope.units.len() {
            remove_incomplete_file(&self.assembly_temp_path(completed_unit_count))?;
            remove_incomplete_file(&self.assembly_payload_temp_path(completed_unit_count))?;
            let manifest = self.assembly_path(completed_unit_count);
            let payload = self.assembly_payload_path(completed_unit_count);
            if payload.exists() && !manifest.exists() {
                remove_plain_file(&payload, "orphan semantic assembly payload")?;
            }
        }
        Ok(())
    }

    pub(super) fn load_assembly_normalized(
        &self,
    ) -> Result<Option<SemanticProgressAssembly>, String> {
        self.remove_assembly_temps()?;
        self.validate_directory_entries()?;
        let mut latest = None;
        for completed_unit_count in 1..=self.scope.units.len() {
            let path = self.assembly_path(completed_unit_count);
            if !path.exists() {
                continue;
            }
            let checkpoint: SemanticAssemblyCheckpoint =
                read_json(&path, "semantic assembly checkpoint")?;
            let payload = validate_assembly_checkpoint(
                &self.scope,
                completed_unit_count,
                &checkpoint,
                &self.assembly_payload_path(completed_unit_count),
                |unit| {
                    (completed_unit_count != self.scope.units.len())
                        .then(|| plain_file_sha256(&self.unit_path(unit)))
                        .transpose()
                },
            )?;
            latest = Some(SemanticProgressAssembly {
                completed_unit_count,
                payload,
            });
        }
        if latest
            .as_ref()
            .is_some_and(|assembly| assembly.completed_unit_count == self.scope.units.len())
        {
            self.prune_completed_unit_checkpoints()?;
        }
        Ok(latest)
    }

    fn prune_completed_unit_checkpoints(&self) -> Result<(), String> {
        let units_root = self.root.join(UNITS_DIRECTORY);
        for unit in &self.scope.units {
            let path = self.unit_path(unit);
            match fs::symlink_metadata(&path) {
                Ok(_) => remove_plain_file(&path, "superseded semantic unit checkpoint")?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect superseded semantic unit checkpoint {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        io::sync_directory(&units_root)
    }

    pub(super) fn prune_assemblies(&self, keep_completed_unit_count: usize) -> Result<(), String> {
        for completed_unit_count in 1..keep_completed_unit_count {
            let path = self.assembly_path(completed_unit_count);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(format!(
                        "semantic assembly checkpoint is not a plain file: {}",
                        path.display()
                    ));
                }
                Ok(_) => fs::remove_file(&path).map_err(|error| {
                    format!(
                        "failed to prune semantic assembly checkpoint {}: {error}",
                        path.display()
                    )
                })?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect semantic assembly checkpoint {}: {error}",
                        path.display()
                    ));
                }
            }
            let payload = self.assembly_payload_path(completed_unit_count);
            if payload.exists() {
                remove_plain_file(&payload, "superseded semantic assembly payload")?;
            }
        }
        Ok(())
    }
}

pub(super) fn allowed_entry_names(unit_count: usize) -> BTreeSet<String> {
    (1..=unit_count)
        .flat_map(|completed_unit_count| {
            let name = assembly_file_name(completed_unit_count);
            let payload = assembly_payload_file_name(completed_unit_count);
            [
                name.clone(),
                format!("{name}.tmp"),
                payload.clone(),
                format!("{payload}.tmp"),
            ]
        })
        .collect()
}

fn assembly_file_name(completed_unit_count: usize) -> String {
    format!("assembly-{completed_unit_count:08}.json")
}

fn assembly_payload_file_name(completed_unit_count: usize) -> String {
    format!("assembly-{completed_unit_count:08}.payload.json")
}

fn validate_assembly_checkpoint<F>(
    scope: &SemanticProgressScope,
    completed_unit_count: usize,
    checkpoint: &SemanticAssemblyCheckpoint,
    payload_path: &Path,
    mut unit_file_sha256: F,
) -> Result<SemanticIndex, String>
where
    F: FnMut(&SemanticProgressUnit) -> Result<Option<String>, String>,
{
    if completed_unit_count == 0 || completed_unit_count > scope.units.len() {
        return Err("semantic assembly checkpoint has an invalid prefix length".to_string());
    }
    let expected_units = &scope.units[..completed_unit_count];
    if checkpoint.schema_version != PROGRESS_SCHEMA_VERSION
        || checkpoint.progress_contract != ASSEMBLY_CONTRACT
        || checkpoint.scope_sha256 != scope.scope_sha256
        || checkpoint.completed_units.len() != completed_unit_count
        || checkpoint.payload_file_size == 0
        || checkpoint.payload_file_size > io::MAX_CHECKPOINT_BYTES
        || !is_sha256(&checkpoint.payload_file_sha256)
        || !is_sha256(&checkpoint.checkpoint_sha256)
    {
        return Err(format!(
            "semantic assembly checkpoint {completed_unit_count} changed immutable evidence"
        ));
    }
    for (unit, commitment) in expected_units.iter().zip(&checkpoint.completed_units) {
        if commitment.unit_id != unit.unit_id
            || commitment.unit_input_sha256 != unit.input_sha256
            || !is_sha256(&commitment.checkpoint_file_sha256)
            || unit_file_sha256(unit)?
                .is_some_and(|sha256| commitment.checkpoint_file_sha256 != sha256)
        {
            return Err(format!(
                "semantic assembly checkpoint {completed_unit_count} changed unit {} evidence",
                unit.unit_id
            ));
        }
    }
    let mut projection = checkpoint.clone();
    projection.checkpoint_sha256.clear();
    if checkpoint.checkpoint_sha256 != canonical_sha256(&projection)? {
        return Err(format!(
            "semantic assembly checkpoint {completed_unit_count} commitment changed"
        ));
    }
    if checkpoint.payload_file_size != plain_file_size(payload_path)?
        || checkpoint.payload_file_sha256 != plain_file_sha256(payload_path)?
    {
        return Err(format!(
            "semantic assembly checkpoint {completed_unit_count} payload changed"
        ));
    }
    let payload: SemanticIndex = read_json(payload_path, "semantic assembly payload")?;
    if payload.repository_root != "." {
        return Err(format!(
            "semantic assembly checkpoint {completed_unit_count} payload is not repository-relative"
        ));
    }
    Ok(payload)
}

fn plain_file_sha256(path: &Path) -> Result<String, String> {
    plain_file_size(path)?;
    let mut file = fs::File::open(path).map_err(|error| {
        format!(
            "failed to open semantic progress checkpoint {}: {error}",
            path.display()
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            format!(
                "failed to hash semantic progress checkpoint {}: {error}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn plain_file_size(path: &Path) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect semantic progress checkpoint {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > io::MAX_CHECKPOINT_BYTES
    {
        return Err(format!(
            "semantic progress checkpoint is not a bounded plain file: {}",
            path.display()
        ));
    }
    Ok(metadata.len())
}

fn remove_plain_file(path: &Path, label: &str) -> Result<(), String> {
    plain_file_size(path)?;
    fs::remove_file(path)
        .map_err(|error| format!("failed to remove {label} {}: {error}", path.display()))
}
