use super::strip_windows_verbatim_prefix;
use crate::semantic_index::{RepositoryPath, SemanticIndex};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const PROGRESS_SCHEMA_VERSION: u32 = 1;
const PROGRESS_CONTRACT: &str = "semantic-indexer-unit-progress-v1";
const SCOPE_FILE: &str = "scope.json";
const SCOPE_TEMP_FILE: &str = "scope.json.tmp";
const UNITS_DIRECTORY: &str = "units";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticProgressUnit {
    pub(super) unit_id: String,
    pub(super) contribution: String,
    pub(super) patterns: Vec<String>,
    pub(super) expected_documents: Vec<RepositoryPath>,
    pub(super) collect_calls: bool,
    pub(super) input_sha256: String,
}

impl SemanticProgressUnit {
    pub(super) fn new(
        unit_id: String,
        contribution: &str,
        patterns: Vec<String>,
        expected_documents: &BTreeSet<RepositoryPath>,
        collect_calls: bool,
    ) -> Result<Self, String> {
        require_safe_unit_id(&unit_id)?;
        let mut unit = Self {
            unit_id,
            contribution: contribution.to_string(),
            patterns,
            expected_documents: expected_documents.iter().cloned().collect(),
            collect_calls,
            input_sha256: String::new(),
        };
        unit.input_sha256 = canonical_sha256(&unit)?;
        Ok(unit)
    }

    fn validate(&self) -> Result<(), String> {
        require_safe_unit_id(&self.unit_id)?;
        if self.contribution.is_empty()
            || self.patterns.is_empty()
            || self.expected_documents.is_empty()
            || !is_sha256(&self.input_sha256)
        {
            return Err(format!(
                "semantic progress unit {} is incomplete",
                self.unit_id
            ));
        }
        let mut projection = self.clone();
        projection.input_sha256.clear();
        if self.input_sha256 != canonical_sha256(&projection)? {
            return Err(format!(
                "semantic progress unit {} commitment changed",
                self.unit_id
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticProgressScope {
    schema_version: u32,
    progress_contract: String,
    indexer: SemanticIndexerKind,
    indexer_version: String,
    installation_tree_sha256: String,
    runtime_sha256: String,
    repository_content_sha256: String,
    file_scope_sha256: String,
    build_context: BTreeMap<String, String>,
    build_context_output_sha256: String,
    package_inventory_sha256: String,
    shard_plan_sha256: String,
    units: Vec<SemanticProgressUnit>,
    scope_sha256: String,
}

pub(super) struct SemanticProgressScopeInputs {
    pub(super) indexer: SemanticIndexerKind,
    pub(super) indexer_version: String,
    pub(super) installation_tree_sha256: String,
    pub(super) runtime_sha256: String,
    pub(super) repository_content_sha256: String,
    pub(super) file_scope_sha256: String,
    pub(super) build_context: BTreeMap<String, String>,
    pub(super) build_context_output_sha256: String,
    pub(super) package_inventory_sha256: String,
    pub(super) shard_plan_sha256: String,
    pub(super) units: Vec<SemanticProgressUnit>,
}

impl SemanticProgressScope {
    pub(super) fn new(inputs: SemanticProgressScopeInputs) -> Result<Self, String> {
        let mut scope = Self {
            schema_version: PROGRESS_SCHEMA_VERSION,
            progress_contract: PROGRESS_CONTRACT.to_string(),
            indexer: inputs.indexer,
            indexer_version: inputs.indexer_version,
            installation_tree_sha256: inputs.installation_tree_sha256,
            runtime_sha256: inputs.runtime_sha256,
            repository_content_sha256: inputs.repository_content_sha256,
            file_scope_sha256: inputs.file_scope_sha256,
            build_context: inputs.build_context,
            build_context_output_sha256: inputs.build_context_output_sha256,
            package_inventory_sha256: inputs.package_inventory_sha256,
            shard_plan_sha256: inputs.shard_plan_sha256,
            units: inputs.units,
            scope_sha256: String::new(),
        };
        scope.validate_without_commitment()?;
        scope.scope_sha256 = canonical_sha256(&scope)?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), String> {
        self.validate_without_commitment()?;
        if !is_sha256(&self.scope_sha256) {
            return Err("semantic progress scope has an invalid commitment".to_string());
        }
        let mut projection = self.clone();
        projection.scope_sha256.clear();
        if self.scope_sha256 != canonical_sha256(&projection)? {
            return Err("semantic progress scope commitment changed".to_string());
        }
        Ok(())
    }

    fn validate_without_commitment(&self) -> Result<(), String> {
        if self.schema_version != PROGRESS_SCHEMA_VERSION
            || self.progress_contract != PROGRESS_CONTRACT
            || self.indexer_version.is_empty()
            || !is_sha256(&self.installation_tree_sha256)
            || !is_sha256(&self.runtime_sha256)
            || !is_sha256(&self.repository_content_sha256)
            || !is_sha256(&self.file_scope_sha256)
            || !is_sha256(&self.build_context_output_sha256)
            || !is_sha256(&self.package_inventory_sha256)
            || !is_sha256(&self.shard_plan_sha256)
            || self.units.is_empty()
        {
            return Err("semantic progress scope is incomplete".to_string());
        }
        let mut unit_ids = BTreeSet::new();
        for unit in &self.units {
            unit.validate()?;
            if !unit_ids.insert(unit.unit_id.as_str()) {
                return Err(format!(
                    "semantic progress scope repeats unit {}",
                    unit.unit_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticProgressCheckpoint {
    schema_version: u32,
    progress_contract: String,
    scope_sha256: String,
    unit_id: String,
    unit_input_sha256: String,
    payload_sha256: String,
    payload: SemanticIndex,
    checkpoint_sha256: String,
}

pub(super) struct SemanticProgressStore {
    root: PathBuf,
    scope: SemanticProgressScope,
}

impl SemanticProgressStore {
    pub(super) fn open(root: &Path, scope: SemanticProgressScope) -> Result<Self, String> {
        scope.validate()?;
        ensure_plain_directory(root)?;
        let units_root = root.join(UNITS_DIRECTORY);
        ensure_plain_directory(&units_root)?;
        ensure_plain_directory(&root.join(ASSEMBLIES_DIRECTORY))?;
        remove_incomplete_file(&root.join(SCOPE_TEMP_FILE))?;
        let scope_path = root.join(SCOPE_FILE);
        if scope_path.exists() {
            let stored: SemanticProgressScope = read_json(&scope_path, "semantic progress scope")?;
            stored.validate()?;
            if stored != scope {
                return Err(
                    "semantic progress scope disagrees with current compiler inputs".to_string(),
                );
            }
        } else {
            if fs::read_dir(&units_root)
                .map_err(|error| format!("failed to inspect semantic progress units: {error}"))?
                .next()
                .is_some()
            {
                return Err("semantic progress units exist without a committed scope".to_string());
            }
            write_atomic_new(
                &scope_path,
                &serde_json::to_vec_pretty(&scope).map_err(|error| {
                    format!("failed to serialize semantic progress scope: {error}")
                })?,
            )?;
        }
        let store = Self {
            root: root.to_path_buf(),
            scope,
        };
        store.validate_directory_entries()?;
        Ok(store)
    }

    pub(super) fn recover_existing(root: &Path) -> Result<(), String> {
        match fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "failed to inspect semantic progress root {}: {error}",
                    root.display()
                ));
            }
        }
        ensure_plain_directory(root)?;
        let units_root = root.join(UNITS_DIRECTORY);
        ensure_plain_directory(&units_root)?;
        let assemblies_root = root.join(ASSEMBLIES_DIRECTORY);
        ensure_plain_directory(&assemblies_root)?;
        remove_incomplete_file(&root.join(SCOPE_TEMP_FILE))?;
        let scope_path = root.join(SCOPE_FILE);
        if !scope_path.exists() {
            require_exact_entries(
                root,
                &BTreeSet::from([ASSEMBLIES_DIRECTORY, UNITS_DIRECTORY]),
                "semantic progress root",
            )?;
            if fs::read_dir(&units_root)
                .map_err(|error| format!("failed to inspect semantic progress units: {error}"))?
                .next()
                .is_some()
            {
                return Err("semantic progress units exist without a committed scope".to_string());
            }
            if fs::read_dir(&assemblies_root)
                .map_err(|error| {
                    format!("failed to inspect semantic progress assemblies: {error}")
                })?
                .next()
                .is_some()
            {
                return Err(
                    "semantic progress assemblies exist without a committed scope".to_string(),
                );
            }
            return Ok(());
        }
        let scope: SemanticProgressScope = read_json(&scope_path, "semantic progress scope")?;
        scope.validate()?;
        let store = Self {
            root: root.to_path_buf(),
            scope,
        };
        store.validate_directory_entries()?;
        for unit in &store.scope.units {
            store.remove_unit_temp(unit)?;
        }
        store.remove_assembly_temps()?;
        store.validate_directory_entries()?;
        if let Some(latest) = store.load_assembly_normalized()? {
            store.prune_assemblies(latest.completed_unit_count)?;
        }
        store.validate_directory_entries()
    }

    pub(super) fn load(
        &self,
        unit: &SemanticProgressUnit,
        repository_root: &Path,
    ) -> Result<Option<SemanticIndex>, String> {
        self.require_unit(unit)?;
        self.remove_unit_temp(unit)?;
        self.validate_directory_entries()?;
        let path = self.unit_path(unit);
        if !path.exists() {
            return Ok(None);
        }
        let checkpoint: SemanticProgressCheckpoint =
            read_json(&path, "semantic progress checkpoint")?;
        validate_checkpoint(&self.scope, unit, &checkpoint)?;
        let mut payload = checkpoint.payload;
        bind_repository_root(&mut payload, repository_root)?;
        Ok(Some(payload))
    }

    pub(super) fn publish(
        &self,
        unit: &SemanticProgressUnit,
        repository_root: &Path,
        payload: &SemanticIndex,
    ) -> Result<(), String> {
        self.require_unit(unit)?;
        self.remove_unit_temp(unit)?;
        self.validate_directory_entries()?;
        let path = self.unit_path(unit);
        if path.exists() {
            return Err(format!(
                "semantic progress checkpoint {} already exists",
                unit.unit_id
            ));
        }
        let payload = normalize_repository_root(payload, repository_root)?;
        let payload_sha256 = canonical_sha256(&payload)?;
        let mut checkpoint = SemanticProgressCheckpoint {
            schema_version: PROGRESS_SCHEMA_VERSION,
            progress_contract: PROGRESS_CONTRACT.to_string(),
            scope_sha256: self.scope.scope_sha256.clone(),
            unit_id: unit.unit_id.clone(),
            unit_input_sha256: unit.input_sha256.clone(),
            payload_sha256,
            payload,
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint)?;
        write_atomic_new(
            &path,
            &serde_json::to_vec(&checkpoint).map_err(|error| {
                format!("failed to serialize semantic progress checkpoint: {error}")
            })?,
        )
    }

    fn require_unit(&self, unit: &SemanticProgressUnit) -> Result<(), String> {
        unit.validate()?;
        if !self.scope.units.contains(unit) {
            return Err(format!(
                "semantic progress unit {} is outside the committed scope",
                unit.unit_id
            ));
        }
        Ok(())
    }

    fn unit_path(&self, unit: &SemanticProgressUnit) -> PathBuf {
        self.root
            .join(UNITS_DIRECTORY)
            .join(format!("{}.json", unit.unit_id))
    }

    fn unit_temp_path(&self, unit: &SemanticProgressUnit) -> PathBuf {
        self.root
            .join(UNITS_DIRECTORY)
            .join(format!("{}.json.tmp", unit.unit_id))
    }

    fn remove_unit_temp(&self, unit: &SemanticProgressUnit) -> Result<(), String> {
        remove_incomplete_file(&self.unit_temp_path(unit))
    }

    fn validate_directory_entries(&self) -> Result<(), String> {
        let expected_root = BTreeSet::from([ASSEMBLIES_DIRECTORY, SCOPE_FILE, UNITS_DIRECTORY]);
        require_exact_entries(&self.root, &expected_root, "semantic progress root")?;
        let expected_units = self
            .scope
            .units
            .iter()
            .flat_map(|unit| {
                [
                    format!("{}.json", unit.unit_id),
                    format!("{}.json.tmp", unit.unit_id),
                ]
            })
            .collect::<BTreeSet<_>>();
        require_allowed_entries(
            &self.root.join(UNITS_DIRECTORY),
            &expected_units,
            "semantic progress units",
        )?;
        require_allowed_entries(
            &self.root.join(ASSEMBLIES_DIRECTORY),
            &assembly::allowed_entry_names(self.scope.units.len()),
            "semantic progress assemblies",
        )
    }
}

fn validate_checkpoint(
    scope: &SemanticProgressScope,
    unit: &SemanticProgressUnit,
    checkpoint: &SemanticProgressCheckpoint,
) -> Result<(), String> {
    if checkpoint.schema_version != PROGRESS_SCHEMA_VERSION
        || checkpoint.progress_contract != PROGRESS_CONTRACT
        || checkpoint.scope_sha256 != scope.scope_sha256
        || checkpoint.unit_id != unit.unit_id
        || checkpoint.unit_input_sha256 != unit.input_sha256
        || !is_sha256(&checkpoint.payload_sha256)
        || !is_sha256(&checkpoint.checkpoint_sha256)
        || checkpoint.payload.repository_root != "."
        || checkpoint.payload_sha256 != canonical_sha256(&checkpoint.payload)?
    {
        return Err(format!(
            "semantic progress checkpoint {} changed immutable evidence",
            unit.unit_id
        ));
    }
    let mut projection = checkpoint.clone();
    projection.checkpoint_sha256.clear();
    if checkpoint.checkpoint_sha256 != canonical_sha256(&projection)? {
        return Err(format!(
            "semantic progress checkpoint {} commitment changed",
            unit.unit_id
        ));
    }
    Ok(())
}

fn normalize_repository_root(
    payload: &SemanticIndex,
    repository_root: &Path,
) -> Result<SemanticIndex, String> {
    let expected = canonical_root_text(repository_root)?;
    if payload.repository_root != expected {
        return Err(format!(
            "semantic progress payload repository root changed: expected {expected}, found {}",
            payload.repository_root
        ));
    }
    let mut normalized = payload.clone();
    normalized.repository_root = ".".to_string();
    Ok(normalized)
}

fn bind_repository_root(payload: &mut SemanticIndex, repository_root: &Path) -> Result<(), String> {
    if payload.repository_root != "." {
        return Err("semantic progress payload is not repository-relative".to_string());
    }
    payload.repository_root = canonical_root_text(repository_root)?;
    Ok(())
}

fn canonical_root_text(root: &Path) -> Result<String, String> {
    fs::canonicalize(root)
        .map(strip_windows_verbatim_prefix)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| {
            format!(
                "failed to resolve semantic progress repository root {}: {error}",
                root.display()
            )
        })
}

#[path = "semantic_indexer_progress_assembly.rs"]
mod assembly;

use assembly::ASSEMBLIES_DIRECTORY;

#[path = "semantic_indexer_progress_io.rs"]
mod io;

use io::{
    ensure_plain_directory, read_json, remove_incomplete_file, require_allowed_entries,
    require_exact_entries, write_atomic_new, write_json_atomic_new,
};

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to serialize semantic progress commitment: {error}"))
}

fn require_safe_unit_id(value: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Ok(());
    }
    Err("semantic progress unit ID is unsafe".to_string())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
#[path = "semantic_indexer_progress_tests.rs"]
mod tests;
