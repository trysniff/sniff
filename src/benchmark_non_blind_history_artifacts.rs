use super::{
    HistoricalAssessmentEvidence, HistoricalEvidenceKind, HistoricalRepositoryAssessment,
    ProvenanceArtifact, SourceSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_FILE: &str = "_transaction.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RankTransaction {
    schema_version: u32,
    task_sha256: String,
    rank: usize,
    assessment: HistoricalRepositoryAssessment,
    files: Vec<CommittedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedFile {
    artifact_path: String,
    sha256: String,
}

pub(super) struct RankArtifactWriter {
    state_root: PathBuf,
    staging_root: PathBuf,
    final_root: PathBuf,
    final_prefix: String,
}

impl RankArtifactWriter {
    pub(super) fn create(state_root: &Path, work_root: &Path, rank: usize) -> Result<Self, String> {
        let state_root = canonical_directory(state_root, "historical state root")?;
        let work_root = canonical_directory(work_root, "historical work root")?;
        require_child(&state_root, &work_root, "historical work root")?;
        let artifacts_root = state_root.join("artifacts");
        fs::create_dir_all(&artifacts_root)
            .map_err(|error| format!("failed to create historical artifact root: {error}"))?;
        let artifacts_root = canonical_directory(&artifacts_root, "historical artifact root")?;
        require_child(&state_root, &artifacts_root, "historical artifact root")?;

        let name = format!("rank-{rank:04}");
        let staging_root = work_root.join(format!("{name}-artifacts"));
        let final_root = artifacts_root.join(&name);
        if staging_root.exists() {
            remove_tree_inside(&work_root, &staging_root)?;
        }
        if final_root.exists() {
            return Err(format!(
                "historical rank artifact already exists: {}",
                final_root.display()
            ));
        }
        fs::create_dir(&staging_root).map_err(|error| {
            format!(
                "failed to create historical rank staging directory {}: {error}",
                staging_root.display()
            )
        })?;
        Ok(Self {
            state_root,
            staging_root,
            final_root,
            final_prefix: format!("artifacts/{name}"),
        })
    }

    pub(super) fn evidence_json<T: Serialize>(
        &self,
        kind: HistoricalEvidenceKind,
        source: impl Into<String>,
        observed_at: &str,
        relative_path: &str,
        value: &T,
    ) -> Result<HistoricalAssessmentEvidence, String> {
        let mut bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| format!("failed to serialize historical evidence: {error}"))?;
        bytes.push(b'\n');
        let artifact = self.write_bytes(relative_path, &bytes)?;
        Ok(HistoricalAssessmentEvidence {
            kind,
            source: source.into(),
            observed_at: observed_at.to_string(),
            artifact_path: artifact.artifact_path,
            sha256: artifact.sha256,
        })
    }

    pub(super) fn provenance_artifact(
        &self,
        relative_path: &str,
        bytes: &[u8],
        description: impl Into<String>,
    ) -> Result<ProvenanceArtifact, String> {
        let artifact = self.write_bytes(relative_path, bytes)?;
        Ok(ProvenanceArtifact {
            artifact_path: artifact.artifact_path,
            sha256: artifact.sha256,
            description: description.into(),
        })
    }

    pub(super) fn source_snapshot(
        &self,
        snapshot_root: &Path,
        repository: &str,
        revision: &str,
        repository_path: &str,
        side: &str,
    ) -> Result<SourceSnapshot, String> {
        require_safe_relative(repository_path)?;
        let source = canonical_file_inside(snapshot_root, repository_path)?;
        let bytes = fs::read(&source).map_err(|error| {
            format!(
                "failed to read historical source snapshot {}: {error}",
                source.display()
            )
        })?;
        let relative = format!("sources/{side}/{repository_path}");
        let artifact = self.write_bytes(&relative, &bytes)?;
        Ok(SourceSnapshot {
            repository: repository.to_string(),
            revision: revision.to_string(),
            repository_path: repository_path.to_string(),
            artifact_path: artifact.artifact_path,
            sha256: artifact.sha256,
        })
    }

    pub(super) fn write_bytes(
        &self,
        relative_path: &str,
        bytes: &[u8],
    ) -> Result<ProvenanceArtifact, String> {
        require_safe_relative(relative_path)?;
        if relative_path == TRANSACTION_FILE {
            return Err("historical evidence cannot replace its transaction manifest".to_string());
        }
        let path = self.staging_root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create historical artifact parent: {error}"))?;
        }
        write_new_synced(&path, bytes)?;
        Ok(ProvenanceArtifact {
            artifact_path: format!("{}/{relative_path}", self.final_prefix).replace('\\', "/"),
            sha256: sha256(bytes),
            description: String::new(),
        })
    }

    pub(super) fn publish(
        self,
        task_sha256: &str,
        assessment: &HistoricalRepositoryAssessment,
    ) -> Result<(), String> {
        if assessment.candidate.rank == 0 || assessment.disposition.is_none() {
            return Err("historical rank transaction requires a completed assessment".to_string());
        }
        let files = inventory_files(
            &self.staging_root,
            &self.final_prefix,
            Some(TRANSACTION_FILE),
        )?;
        let transaction = RankTransaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            task_sha256: task_sha256.to_string(),
            rank: assessment.candidate.rank,
            assessment: assessment.clone(),
            files,
        };
        let mut bytes = serde_json::to_vec_pretty(&transaction)
            .map_err(|error| format!("failed to serialize historical transaction: {error}"))?;
        bytes.push(b'\n');
        write_new_synced(&self.staging_root.join(TRANSACTION_FILE), &bytes)?;
        fs::rename(&self.staging_root, &self.final_root).map_err(|error| {
            format!(
                "failed to publish historical rank artifacts {}: {error}",
                self.final_root.display()
            )
        })?;
        verify_published_rank(&self.state_root, assessment.candidate.rank, task_sha256)?
            .ok_or_else(|| "published historical rank disappeared".to_string())?;
        Ok(())
    }
}

pub(super) fn verify_published_rank(
    state_root: &Path,
    rank: usize,
    task_sha256: &str,
) -> Result<Option<HistoricalRepositoryAssessment>, String> {
    let state_root = canonical_directory(state_root, "historical state root")?;
    let rank_root = state_root.join("artifacts").join(format!("rank-{rank:04}"));
    if !rank_root.exists() {
        return Ok(None);
    }
    let rank_root = canonical_directory(&rank_root, "historical rank artifact")?;
    require_child(&state_root, &rank_root, "historical rank artifact")?;
    let transaction_path = rank_root.join(TRANSACTION_FILE);
    let transaction: RankTransaction =
        serde_json::from_slice(&fs::read(&transaction_path).map_err(|error| {
            format!(
                "failed to read historical transaction {}: {error}",
                transaction_path.display()
            )
        })?)
        .map_err(|error| format!("invalid historical rank transaction: {error}"))?;
    if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
        || transaction.task_sha256 != task_sha256
        || transaction.rank != rank
        || transaction.assessment.candidate.rank != rank
        || transaction.assessment.disposition.is_none()
    {
        return Err(format!(
            "historical rank {rank} transaction changed its immutable task"
        ));
    }
    let prefix = format!("artifacts/rank-{rank:04}");
    let actual = inventory_files(&rank_root, &prefix, Some(TRANSACTION_FILE))?;
    if actual != transaction.files {
        return Err(format!(
            "historical rank {rank} artifact inventory does not match its transaction"
        ));
    }
    verify_assessment_artifact_references(&transaction.assessment, &transaction.files, &prefix)?;
    Ok(Some(transaction.assessment))
}

fn verify_assessment_artifact_references(
    assessment: &HistoricalRepositoryAssessment,
    files: &[CommittedFile],
    prefix: &str,
) -> Result<(), String> {
    let committed = files
        .iter()
        .map(|file| (file.artifact_path.as_str(), file.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut referenced = BTreeSet::new();
    for evidence in &assessment.evidence {
        require_committed(
            &committed,
            prefix,
            &evidence.artifact_path,
            &evidence.sha256,
        )?;
        referenced.insert(evidence.artifact_path.as_str());
    }
    if let Some(provenance) = &assessment.selected_provenance {
        for snapshot in provenance.before.iter().chain(&provenance.after) {
            require_committed(
                &committed,
                prefix,
                &snapshot.artifact_path,
                &snapshot.sha256,
            )?;
            referenced.insert(snapshot.artifact_path.as_str());
        }
        for artifact in
            std::iter::once(&provenance.license).chain(provenance.behavioral_evidence.iter())
        {
            require_committed(
                &committed,
                prefix,
                &artifact.artifact_path,
                &artifact.sha256,
            )?;
            referenced.insert(artifact.artifact_path.as_str());
        }
    }
    if referenced.is_empty() {
        return Err("historical rank transaction has no referenced evidence".to_string());
    }
    Ok(())
}

fn require_committed(
    files: &BTreeMap<&str, &str>,
    prefix: &str,
    path: &str,
    sha256: &str,
) -> Result<(), String> {
    if !path.starts_with(&format!("{prefix}/")) || files.get(path).copied() != Some(sha256) {
        return Err(format!(
            "historical artifact reference is outside or absent from its rank transaction: {path}"
        ));
    }
    Ok(())
}

fn inventory_files(
    root: &Path,
    final_prefix: &str,
    excluded_name: Option<&str>,
) -> Result<Vec<CommittedFile>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("failed to inventory historical artifacts: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("failed to inspect historical artifact: {error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("failed to inspect historical artifact: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("historical artifact transaction cannot contain symlinks".to_string());
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err("historical artifact transaction contains a special file".to_string());
            }
            if path.parent() == Some(root)
                && path.file_name().and_then(|name| name.to_str()) == excluded_name
            {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "historical artifact escaped its transaction".to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&path)
                .map_err(|error| format!("failed to hash historical artifact: {error}"))?;
            files.push(CommittedFile {
                artifact_path: format!("{final_prefix}/{relative}"),
                sha256: sha256(&bytes),
            });
        }
    }
    files.sort();
    Ok(files)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "failed to create historical artifact {}: {error}",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to persist historical artifact {}: {error}",
                path.display()
            )
        })
}

fn canonical_file_inside(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let root = canonical_directory(root, "historical snapshot root")?;
    let path = fs::canonicalize(root.join(relative)).map_err(|error| {
        format!("failed to resolve historical snapshot source {relative}: {error}")
    })?;
    require_child(&root, &path, "historical snapshot source")?;
    if !path.is_file() {
        return Err(format!(
            "historical snapshot source is not a file: {relative}"
        ));
    }
    Ok(path)
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if path.is_dir() {
        Ok(path)
    } else {
        Err(format!("{label} is not a directory: {}", path.display()))
    }
}

fn require_child(root: &Path, path: &Path, label: &str) -> Result<(), String> {
    if path.starts_with(root) && path != root {
        Ok(())
    } else {
        Err(format!(
            "{label} escaped its state root: {}",
            path.display()
        ))
    }
}

fn remove_tree_inside(root: &Path, path: &Path) -> Result<(), String> {
    let root = canonical_directory(root, "historical work root")?;
    let path = fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve stale historical work: {error}"))?;
    require_child(&root, &path, "stale historical work")?;
    fs::remove_dir_all(&path).map_err(|error| {
        format!(
            "failed to remove stale historical work {}: {error}",
            path.display()
        )
    })
}

fn require_safe_relative(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(format!(
            "historical artifact path must stay relative: {value}"
        ))
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
