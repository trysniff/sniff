use super::history_v2_exclusion_identity::{
    repositories, research_repositories, validate_history_worksheet,
};
use super::{
    BenchmarkSourceSeal, HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION,
    HistoricalV2ExclusionArtifact, HistoricalV2ExclusionManifest, HistoricalV2PartitionExclusions,
    IntentionalBoundaryFrameTask, NonBlindHistoryWorksheet, NonBlindSelectionPolicy,
    seal_historical_v2_exclusion_manifest, validate_historical_v2_protocol,
    validate_intentional_boundary_frame_task,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const BLIND_SEAL: &str = "sniffbench/blind-oss-v1-source-seal.json";
const HISTORY_WORKSHEET: &str = "sniffbench/non-blind-v1-history-worksheet.json";
const NON_BLIND_POLICY: &str = "sniffbench/non-blind-v1-selection-policy.json";
const BOUNDARY_PROTOCOL: &str = "sniffbench/non-blind-v1-intentional-boundary-protocol.json";
const BOUNDARY_TASK: &str = "sniffbench/non-blind-v1-intentional-boundary-frame-task.json";
const SYNTHETIC_REPOSITORY: &str = "trysniff/sniff";
const GOLD_FILES: [&str; 12] = [
    "gold_fixtures/repo/go/main.go",
    "gold_fixtures/repo/go/math.go",
    "gold_fixtures/repo/helpers.py",
    "gold_fixtures/repo/helpers.ts",
    "gold_fixtures/repo/javascript/helpers.js",
    "gold_fixtures/repo/javascript/main.js",
    "gold_fixtures/repo/kotlin/main.kt",
    "gold_fixtures/repo/kotlin/math.kt",
    "gold_fixtures/repo/python_main.py",
    "gold_fixtures/repo/rust/main.rs",
    "gold_fixtures/repo/rust/math.rs",
    "gold_fixtures/repo/ts_main.ts",
];

pub fn derive_historical_v2_exclusion_manifest(
    protocol_bytes: &[u8],
    artifact_root: &Path,
) -> Result<HistoricalV2ExclusionManifest, String> {
    let protocol = validate_historical_v2_protocol(protocol_bytes)?;
    let root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("failed to resolve historical-v2 artifact root: {error}"))?;
    validate_gold_inventory(&root)?;

    let blind_bytes = read_artifact(&root, BLIND_SEAL)?;
    let history_bytes = read_artifact(&root, HISTORY_WORKSHEET)?;
    let policy_bytes = read_artifact(&root, NON_BLIND_POLICY)?;
    let boundary_protocol_bytes = read_artifact(&root, BOUNDARY_PROTOCOL)?;
    let boundary_task_bytes = read_artifact(&root, BOUNDARY_TASK)?;

    let blind: BenchmarkSourceSeal = parse_artifact(BLIND_SEAL, &blind_bytes)?;
    if blind.selection_id != "sniffbench-blind-oss-v1-composite"
        || blind.computed_seal_sha256()? != blind.seal_sha256
    {
        return Err("blind-oss-v1 source seal commitment changed".to_string());
    }
    let blind_repositories = repositories(
        blind
            .sources
            .iter()
            .map(|source| source.repository.as_str()),
    )?;
    if blind_repositories.is_empty() {
        return Err("blind-oss-v1 exclusion source is empty".to_string());
    }

    let policy: NonBlindSelectionPolicy = parse_artifact(NON_BLIND_POLICY, &policy_bytes)?;
    let history: NonBlindHistoryWorksheet = parse_artifact(HISTORY_WORKSHEET, &history_bytes)?;
    validate_history_worksheet(
        &policy_bytes,
        &policy,
        &blind_bytes,
        &blind_repositories,
        &history,
    )?;
    let historical_repositories = repositories(
        history
            .candidates
            .iter()
            .map(|candidate| candidate.repository.as_str()),
    )?;

    let boundary_task: IntentionalBoundaryFrameTask =
        parse_artifact(BOUNDARY_TASK, &boundary_task_bytes)?;
    validate_intentional_boundary_frame_task(
        &policy_bytes,
        &history_bytes,
        &blind_bytes,
        &boundary_protocol_bytes,
        &boundary_task,
    )?;
    let boundary_repositories = repositories(
        boundary_task
            .repositories
            .iter()
            .map(|repository| repository.repository.as_str()),
    )?;
    let research_repositories = research_repositories(&policy)?;

    let blind_artifacts = artifact_commitments(&root, &[BLIND_SEAL])?;
    let history_artifacts =
        artifact_commitments(&root, &[BLIND_SEAL, HISTORY_WORKSHEET, NON_BLIND_POLICY])?;
    let boundary_artifacts = artifact_commitments(
        &root,
        &[
            BLIND_SEAL,
            HISTORY_WORKSHEET,
            BOUNDARY_TASK,
            BOUNDARY_PROTOCOL,
            NON_BLIND_POLICY,
        ],
    )?;
    let research_artifacts = artifact_commitments(&root, &[NON_BLIND_POLICY])?;
    let synthetic_artifacts = artifact_commitments(&root, &GOLD_FILES)?;
    let partitions = vec![
        partition("blind-oss-v1", blind_artifacts, blind_repositories),
        partition("historical-v1", history_artifacts, historical_repositories),
        partition(
            "intentional-boundary-v1",
            boundary_artifacts,
            boundary_repositories,
        ),
        partition(
            "slopcodebench",
            research_artifacts.clone(),
            research_repositories
                .get("slopcodebench")
                .cloned()
                .ok_or_else(|| "SlopCodeBench exclusion source is missing".to_string())?,
        ),
        partition(
            "synthetic-gold-v1",
            synthetic_artifacts,
            vec![SYNTHETIC_REPOSITORY.to_string()],
        ),
        partition(
            "trim",
            research_artifacts,
            research_repositories
                .get("trim")
                .cloned()
                .ok_or_else(|| "TRIM exclusion source is missing".to_string())?,
        ),
    ];
    let repository_count = partitions
        .iter()
        .flat_map(|partition| partition.repositories.iter())
        .collect::<BTreeSet<_>>()
        .len();
    seal_historical_v2_exclusion_manifest(
        protocol_bytes,
        &root,
        HistoricalV2ExclusionManifest {
            schema_version: HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION,
            protocol_sha256: protocol.protocol_sha256,
            partitions,
            repository_count,
            manifest_sha256: String::new(),
        },
    )
}

pub fn write_derived_historical_v2_exclusion_manifest(
    protocol_bytes: &[u8],
    artifact_root: &Path,
    output_path: &Path,
) -> Result<HistoricalV2ExclusionManifest, String> {
    let manifest = derive_historical_v2_exclusion_manifest(protocol_bytes, artifact_root)?;
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        format!("failed to serialize historical-v2 exclusion manifest: {error}")
    })?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)
        .map_err(|error| format!("failed to create historical-v2 exclusion manifest: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 exclusion manifest: {error}"))?;
    Ok(manifest)
}

fn partition(
    partition: &str,
    artifacts: Vec<HistoricalV2ExclusionArtifact>,
    repositories: Vec<String>,
) -> HistoricalV2PartitionExclusions {
    HistoricalV2PartitionExclusions {
        partition: partition.to_string(),
        artifacts,
        repositories,
    }
}

fn artifact_commitments(
    root: &Path,
    paths: &[&str],
) -> Result<Vec<HistoricalV2ExclusionArtifact>, String> {
    paths
        .iter()
        .map(|path| {
            read_artifact(root, path).map(|bytes| HistoricalV2ExclusionArtifact {
                artifact_path: (*path).to_string(),
                artifact_sha256: sha256(&bytes),
            })
        })
        .collect()
}

fn validate_gold_inventory(root: &Path) -> Result<(), String> {
    let mut actual = Vec::new();
    collect_files(root, &root.join("gold_fixtures/repo"), &mut actual)?;
    actual.sort();
    if actual != GOLD_FILES {
        return Err("synthetic-gold-v1 source inventory changed".to_string());
    }
    Ok(())
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("failed to read synthetic gold inventory: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("failed to read synthetic gold entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect synthetic gold entry: {error}"))?;
        if file_type.is_symlink() {
            return Err("synthetic gold inventory contains a symlink".to_string());
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| "synthetic gold source escapes artifact root".to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            files.push(relative);
        } else {
            return Err("synthetic gold inventory contains a non-file entry".to_string());
        }
    }
    Ok(())
}

fn read_artifact(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let relative_path = safe_relative_path(relative)?;
    let path = fs::canonicalize(root.join(relative_path))
        .map_err(|error| format!("failed to resolve exclusion source {relative}: {error}"))?;
    if !path.starts_with(root) {
        return Err(format!(
            "exclusion source escapes artifact root: {relative}"
        ));
    }
    fs::read(path).map_err(|error| format!("failed to read exclusion source {relative}: {error}"))
}

fn safe_relative_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe exclusion source path: {value}"));
    }
    Ok(path.to_path_buf())
}

fn parse_artifact<T: serde::de::DeserializeOwned>(label: &str, bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("failed to parse {label}: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
