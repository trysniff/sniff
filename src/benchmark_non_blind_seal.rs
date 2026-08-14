use super::{BenchmarkPartition, SourceSnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path};

pub const NON_BLIND_SOURCE_SEAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonBlindSourceKind {
    HistoricalSimplification,
    SlopCodeBenchTrajectory,
    TrimTrajectory,
    IntentionalBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceArtifact {
    pub artifact_path: String,
    pub sha256: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonBlindSourceEntry {
    pub provenance_id: String,
    pub partition: BenchmarkPartition,
    pub source_kind: NonBlindSourceKind,
    pub upstream_url: String,
    pub upstream_revision: String,
    pub upstream_record_id: String,
    pub selection_rationale: String,
    pub before: Vec<SourceSnapshot>,
    pub after: Vec<SourceSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_after_paths: Vec<String>,
    pub license: ProvenanceArtifact,
    pub behavioral_evidence: Vec<ProvenanceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonBlindSourceSeal {
    pub schema_version: u32,
    pub seal_id: String,
    pub frozen_at: String,
    pub selection_policy: ProvenanceArtifact,
    pub selection_protocol: String,
    pub sealed_before_sniff_analysis: bool,
    pub entries: Vec<NonBlindSourceEntry>,
    pub seal_sha256: String,
}

impl NonBlindSourceSeal {
    pub fn computed_seal_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct CommittedSeal<'a> {
            schema_version: u32,
            seal_id: &'a str,
            frozen_at: &'a str,
            selection_policy: &'a ProvenanceArtifact,
            selection_protocol: &'a str,
            sealed_before_sniff_analysis: bool,
            entries: Vec<&'a NonBlindSourceEntry>,
        }

        let mut entries = self.entries.iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.provenance_id.cmp(&right.provenance_id));
        let bytes = serde_json::to_vec(&CommittedSeal {
            schema_version: self.schema_version,
            seal_id: &self.seal_id,
            frozen_at: &self.frozen_at,
            selection_policy: &self.selection_policy,
            selection_protocol: &self.selection_protocol,
            sealed_before_sniff_analysis: self.sealed_before_sniff_analysis,
            entries,
        })
        .map_err(|error| format!("failed to serialize non-blind source seal: {error}"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

pub fn freeze_non_blind_source_seal(
    mut seal: NonBlindSourceSeal,
    artifact_root: &Path,
) -> Result<NonBlindSourceSeal, String> {
    seal.seal_sha256 = seal.computed_seal_sha256()?;
    validate_non_blind_source_seal(&seal, artifact_root)?;
    Ok(seal)
}

pub fn validate_non_blind_source_seal(
    seal: &NonBlindSourceSeal,
    artifact_root: &Path,
) -> Result<(), String> {
    if seal.schema_version != NON_BLIND_SOURCE_SEAL_SCHEMA_VERSION {
        return Err(format!(
            "non-blind source seal schema_version must be {NON_BLIND_SOURCE_SEAL_SCHEMA_VERSION}"
        ));
    }
    require_text("non-blind seal_id", &seal.seal_id)?;
    require_text("non-blind frozen_at", &seal.frozen_at)?;
    require_text("non-blind selection_protocol", &seal.selection_protocol)?;
    if !seal.sealed_before_sniff_analysis {
        return Err(
            "non-blind source seal must attest that selection preceded Sniff analysis".to_string(),
        );
    }
    if seal.entries.is_empty() {
        return Err("non-blind source seal cannot be empty".to_string());
    }
    let root = fs::canonicalize(artifact_root).map_err(|error| {
        format!(
            "failed to resolve non-blind artifact root {}: {error}",
            artifact_root.display()
        )
    })?;
    validate_artifact(&seal.selection_policy, &root, "selection policy")?;
    let mut ids = HashSet::new();
    let mut partitions = HashSet::new();
    let mut source_kinds = HashSet::new();
    for entry in &seal.entries {
        validate_entry(entry, &root)?;
        if !ids.insert(entry.provenance_id.as_str()) {
            return Err(format!(
                "non-blind source seal repeats provenance_id {}",
                entry.provenance_id
            ));
        }
        partitions.insert(entry.partition);
        source_kinds.insert(entry.source_kind);
    }
    for partition in [
        BenchmarkPartition::HistoricalSimplification,
        BenchmarkPartition::ResearchTrajectory,
        BenchmarkPartition::IntentionalBoundary,
    ] {
        if !partitions.contains(&partition) {
            return Err(format!(
                "non-blind source seal is missing partition {partition:?}"
            ));
        }
    }
    for source_kind in [
        NonBlindSourceKind::SlopCodeBenchTrajectory,
        NonBlindSourceKind::TrimTrajectory,
    ] {
        if !source_kinds.contains(&source_kind) {
            return Err(format!(
                "non-blind source seal is missing required research source {source_kind:?}"
            ));
        }
    }
    let expected = seal.computed_seal_sha256()?;
    if !seal.seal_sha256.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "non-blind source seal commitment mismatch; expected {expected}"
        ));
    }
    Ok(())
}

fn validate_entry(entry: &NonBlindSourceEntry, root: &Path) -> Result<(), String> {
    require_text("non-blind provenance_id", &entry.provenance_id)?;
    require_immutable_revision("non-blind upstream_revision", &entry.upstream_revision)?;
    require_text("non-blind upstream_record_id", &entry.upstream_record_id)?;
    require_text("non-blind selection_rationale", &entry.selection_rationale)?;
    if !entry.upstream_url.starts_with("https://") {
        return Err(format!(
            "non-blind entry {} requires an HTTPS upstream_url",
            entry.provenance_id
        ));
    }
    let expected_partition = match entry.source_kind {
        NonBlindSourceKind::HistoricalSimplification => {
            BenchmarkPartition::HistoricalSimplification
        }
        NonBlindSourceKind::SlopCodeBenchTrajectory | NonBlindSourceKind::TrimTrajectory => {
            BenchmarkPartition::ResearchTrajectory
        }
        NonBlindSourceKind::IntentionalBoundary => BenchmarkPartition::IntentionalBoundary,
    };
    if entry.partition != expected_partition {
        return Err(format!(
            "non-blind entry {} source kind does not match its partition",
            entry.provenance_id
        ));
    }
    if entry.before.is_empty() {
        return Err(format!(
            "non-blind entry {} requires before source",
            entry.provenance_id
        ));
    }
    if entry.partition != BenchmarkPartition::IntentionalBoundary
        && entry.after.is_empty()
        && entry.removed_after_paths.is_empty()
    {
        return Err(format!(
            "non-blind simplification entry {} requires after source or explicit removals",
            entry.provenance_id
        ));
    }
    if entry.partition == BenchmarkPartition::IntentionalBoundary
        && !entry.removed_after_paths.is_empty()
    {
        return Err(format!(
            "intentional-boundary entry {} cannot claim removed after paths",
            entry.provenance_id
        ));
    }
    let after_paths = entry
        .after
        .iter()
        .map(|snapshot| snapshot.repository_path.as_str())
        .collect::<HashSet<_>>();
    let removed_paths = entry
        .removed_after_paths
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if removed_paths.len() != entry.removed_after_paths.len()
        || entry
            .removed_after_paths
            .iter()
            .any(|path| require_safe_path(path).is_err())
        || !after_paths.is_disjoint(&removed_paths)
    {
        return Err(format!(
            "non-blind entry {} has invalid removed after paths",
            entry.provenance_id
        ));
    }
    if entry.behavioral_evidence.is_empty() {
        return Err(format!(
            "non-blind entry {} requires behavioral evidence artifacts",
            entry.provenance_id
        ));
    }
    for snapshot in entry.before.iter().chain(&entry.after) {
        require_immutable_revision("non-blind source revision", &snapshot.revision)?;
        validate_snapshot(snapshot, root)?;
    }
    validate_artifact(&entry.license, root, "license")?;
    for artifact in &entry.behavioral_evidence {
        validate_artifact(artifact, root, "behavioral evidence")?;
    }
    Ok(())
}

fn validate_snapshot(snapshot: &SourceSnapshot, root: &Path) -> Result<(), String> {
    require_text("non-blind repository", &snapshot.repository)?;
    require_text("non-blind revision", &snapshot.revision)?;
    require_text("non-blind repository_path", &snapshot.repository_path)?;
    validate_path_and_hash(root, &snapshot.artifact_path, &snapshot.sha256, "source")
}

fn validate_artifact(
    artifact: &ProvenanceArtifact,
    root: &Path,
    label: &str,
) -> Result<(), String> {
    require_text(
        &format!("non-blind {label} description"),
        &artifact.description,
    )?;
    validate_path_and_hash(root, &artifact.artifact_path, &artifact.sha256, label)
}

fn validate_path_and_hash(
    root: &Path,
    artifact_path: &str,
    expected_hash: &str,
    label: &str,
) -> Result<(), String> {
    require_safe_path(artifact_path)?;
    require_sha256(&format!("non-blind {label} sha256"), expected_hash)?;
    let resolved = fs::canonicalize(root.join(artifact_path))
        .map_err(|error| format!("failed to resolve non-blind {label} {artifact_path}: {error}"))?;
    if !resolved.starts_with(root) {
        return Err(format!(
            "non-blind {label} {artifact_path} escapes the artifact root"
        ));
    }
    let bytes = fs::read(&resolved)
        .map_err(|error| format!("failed to read non-blind {label} {artifact_path}: {error}"))?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected_hash) {
        return Err(format!(
            "non-blind {label} {artifact_path} hash mismatch: expected {expected_hash}, got {actual}"
        ));
    }
    Ok(())
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{label} must be a SHA-256 hex digest"))
    }
}

fn require_immutable_revision(label: &str, value: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "{label} must be an immutable 40- or 64-character hexadecimal revision"
        ))
    }
}

fn require_safe_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("non-blind artifact path cannot be empty".to_string());
    }
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "non-blind artifact path must stay relative: {path}"
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_test_non_blind_source_seal(
    root: &Path,
    cases: &mut [super::ReleaseBenchmarkCase],
) -> (String, String) {
    let license_path = "non-blind/LICENSE.txt";
    let evidence_path = "non-blind/behavior.txt";
    let policy_path = "non-blind/selection-policy.json";
    fs::create_dir_all(root.join("non-blind")).expect("create non-blind fixture directory");
    fs::write(root.join(license_path), "fixture license\n").expect("write fixture license");
    fs::write(root.join(evidence_path), "fixture behavior preserved\n")
        .expect("write fixture evidence");
    fs::write(root.join(policy_path), b"{\"fixture\":true}\n")
        .expect("write fixture selection policy");
    let license = ProvenanceArtifact {
        artifact_path: license_path.to_string(),
        sha256: format!("{:x}", Sha256::digest(b"fixture license\n")),
        description: "Fixture source license".to_string(),
    };
    let evidence = ProvenanceArtifact {
        artifact_path: evidence_path.to_string(),
        sha256: format!("{:x}", Sha256::digest(b"fixture behavior preserved\n")),
        description: "Fixture behavioral evidence".to_string(),
    };
    let mut entries = Vec::new();
    let mut research_count = 0usize;
    for case in cases.iter_mut().filter(|case| {
        matches!(
            case.partition,
            BenchmarkPartition::HistoricalSimplification
                | BenchmarkPartition::ResearchTrajectory
                | BenchmarkPartition::IntentionalBoundary
        )
    }) {
        let provenance_id = format!("provenance-{}", case.label.case_id);
        case.provenance_id = Some(provenance_id.clone());
        let source_kind = match case.partition {
            BenchmarkPartition::HistoricalSimplification => {
                NonBlindSourceKind::HistoricalSimplification
            }
            BenchmarkPartition::ResearchTrajectory => {
                research_count += 1;
                if research_count == 1 {
                    NonBlindSourceKind::SlopCodeBenchTrajectory
                } else {
                    NonBlindSourceKind::TrimTrajectory
                }
            }
            BenchmarkPartition::IntentionalBoundary => NonBlindSourceKind::IntentionalBoundary,
            BenchmarkPartition::SyntheticGold | BenchmarkPartition::BlindOss => unreachable!(),
        };
        let after = if case.partition == BenchmarkPartition::IntentionalBoundary {
            Vec::new()
        } else if case.after.is_empty() {
            case.before.clone()
        } else {
            case.after.clone()
        };
        entries.push(NonBlindSourceEntry {
            provenance_id,
            partition: case.partition,
            source_kind,
            upstream_url: "https://example.com/fixture".to_string(),
            upstream_revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            upstream_record_id: case.label.case_id.clone(),
            selection_rationale: "Deterministic test fixture".to_string(),
            before: case.before.clone(),
            after,
            removed_after_paths: Vec::new(),
            license: license.clone(),
            behavioral_evidence: vec![evidence.clone()],
        });
    }
    let draft = NonBlindSourceSeal {
        schema_version: NON_BLIND_SOURCE_SEAL_SCHEMA_VERSION,
        seal_id: "non-blind-test-seal".to_string(),
        frozen_at: "2026-08-13T00:00:00Z".to_string(),
        selection_policy: ProvenanceArtifact {
            artifact_path: policy_path.to_string(),
            sha256: format!("{:x}", Sha256::digest(b"{\"fixture\":true}\n")),
            description: "Precommitted fixture selection policy".to_string(),
        },
        selection_protocol: "Deterministic fixture selection before test predictions".to_string(),
        sealed_before_sniff_analysis: true,
        entries,
        seal_sha256: String::new(),
    };
    let seal = freeze_non_blind_source_seal(draft, root).expect("freeze test non-blind seal");
    let artifact_path = "non-blind-source-seal.json".to_string();
    let bytes = serde_json::to_vec_pretty(&seal).expect("serialize test non-blind seal");
    fs::write(root.join(&artifact_path), &bytes).expect("write test non-blind seal");
    (artifact_path, format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn snapshot(root: &Path, artifact_path: &str, revision: &str) -> SourceSnapshot {
        fs::create_dir_all(root.join("sources")).unwrap();
        fs::write(root.join(artifact_path), "fn demo() {}\n").unwrap();
        SourceSnapshot {
            repository: "example/project".to_string(),
            revision: revision.to_string(),
            repository_path: "src/demo.rs".to_string(),
            artifact_path: artifact_path.to_string(),
            sha256: format!("{:x}", Sha256::digest(b"fn demo() {}\n")),
        }
    }

    fn draft(root: &Path) -> NonBlindSourceSeal {
        fs::write(root.join("LICENSE"), "MIT\n").unwrap();
        fs::write(root.join("tests.txt"), "all tests passed\n").unwrap();
        fs::write(root.join("policy.json"), "{\"policy\":1}\n").unwrap();
        let license = ProvenanceArtifact {
            artifact_path: "LICENSE".to_string(),
            sha256: format!("{:x}", Sha256::digest(b"MIT\n")),
            description: "Upstream license".to_string(),
        };
        let evidence = ProvenanceArtifact {
            artifact_path: "tests.txt".to_string(),
            sha256: format!("{:x}", Sha256::digest(b"all tests passed\n")),
            description: "Behavioral test result".to_string(),
        };
        let definitions = [
            (
                "historical",
                BenchmarkPartition::HistoricalSimplification,
                NonBlindSourceKind::HistoricalSimplification,
            ),
            (
                "research-slopcodebench",
                BenchmarkPartition::ResearchTrajectory,
                NonBlindSourceKind::SlopCodeBenchTrajectory,
            ),
            (
                "research-trim",
                BenchmarkPartition::ResearchTrajectory,
                NonBlindSourceKind::TrimTrajectory,
            ),
            (
                "boundary",
                BenchmarkPartition::IntentionalBoundary,
                NonBlindSourceKind::IntentionalBoundary,
            ),
        ];
        NonBlindSourceSeal {
            schema_version: NON_BLIND_SOURCE_SEAL_SCHEMA_VERSION,
            seal_id: "fixture-seal".to_string(),
            frozen_at: "2026-08-13T00:00:00Z".to_string(),
            selection_policy: ProvenanceArtifact {
                artifact_path: "policy.json".to_string(),
                sha256: format!("{:x}", Sha256::digest(b"{\"policy\":1}\n")),
                description: "Precommitted test selection policy".to_string(),
            },
            selection_protocol: "Cases fixed before any Sniff output".to_string(),
            sealed_before_sniff_analysis: true,
            entries: definitions
                .into_iter()
                .map(|(id, partition, source_kind)| NonBlindSourceEntry {
                    provenance_id: id.to_string(),
                    partition,
                    source_kind,
                    upstream_url: "https://example.com/project".to_string(),
                    upstream_revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                    upstream_record_id: id.to_string(),
                    selection_rationale: "Precommitted fixture selection".to_string(),
                    before: vec![snapshot(
                        root,
                        &format!("sources/{id}-before.rs"),
                        "0123456789abcdef0123456789abcdef01234567",
                    )],
                    after: if partition == BenchmarkPartition::IntentionalBoundary {
                        Vec::new()
                    } else {
                        vec![snapshot(
                            root,
                            &format!("sources/{id}-after.rs"),
                            "fedcba9876543210fedcba9876543210fedcba98",
                        )]
                    },
                    removed_after_paths: Vec::new(),
                    license: license.clone(),
                    behavioral_evidence: vec![evidence.clone()],
                })
                .collect(),
            seal_sha256: String::new(),
        }
    }

    #[test]
    fn freezes_and_replays_complete_non_blind_provenance() {
        let root = TempDir::new().unwrap();
        let seal = freeze_non_blind_source_seal(draft(root.path()), root.path()).unwrap();

        validate_non_blind_source_seal(&seal, root.path()).unwrap();
        assert_eq!(seal.seal_sha256.len(), 64);
    }

    #[test]
    fn rejects_post_analysis_or_tampered_evidence() {
        let root = TempDir::new().unwrap();
        let mut post_analysis = draft(root.path());
        post_analysis.sealed_before_sniff_analysis = false;
        post_analysis.seal_sha256 = post_analysis.computed_seal_sha256().unwrap();

        let error = validate_non_blind_source_seal(&post_analysis, root.path()).unwrap_err();

        assert!(error.contains("selection preceded Sniff analysis"));

        let seal = freeze_non_blind_source_seal(draft(root.path()), root.path()).unwrap();
        fs::write(root.path().join("tests.txt"), "changed result\n").unwrap();

        let error = validate_non_blind_source_seal(&seal, root.path()).unwrap_err();

        assert!(error.contains("behavioral evidence tests.txt hash mismatch"));

        fs::write(root.path().join("tests.txt"), "all tests passed\n").unwrap();
        fs::write(root.path().join("policy.json"), "{\"policy\":2}\n").unwrap();

        let error = validate_non_blind_source_seal(&seal, root.path()).unwrap_err();

        assert!(error.contains("selection policy policy.json hash mismatch"));
    }

    #[test]
    fn requires_both_research_datasets() {
        let root = TempDir::new().unwrap();
        let mut incomplete = draft(root.path());
        incomplete
            .entries
            .retain(|entry| entry.source_kind != NonBlindSourceKind::SlopCodeBenchTrajectory);
        incomplete.seal_sha256 = incomplete.computed_seal_sha256().unwrap();

        let error = validate_non_blind_source_seal(&incomplete, root.path()).unwrap_err();

        assert!(error.contains("missing required research source SlopCodeBenchTrajectory"));
    }
}
