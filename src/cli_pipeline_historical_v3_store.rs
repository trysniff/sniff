use super::precommit;
use crate::benchmark::{
    HistoricalV3CandidateCollection, HistoricalV3PriorBenchmarkIdentitySeal, HistoricalV3Protocol,
    HistoricalV3SourceBindingAudit, HistoricalV3SourceFrameArtifact, SourceFrameCollectionManifest,
    bind_historical_v3_source_frames, read_historical_v3_candidate_collection_manifest,
    validate_historical_v3_prior_identity_seal, validate_historical_v3_protocol,
    validate_historical_v3_source_binding_audit,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const BINDING_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceFramePaths {
    pub manifest: PathBuf,
    pub artifact_root: PathBuf,
    pub frame: PathBuf,
    pub public_policy_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperatorConfig {
    pub protocol: PathBuf,
    pub public_protocol_url: String,
    pub prior_identity_seal: PathBuf,
    pub source_frames: Vec<SourceFramePaths>,
    pub operator_root: PathBuf,
    pub github_token_env: String,
    pub docker_program: String,
}

pub(super) struct LoadedFrame {
    pub manifest: SourceFrameCollectionManifest,
    pub artifact_root: PathBuf,
    pub frame: Vec<u8>,
}

pub(super) struct UnboundInputs {
    pub config: OperatorConfig,
    pub protocol: HistoricalV3Protocol,
    pub prior: HistoricalV3PriorBenchmarkIdentitySeal,
    pub frames: Vec<LoadedFrame>,
}

pub(super) struct BoundInputs {
    pub unbound: UnboundInputs,
    pub audit: HistoricalV3SourceBindingAudit,
    pub root: PathBuf,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorBinding {
    schema_version: u32,
    operator_root: String,
    config_sha256: String,
    protocol_sha256: String,
    prior_identity_seal_sha256: String,
    source_binding_audit_sha256: String,
    binding_sha256: String,
}

impl UnboundInputs {
    pub fn artifacts(&self) -> Vec<HistoricalV3SourceFrameArtifact<'_>> {
        self.frames
            .iter()
            .map(|frame| HistoricalV3SourceFrameArtifact {
                manifest: &frame.manifest,
                artifact_root: &frame.artifact_root,
                frame: &frame.frame,
            })
            .collect()
    }
}

impl BoundInputs {
    pub fn collection(&self) -> Result<HistoricalV3CandidateCollection, String> {
        precommit::validate_public_precommit(self)?;
        read_historical_v3_candidate_collection_manifest(
            &self.root.join("candidate-manifest.json"),
            &self.unbound.protocol,
            &self.unbound.prior,
            &self.unbound.artifacts(),
            &self.audit,
            &self.root.join("candidate-state"),
        )
    }

    pub fn journal_root(&self) -> PathBuf {
        self.root.join("journal")
    }

    pub fn workspace_root(&self) -> PathBuf {
        self.root.join("workspace")
    }

    pub fn review_root(&self) -> PathBuf {
        self.root.join("reviews")
    }

    pub fn stop_path(&self, language: &str) -> PathBuf {
        self.root.join("stops").join(format!("{language}.json"))
    }
}

pub(super) fn load_unbound(config_path: &Path) -> Result<UnboundInputs, String> {
    let config: OperatorConfig = read_json(config_path, MAX_CONFIG_BYTES, "operator config")?;
    for (name, path) in [
        ("protocol", &config.protocol),
        ("prior identity seal", &config.prior_identity_seal),
        ("operator root", &config.operator_root),
    ] {
        require_absolute(path, name)?;
    }
    if config.source_frames.len() != 6 {
        return Err("historical-v3 operator requires exactly six source frames".to_string());
    }
    precommit::validate_public_url(&config.public_protocol_url)?;
    for frame in &config.source_frames {
        require_absolute(&frame.manifest, "source-frame manifest")?;
        require_absolute(&frame.artifact_root, "source-frame artifact root")?;
        require_absolute(&frame.frame, "source-frame CSV")?;
        require_plain_directory(&frame.artifact_root, "source-frame artifact root")?;
        precommit::validate_public_url(&frame.public_policy_url)?;
    }
    if config.github_token_env.is_empty()
        || !config
            .github_token_env
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || config.docker_program.trim().is_empty()
    {
        return Err("historical-v3 operator runtime names are invalid".to_string());
    }
    let protocol = read_json(&config.protocol, MAX_INPUT_BYTES, "protocol")?;
    validate_historical_v3_protocol(&protocol)?;
    let prior = read_json(
        &config.prior_identity_seal,
        MAX_INPUT_BYTES,
        "prior identity seal",
    )?;
    validate_historical_v3_prior_identity_seal(&prior)?;
    let frames = config
        .source_frames
        .iter()
        .map(|paths| {
            Ok(LoadedFrame {
                manifest: read_json(&paths.manifest, MAX_INPUT_BYTES, "source-frame manifest")?,
                artifact_root: paths.artifact_root.clone(),
                frame: read_plain(&paths.frame, MAX_INPUT_BYTES, "source-frame CSV")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(UnboundInputs {
        config,
        protocol,
        prior,
        frames,
    })
}

pub(super) fn initialize(config_path: &Path) -> Result<BoundInputs, String> {
    let unbound = load_unbound(config_path)?;
    let audit =
        bind_historical_v3_source_frames(&unbound.protocol, &unbound.prior, &unbound.artifacts())?;
    if !unbound.config.operator_root.exists() {
        fs::create_dir(&unbound.config.operator_root)
            .map_err(|error| format!("failed to create historical-v3 operator root: {error}"))?;
    }
    let root = canonical_plain_directory(&unbound.config.operator_root, "operator root")?;
    require_operator_root_contents(&root)?;
    for name in [
        "candidate-state",
        "journal",
        "workspace",
        "reviews",
        "stops",
    ] {
        ensure_child_directory(&root.join(name), name)?;
    }
    write_json_durable(&root.join("source-binding-audit.json"), &audit)?;
    let binding = binding(&root, &unbound, &audit)?;
    write_json_durable(&root.join("operator-binding.json"), &binding)?;
    Ok(BoundInputs {
        unbound,
        audit,
        root,
    })
}

pub(super) fn load_bound(config_path: &Path) -> Result<BoundInputs, String> {
    let unbound = load_unbound(config_path)?;
    let root = canonical_plain_directory(&unbound.config.operator_root, "operator root")?;
    for name in [
        "candidate-state",
        "journal",
        "workspace",
        "reviews",
        "stops",
    ] {
        require_plain_directory(&root.join(name), name)?;
    }
    let audit: HistoricalV3SourceBindingAudit = read_json(
        &root.join("source-binding-audit.json"),
        MAX_INPUT_BYTES,
        "source-binding audit",
    )?;
    validate_historical_v3_source_binding_audit(
        &unbound.protocol,
        &unbound.prior,
        &unbound.artifacts(),
        &audit,
    )?;
    let stored: OperatorBinding = read_json(
        &root.join("operator-binding.json"),
        MAX_CONFIG_BYTES,
        "operator binding",
    )?;
    if stored != binding(&root, &unbound, &audit)? {
        return Err("historical-v3 operator binding changed".to_string());
    }
    Ok(BoundInputs {
        unbound,
        audit,
        root,
    })
}

fn binding(
    root: &Path,
    unbound: &UnboundInputs,
    audit: &HistoricalV3SourceBindingAudit,
) -> Result<OperatorBinding, String> {
    let mut binding = OperatorBinding {
        schema_version: BINDING_SCHEMA_VERSION,
        operator_root: root
            .to_str()
            .ok_or_else(|| "historical-v3 operator root is not UTF-8".to_string())?
            .to_string(),
        config_sha256: sha256(
            &serde_json::to_vec(&unbound.config)
                .map_err(|error| format!("failed to bind operator config: {error}"))?,
        ),
        protocol_sha256: unbound.protocol.protocol_sha256.clone(),
        prior_identity_seal_sha256: unbound.prior.seal_sha256.clone(),
        source_binding_audit_sha256: audit.audit_sha256.clone(),
        binding_sha256: String::new(),
    };
    binding.binding_sha256 = sha256(
        &serde_json::to_vec(&binding)
            .map_err(|error| format!("failed to commit operator binding: {error}"))?,
    );
    Ok(binding)
}

pub(super) fn read_json<T: DeserializeOwned>(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<T, String> {
    let bytes = read_plain(path, limit, label)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid {label}: {error}"))
}

pub(super) fn read_plain(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!("{label} is not a plain file within its size limit"));
    }
    let bytes = fs::read(path).map_err(|error| format!("failed to read {label}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn write_json_durable<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize historical-v3 artifact: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("historical-v3 artifact exceeds its size limit".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v3 artifact path has no parent".to_string())?;
    require_plain_directory(parent, "artifact parent")?;
    if path.exists() {
        let existing = read_plain(path, MAX_INPUT_BYTES, "existing historical-v3 artifact")?;
        return if existing == bytes {
            Ok(())
        } else {
            Err("historical-v3 artifact already exists with different content".to_string())
        };
    }
    let mut pending_name = OsString::from(".");
    pending_name.push(
        path.file_name()
            .ok_or_else(|| "historical-v3 artifact path has no filename".to_string())?,
    );
    pending_name.push(format!(".{}.pending", sha256(&bytes)));
    let pending = parent.join(pending_name);
    if pending.exists() {
        let metadata = fs::symlink_metadata(&pending)
            .map_err(|error| format!("failed to inspect pending artifact: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("historical-v3 pending artifact is not a plain file".to_string());
        }
        if read_plain(&pending, MAX_INPUT_BYTES, "pending historical-v3 artifact")? != bytes {
            fs::remove_file(&pending)
                .map_err(|error| format!("failed to clear incomplete artifact: {error}"))?;
        }
    }
    if !pending.exists() {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|error| format!("failed to create pending artifact: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("failed to persist pending artifact: {error}"))?;
    }
    match fs::hard_link(&pending, path) {
        Ok(()) => {}
        Err(error) => {
            let published_matches = path.exists()
                && read_plain(path, MAX_INPUT_BYTES, "published historical-v3 artifact")? == bytes;
            if !published_matches {
                return Err(format!("failed to publish historical-v3 artifact: {error}"));
            }
        }
    }
    sync_directory(parent)?;
    if pending.exists() {
        fs::remove_file(&pending)
            .map_err(|error| format!("failed to clear pending artifact: {error}"))?;
    }
    Ok(())
}

pub(super) fn ensure_child_directory(path: &Path, label: &str) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir(path).map_err(|error| format!("failed to create {label}: {error}"))?;
    }
    require_plain_directory(path, label)
}

pub(super) fn require_plain_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a plain directory"));
    }
    Ok(())
}

fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    require_plain_directory(path, label)?;
    fs::canonicalize(path).map_err(|error| format!("failed to resolve {label}: {error}"))
}

fn require_operator_root_contents(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v3 operator root: {error}"))?
    {
        let entry = entry.map_err(|error| format!("invalid operator-root entry: {error}"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "historical-v3 operator root has a non-UTF-8 entry".to_string())?;
        let expected = matches!(
            name,
            "candidate-state"
                | "journal"
                | "workspace"
                | "reviews"
                | "stops"
                | "source-binding-audit.json"
                | "operator-binding.json"
                | "candidate-manifest.json"
                | "public-precommit-proof.json"
        );
        let pending = (name.starts_with(".source-binding-audit.json.")
            || name.starts_with(".operator-binding.json.")
            || name.starts_with(".candidate-manifest.json.")
            || name.starts_with(".public-precommit-proof.json."))
            && name.ends_with(".pending");
        if !expected && !pending {
            return Err(format!(
                "historical-v3 operator root contains an unrelated entry: {name}"
            ));
        }
    }
    Ok(())
}

fn require_absolute(path: &Path, label: &str) -> Result<(), String> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(format!("historical-v3 {label} path must be absolute"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("failed to sync historical-v3 artifact directory: {error}"))
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("failed to sync historical-v3 artifact directory: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{
        HistoricalV3CandidatePageRequest, HistoricalV3CandidatePageTransport, HistoricalV3Language,
        historical_v3_source_fixture as source_fixture,
    };
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;

    struct ZeroTransport {
        calls: usize,
    }

    struct MockPublicTransport {
        responses: BTreeMap<String, Vec<u8>>,
        calls: usize,
    }

    impl precommit::PublicArtifactTransport for MockPublicTransport {
        fn fetch<'a>(
            &'a mut self,
            url: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            Box::pin(async move {
                self.calls += 1;
                self.responses
                    .get(url)
                    .cloned()
                    .ok_or_else(|| format!("unexpected public artifact: {url}"))
            })
        }
    }

    fn public_transport(bound: &BoundInputs) -> MockPublicTransport {
        let config = &bound.unbound.config;
        let mut responses = BTreeMap::new();
        for (api_url, commit_sha) in precommit::expected_commits(bound).unwrap() {
            responses.insert(
                api_url,
                serde_json::to_vec(&serde_json::json!({ "sha": commit_sha })).unwrap(),
            );
        }
        responses.insert(
            config.public_protocol_url.clone(),
            fs::read(&config.protocol).unwrap(),
        );
        for (paths, frame) in config.source_frames.iter().zip(&bound.unbound.frames) {
            responses.insert(
                paths.public_policy_url.clone(),
                serde_json::to_vec(&frame.manifest.policy).unwrap(),
            );
        }
        MockPublicTransport {
            responses,
            calls: 0,
        }
    }

    impl HistoricalV3CandidatePageTransport for ZeroTransport {
        fn fetch<'a>(
            &'a mut self,
            request: &'a HistoricalV3CandidatePageRequest,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            Box::pin(async move {
                self.calls += 1;
                let repository = &request.partition;
                let timestamp = &repository.merged_at_or_after_utc;
                Ok(serde_json::to_vec(&serde_json::json!({
                    "data": {
                        "search": {
                            "issueCount": 1,
                            "pageInfo": { "hasNextPage": false, "endCursor": null },
                            "nodes": [{
                                "number": 7,
                                "createdAt": timestamp,
                                "updatedAt": timestamp,
                                "closedAt": timestamp,
                                "mergedAt": timestamp,
                                "baseRefOid": format!("{:040x}", repository.repository_id),
                                "headRefOid": format!("{:040x}", repository.repository_id + 100),
                                "mergeCommit": {
                                    "oid": format!("{:040x}", repository.repository_id + 200)
                                },
                                "repository": {
                                    "databaseId": repository.repository_id,
                                    "nameWithOwner": repository.name_with_owner,
                                }
                            }],
                        }
                    },
                    "errors": [],
                }))
                .unwrap())
            })
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        _frames: Vec<source_fixture::FrameFixture>,
        config: PathBuf,
        frame_paths: Vec<PathBuf>,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let frames = source_fixture::fixtures();
        let prior = source_fixture::prior_identity_seal();
        let protocol = source_fixture::protocol(&prior, &frames);
        let protocol_path = root.path().join("protocol.json");
        let prior_path = root.path().join("prior.json");
        fs::write(&protocol_path, serde_json::to_vec(&protocol).unwrap()).unwrap();
        fs::write(&prior_path, serde_json::to_vec(&prior).unwrap()).unwrap();
        let mut source_paths = Vec::new();
        let mut frame_paths = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            let manifest_path = root.path().join(format!("source-{index}.json"));
            let frame_path = root.path().join(format!("source-{index}.csv"));
            fs::write(&manifest_path, serde_json::to_vec(&frame.manifest).unwrap()).unwrap();
            fs::write(&frame_path, &frame.frame).unwrap();
            source_paths.push(SourceFramePaths {
                manifest: manifest_path,
                artifact_root: frame.root.path().to_path_buf(),
                frame: frame_path.clone(),
                public_policy_url: format!(
                    "https://raw.githubusercontent.com/trysniff/sniff/{:040x}/policies/{index}.json",
                    index + 2
                ),
            });
            frame_paths.push(frame_path);
        }
        let config = root.path().join("operator-config.json");
        fs::write(
            &config,
            serde_json::to_vec(&OperatorConfig {
                protocol: protocol_path,
                public_protocol_url: format!(
                    "https://raw.githubusercontent.com/trysniff/sniff/{:040x}/protocol.json",
                    1
                ),
                prior_identity_seal: prior_path,
                source_frames: source_paths,
                operator_root: root.path().join("operator"),
                github_token_env: "SNIFF_TEST_GITHUB_TOKEN".to_string(),
                docker_program: "docker".to_string(),
            })
            .unwrap(),
        )
        .unwrap();
        Fixture {
            _root: root,
            _frames: frames,
            config,
            frame_paths,
        }
    }

    #[test]
    fn init_pins_six_sources_and_never_treats_a_new_root_as_resume() {
        let fixture = fixture();
        assert!(load_bound(&fixture.config).is_err());
        let first = initialize(&fixture.config).unwrap();
        let second = initialize(&fixture.config).unwrap();
        assert_eq!(first.audit, second.audit);
        let loaded = load_bound(&fixture.config).unwrap();
        assert_eq!(loaded.audit, first.audit);
        assert!(loaded.root.join("operator-binding.json").is_file());

        let mut changed: OperatorConfig =
            read_json(&fixture.config, MAX_CONFIG_BYTES, "operator config").unwrap();
        changed.operator_root = fixture._root.path().join("new-root");
        let changed_path = fixture._root.path().join("changed-config.json");
        fs::write(&changed_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(load_bound(&changed_path).is_err());
        assert!(!changed.operator_root.exists());

        changed.operator_root = fixture._root.path().to_path_buf();
        fs::write(&changed_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(initialize(&changed_path).is_err());
        assert!(!fixture._root.path().join("candidate-state").exists());

        fs::write(&fixture.frame_paths[0], b"changed source").unwrap();
        assert!(load_bound(&fixture.config).is_err());
    }

    #[tokio::test]
    async fn synthetic_collection_resumes_and_reports_a_pending_rank() {
        let fixture = fixture();
        let bound = initialize(&fixture.config).unwrap();
        let mut public = public_transport(&bound);
        assert!(
            super::super::collect_bound(&bound, &mut ZeroTransport { calls: 0 })
                .await
                .is_err()
        );
        precommit::ensure_public_precommit(&bound, &mut public)
            .await
            .unwrap();
        assert_eq!(public.calls, 14);
        precommit::ensure_public_precommit(&bound, &mut public)
            .await
            .unwrap();
        assert_eq!(public.calls, 14);
        let mut transport = ZeroTransport { calls: 0 };
        let collection = super::super::collect_bound(&bound, &mut transport)
            .await
            .unwrap();
        assert_eq!(transport.calls, 6);
        assert_eq!(collection.candidates.len(), 6);
        assert!(bound.root.join("candidate-manifest.json").is_file());

        let mut resumed = ZeroTransport { calls: 0 };
        let same = super::super::collect_bound(&bound, &mut resumed)
            .await
            .unwrap();
        assert_eq!(resumed.calls, 0);
        assert_eq!(same, collection);
        assert_eq!(initialize(&fixture.config).unwrap().audit, bound.audit);
        assert_eq!(
            super::super::status(fixture.config.to_str().unwrap(), HistoricalV3Language::Rust)
                .unwrap(),
            0
        );
        let progress = crate::benchmark::replay_historical_v3_ordered_progress(
            &bound.unbound.protocol,
            &collection,
            HistoricalV3Language::Rust,
            &bound.journal_root(),
            &bound.review_root(),
            &bound.stop_path("rust"),
        )
        .unwrap();
        assert!(matches!(
            progress,
            crate::benchmark::HistoricalV3ReplayProgress::PendingRank { .. }
        ));
        assert!(!bound.stop_path("rust").exists());
    }

    #[tokio::test]
    async fn mismatched_public_policy_blocks_collection_before_candidate_fetch() {
        let fixture = fixture();
        let bound = initialize(&fixture.config).unwrap();
        let mut public = public_transport(&bound);
        let url = &bound.unbound.config.source_frames[0].public_policy_url;
        public.responses.insert(url.clone(), b"{}".to_vec());
        assert!(
            precommit::ensure_public_precommit(&bound, &mut public)
                .await
                .is_err()
        );
        assert!(!bound.root.join("public-precommit-proof.json").exists());
        let mut candidate = ZeroTransport { calls: 0 };
        assert!(
            super::super::collect_bound(&bound, &mut candidate)
                .await
                .is_err()
        );
        assert_eq!(candidate.calls, 0);
    }

    #[tokio::test]
    async fn mutable_ref_disguised_as_commit_blocks_collection() {
        let fixture = fixture();
        let bound = initialize(&fixture.config).unwrap();
        let mut public = public_transport(&bound);
        let (api_url, _) = precommit::expected_commits(&bound)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        public.responses.insert(
            api_url,
            serde_json::to_vec(&serde_json::json!({ "sha": "f".repeat(40) })).unwrap(),
        );
        assert!(
            precommit::ensure_public_precommit(&bound, &mut public)
                .await
                .is_err()
        );
        assert!(!bound.root.join("public-precommit-proof.json").exists());
        let mut candidate = ZeroTransport { calls: 0 };
        assert!(
            super::super::collect_bound(&bound, &mut candidate)
                .await
                .is_err()
        );
        assert_eq!(candidate.calls, 0);
    }

    #[tokio::test]
    async fn tampered_public_precommit_proof_blocks_offline_resume() {
        let fixture = fixture();
        let bound = initialize(&fixture.config).unwrap();
        precommit::ensure_public_precommit(&bound, &mut public_transport(&bound))
            .await
            .unwrap();
        let path = bound.root.join("public-precommit-proof.json");
        let mut proof: serde_json::Value =
            read_json(&path, 10 * 1024 * 1024, "public precommit proof").unwrap();
        proof["protocol"]["fetched_base64"] = serde_json::json!("e30=");
        fs::write(&path, serde_json::to_vec(&proof).unwrap()).unwrap();
        let mut candidate = ZeroTransport { calls: 0 };
        assert!(
            super::super::collect_bound(&bound, &mut candidate)
                .await
                .is_err()
        );
        assert_eq!(candidate.calls, 0);
    }

    #[test]
    fn durable_json_recovers_partial_pending_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifact.json");
        let value = serde_json::json!({ "identity": "sealed" });
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        let pending = root
            .path()
            .join(format!(".artifact.json.{}.pending", sha256(&bytes)));
        fs::write(&pending, b"{").unwrap();
        write_json_durable(&path, &value).unwrap();
        assert!(!pending.exists());
        write_json_durable(&path, &value).unwrap();
        assert!(write_json_durable(&path, &serde_json::json!({ "identity": "other" })).is_err());
        assert_eq!(
            read_plain(&path, MAX_INPUT_BYTES, "artifact").unwrap(),
            bytes
        );
    }
}
