use super::lock::CensusLock;
use super::manifest::{MAX_RAW_EXCHANGE_BYTES, read_artifact};
use super::replay::{
    replay_public_id_census_with_source, validate_exchange_for_version, validate_preflight,
};
use super::{
    PUBLIC_ID_CENSUS_POLICY_COMMIT_SHA, PublicIdCensusExchange, PublicIdCensusFailedAttempt,
    PublicIdCensusManifest, PublicIdCensusPolicy, PublicIdCensusPreflight, PublicIdCensusRequest,
    prepare_public_id_census_manifest, validate_public_id_census_manifest,
    validate_public_id_census_policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::Builder;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdCensusHttpResponse {
    pub status: u16,
    pub body: String,
    pub link: Option<String>,
    pub date: Option<String>,
    pub received_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicIdCensusTransportError {
    Timeout,
    NotSent(String),
    Other(String),
}

pub trait PublicIdCensusTransport {
    fn fetch_public_policy(
        &mut self,
        url: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError>;

    fn fetch_exchange(
        &mut self,
        request: &PublicIdCensusRequest,
        url: &str,
        body: Option<&str>,
        api_version: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError>;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InFlightRequest {
    request: PublicIdCensusRequest,
    url: String,
    body: Option<String>,
    api_version: String,
    attempt_index: usize,
}

pub(crate) struct SourceRequest<'a> {
    pub(crate) api_version: &'a str,
    pub(crate) request: &'a PublicIdCensusRequest,
    pub(crate) url: &'a str,
    pub(crate) body: Option<&'a str>,
}

pub fn collect_public_id_census<T: PublicIdCensusTransport>(
    policy: &PublicIdCensusPolicy,
    artifact_root: &Path,
    transport: &mut T,
) -> Result<PublicIdCensusManifest, String> {
    validate_public_id_census_policy(policy)?;
    fs::create_dir_all(artifact_root)
        .map_err(|error| format!("failed to create public-ID census root: {error}"))?;
    let root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("failed to resolve public-ID census root: {error}"))?;
    let _lock = CensusLock::acquire(&root.join(".collector.lock"))?;
    let manifest_path = root.join("manifest.json");
    if plain_file_exists(&manifest_path)? {
        let bytes = read_artifact(&root, "manifest.json", MAX_MANIFEST_BYTES)?;
        let manifest: PublicIdCensusManifest = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid public-ID census manifest: {error}"))?;
        if &manifest.policy != policy {
            return Err("public-ID census completed root belongs to another policy".to_string());
        }
        validate_public_id_census_manifest(&manifest, &root)?;
        let preflight: PublicIdCensusPreflight =
            serde_json::from_slice(&read_artifact(&root, "preflight.json", MAX_POLICY_BYTES)?)
                .map_err(|error| format!("invalid public-ID census preflight artifact: {error}"))?;
        if preflight != manifest.preflight {
            return Err("public-ID census preflight artifact changed".to_string());
        }
        let raw_paths = manifest
            .exchanges
            .iter()
            .map(|exchange| exchange.artifact_path.clone())
            .collect::<Vec<_>>();
        ensure_exact_raw_files(&root.join("raw"), &raw_paths)?;
        ensure_empty_attempt_directory(&root.join("attempts"))?;
        ensure_exact_frame_files(&root.join("frames"), policy)?;
        ensure_root_entries(&root, true)?;
        return Ok(manifest);
    }

    cleanup_orphan_staging(&root)?;
    ensure_root_entries(&root, false)?;

    let preflight = read_or_fetch_preflight(policy, &root, transport)?;
    let raw_root = root.join("raw");
    fs::create_dir_all(&raw_root)
        .map_err(|error| format!("failed to create public-ID census raw directory: {error}"))?;
    let attempts_root = root.join("attempts");
    fs::create_dir_all(&attempts_root)
        .map_err(|error| format!("failed to create public-ID census attempt directory: {error}"))?;
    let mut exchange_paths = Vec::new();
    let replay = replay_public_id_census_with_source(policy, &preflight, |request, url, body| {
        let sequence = exchange_paths.len();
        let relative = format!("raw/{sequence:08}.json");
        let path = root.join(&relative);
        let exchange = if plain_file_exists(&path)? {
            let bytes = read_artifact(&root, &relative, MAX_RAW_EXCHANGE_BYTES)?;
            let exchange: PublicIdCensusExchange = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid public-ID census checkpoint: {error}"))?;
            finish_committed_request(
                &policy.api_version,
                &root,
                sequence,
                &request,
                &url,
                body.as_deref(),
                &exchange,
            )?;
            exchange
        } else {
            let failures = load_attempts(
                &policy.api_version,
                &root,
                sequence,
                &request,
                &url,
                body.as_deref(),
            )?;
            let exchange = fetch_with_retries(
                transport,
                &root,
                sequence,
                SourceRequest {
                    api_version: &policy.api_version,
                    request: &request,
                    url: &url,
                    body: body.as_deref(),
                },
                failures,
            )?;
            let bytes = serde_json::to_vec(&exchange).map_err(|error| {
                format!("failed to encode public-ID census checkpoint: {error}")
            })?;
            if bytes.len() as u64 > MAX_RAW_EXCHANGE_BYTES {
                return Err("public-ID census checkpoint exceeds its size limit".to_string());
            }
            write_new(&path, &bytes)?;
            finish_committed_request(
                &policy.api_version,
                &root,
                sequence,
                &request,
                &url,
                body.as_deref(),
                &exchange,
            )?;
            exchange
        };
        exchange_paths.push(relative);
        Ok(exchange)
    })?;
    ensure_exact_raw_files(&raw_root, &exchange_paths)?;
    ensure_empty_attempt_directory(&attempts_root)?;

    let frames_root = root.join("frames");
    fs::create_dir_all(&frames_root)
        .map_err(|error| format!("failed to create public-ID census frames directory: {error}"))?;
    cleanup_orphan_staging(&frames_root)?;
    let mut frame_paths = BTreeMap::new();
    for language in &policy.languages {
        let relative = format!("frames/{}.csv", language.to_ascii_lowercase());
        let bytes = &replay.frames[language];
        let path = root.join(&relative);
        if path.try_exists().map_err(|error| error.to_string())? {
            if read_artifact(&root, &relative, bytes.len() as u64)? != *bytes {
                return Err("existing public-ID census frame differs from replay".to_string());
            }
        } else {
            write_new(&path, bytes)?;
        }
        frame_paths.insert(language.clone(), relative);
    }
    ensure_exact_frame_files(&frames_root, policy)?;
    let manifest = prepare_public_id_census_manifest(
        policy.clone(),
        preflight,
        &root,
        &exchange_paths,
        &frame_paths,
    )?;
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("failed to encode public-ID census manifest: {error}"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("public-ID census manifest exceeds its size limit".to_string());
    }
    write_new(&manifest_path, &bytes)?;
    validate_public_id_census_manifest(&manifest, &root)?;
    ensure_root_entries(&root, true)?;
    Ok(manifest)
}

fn read_or_fetch_preflight<T: PublicIdCensusTransport>(
    policy: &PublicIdCensusPolicy,
    root: &Path,
    transport: &mut T,
) -> Result<PublicIdCensusPreflight, String> {
    let path = root.join("preflight.json");
    if path.try_exists().map_err(|error| error.to_string())? {
        let bytes = read_artifact(root, "preflight.json", MAX_POLICY_BYTES)?;
        return serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid public-ID census preflight: {error}"));
    }
    let url = format!(
        "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_POLICY_COMMIT_SHA}/sniffbench/historical-v3-id-census/policy.json"
    );
    let response = transport
        .fetch_public_policy(&url)
        .map_err(|error| format!("public-ID census policy fetch failed: {error:?}"))?;
    if response.body.len() as u64 > MAX_POLICY_BYTES {
        return Err("public-ID census policy response exceeds its size limit".to_string());
    }
    let preflight = PublicIdCensusPreflight {
        public_policy_url: url,
        fetched_policy_sha256: sha256(response.body.as_bytes()),
        fetched_policy: response.body,
        fetched_at_utc: response.received_at_utc,
        response_status: response.status,
    };
    validate_preflight(policy, &preflight)?;
    let bytes = serde_json::to_vec(&preflight)
        .map_err(|error| format!("failed to encode public-ID census preflight: {error}"))?;
    write_new(&path, &bytes)?;
    Ok(preflight)
}

fn attempt_path(root: &Path, sequence: usize, index: usize) -> std::path::PathBuf {
    root.join(format!("attempts/{sequence:08}-{index:02}.json"))
}

fn inflight_path(root: &Path, sequence: usize) -> std::path::PathBuf {
    root.join(format!("attempts/{sequence:08}.inflight.json"))
}

pub(crate) fn load_attempts(
    api_version: &str,
    root: &Path,
    sequence: usize,
    request: &PublicIdCensusRequest,
    url: &str,
    body: Option<&str>,
) -> Result<Vec<PublicIdCensusFailedAttempt>, String> {
    let mut failures = Vec::new();
    loop {
        let relative = format!("attempts/{sequence:08}-{:02}.json", failures.len());
        if !root
            .join(&relative)
            .try_exists()
            .map_err(|error| error.to_string())?
        {
            break;
        }
        let bytes = read_artifact(root, &relative, MAX_RAW_EXCHANGE_BYTES)?;
        let attempt = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid public-ID census retry checkpoint: {error}"))?;
        failures.push(attempt);
    }
    let prefix = format!("{sequence:08}-");
    let names = fs::read_dir(root.join("attempts"))
        .map_err(|error| format!("failed to list public-ID census retry directory: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| error.to_string())?
                .file_name()
                .into_string()
                .map_err(|_| "public-ID census retry filename is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let matching = names
        .iter()
        .filter(|name| name.starts_with(&prefix))
        .count();
    let marker_name = format!("{sequence:08}.inflight.json");
    if matching != failures.len()
        || names
            .iter()
            .any(|name| !name.starts_with(&prefix) && name != &marker_name)
    {
        return Err("public-ID census retry checkpoint sequence has a gap".to_string());
    }
    let received_at_utc = canonical_now_utc();
    let validation = PublicIdCensusExchange {
        request: request.clone(),
        request_url: url.to_string(),
        request_body: body.map(str::to_string),
        request_api_version: api_version.to_string(),
        response_status: 200,
        response_link: None,
        response_date: None,
        received_at_utc,
        response_body: String::new(),
        response_sha256: sha256(b""),
        failed_attempts: failures.clone(),
    };
    validate_exchange_for_version(&validation, api_version)?;
    let marker_path = inflight_path(root, sequence);
    if marker_path
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        let relative = format!("attempts/{sequence:08}.inflight.json");
        let marker: InFlightRequest =
            serde_json::from_slice(&read_artifact(root, &relative, MAX_POLICY_BYTES)?)
                .map_err(|error| format!("invalid public-ID census in-flight marker: {error}"))?;
        if marker.request != *request
            || marker.url != url
            || marker.body.as_deref() != body
            || marker.api_version != api_version
            || marker.attempt_index >= failures.len()
        {
            return Err("public-ID census request has an uncertain in-flight result".to_string());
        }
        remove_known_file(&marker_path)?;
    }
    Ok(failures)
}

pub(crate) fn finish_committed_request(
    api_version: &str,
    root: &Path,
    sequence: usize,
    request: &PublicIdCensusRequest,
    url: &str,
    body: Option<&str>,
    exchange: &PublicIdCensusExchange,
) -> Result<(), String> {
    validate_exchange_for_version(exchange, api_version)?;
    if &exchange.request != request
        || exchange.request_url != url
        || exchange.request_body.as_deref() != body
    {
        return Err("public-ID census checkpoint is not the expected next request".to_string());
    }
    let marker_path = inflight_path(root, sequence);
    if marker_path
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        let relative = format!("attempts/{sequence:08}.inflight.json");
        let marker: InFlightRequest =
            serde_json::from_slice(&read_artifact(root, &relative, MAX_POLICY_BYTES)?)
                .map_err(|error| format!("invalid public-ID census in-flight marker: {error}"))?;
        if marker.request != exchange.request
            || marker.url != exchange.request_url
            || marker.body != exchange.request_body
            || marker.api_version != exchange.request_api_version
            || marker.attempt_index != exchange.failed_attempts.len()
        {
            return Err(
                "public-ID census committed response mismatches its in-flight marker".to_string(),
            );
        }
        remove_known_file(&marker_path)?;
    }
    for (index, expected) in exchange.failed_attempts.iter().enumerate().rev() {
        let path = attempt_path(root, sequence, index);
        if path.try_exists().map_err(|error| error.to_string())? {
            let relative = format!("attempts/{sequence:08}-{index:02}.json");
            let actual: PublicIdCensusFailedAttempt =
                serde_json::from_slice(&read_artifact(root, &relative, MAX_RAW_EXCHANGE_BYTES)?)
                    .map_err(|error| {
                        format!("invalid public-ID census retry checkpoint: {error}")
                    })?;
            if &actual != expected {
                return Err(
                    "public-ID census retry history differs from committed response".to_string(),
                );
            }
            remove_known_file(&path)?;
        }
    }
    ensure_empty_attempt_directory(&root.join("attempts"))?;
    Ok(())
}

pub(crate) fn fetch_with_retries<T: PublicIdCensusTransport>(
    transport: &mut T,
    root: &Path,
    sequence: usize,
    expected: SourceRequest<'_>,
    mut failures: Vec<PublicIdCensusFailedAttempt>,
) -> Result<PublicIdCensusExchange, String> {
    let SourceRequest {
        api_version,
        request,
        url,
        body,
    } = expected;
    loop {
        if failures.len() >= 12 {
            return Err("public-ID census source exhausted its committed retry limit".to_string());
        }
        let marker = InFlightRequest {
            request: request.clone(),
            url: url.to_string(),
            body: body.map(str::to_string),
            api_version: api_version.to_string(),
            attempt_index: failures.len(),
        };
        let marker_path = inflight_path(root, sequence);
        let marker_bytes = serde_json::to_vec(&marker)
            .map_err(|error| format!("failed to encode public-ID census marker: {error}"))?;
        write_new(&marker_path, &marker_bytes)?;
        let response = transport.fetch_exchange(request, url, body, api_version);
        if response
            .as_ref()
            .is_ok_and(|response| response.body.len() as u64 > MAX_RAW_EXCHANGE_BYTES)
        {
            return Err("public-ID census source response exceeds its size limit".to_string());
        }
        let failure = match response {
            Ok(response) if response.status == 200 => {
                return Ok(PublicIdCensusExchange {
                    request: request.clone(),
                    request_url: url.to_string(),
                    request_body: body.map(str::to_string),
                    request_api_version: api_version.to_string(),
                    response_status: 200,
                    response_link: response.link,
                    response_date: response.date,
                    received_at_utc: response.received_at_utc,
                    response_sha256: sha256(response.body.as_bytes()),
                    response_body: response.body,
                    failed_attempts: failures,
                });
            }
            Ok(response) if response.status == 429 || (500..=599).contains(&response.status) => {
                PublicIdCensusFailedAttempt {
                    request: request.clone(),
                    request_url: url.to_string(),
                    request_body: body.map(str::to_string),
                    request_api_version: api_version.to_string(),
                    received_at_utc: response.received_at_utc,
                    response_status: Some(response.status),
                    response_sha256: Some(sha256(response.body.as_bytes())),
                    response_body: Some(response.body),
                    transport_error: None,
                }
            }
            Err(PublicIdCensusTransportError::Timeout) => PublicIdCensusFailedAttempt {
                request: request.clone(),
                request_url: url.to_string(),
                request_body: body.map(str::to_string),
                request_api_version: api_version.to_string(),
                received_at_utc: canonical_now_utc(),
                response_status: None,
                response_sha256: None,
                response_body: None,
                transport_error: Some("timeout".to_string()),
            },
            Err(PublicIdCensusTransportError::NotSent(error)) => {
                remove_known_file(&marker_path)?;
                return Err(format!("public-ID census request was not sent: {error}"));
            }
            Ok(response) => {
                return Err(format!(
                    "public-ID census source returned nonretryable HTTP {}",
                    response.status
                ));
            }
            Err(PublicIdCensusTransportError::Other(error)) => {
                return Err(format!("public-ID census source failed: {error}"));
            }
        };
        let attempt_path = attempt_path(root, sequence, failures.len());
        let bytes = serde_json::to_vec(&failure)
            .map_err(|error| format!("failed to encode public-ID census retry: {error}"))?;
        if bytes.len() as u64 > MAX_RAW_EXCHANGE_BYTES {
            return Err("public-ID census retry record exceeds its size limit".to_string());
        }
        write_new(&attempt_path, &bytes)?;
        remove_known_file(&marker_path)?;
        failures.push(failure);
    }
}

fn canonical_now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub(crate) fn ensure_exact_raw_files(raw_root: &Path, paths: &[String]) -> Result<(), String> {
    let mut names = fs::read_dir(raw_root)
        .map_err(|error| format!("failed to list public-ID census raw directory: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| error.to_string())?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| "public-ID census raw checkpoint name is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    names.sort();
    if names.len() != paths.len()
        || names
            .iter()
            .enumerate()
            .any(|(index, name)| name != &format!("{index:08}.json"))
    {
        return Err("public-ID census raw checkpoint count changed".to_string());
    }
    Ok(())
}

pub(crate) fn ensure_empty_attempt_directory(path: &Path) -> Result<(), String> {
    if fs::read_dir(path)
        .map_err(|error| format!("failed to list public-ID census attempts: {error}"))?
        .next()
        .is_some()
    {
        return Err("public-ID census has unsealed request attempts".to_string());
    }
    Ok(())
}

pub(crate) fn cleanup_orphan_staging(path: &Path) -> Result<(), String> {
    for entry in fs::read_dir(path)
        .map_err(|error| format!("failed to list public-ID census staging directory: {error}"))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "public-ID census staging filename is not UTF-8".to_string())?;
        if name.starts_with(".sniff-census-") {
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                format!("failed to inspect public-ID census staging file: {error}")
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("public-ID census staging entry is not a plain file".to_string());
            }
            remove_known_file(&entry.path())?;
        }
    }
    Ok(())
}

fn ensure_root_entries(root: &Path, completed: bool) -> Result<(), String> {
    let mut names = fs::read_dir(root)
        .map_err(|error| format!("failed to list public-ID census root: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| error.to_string())?
                .file_name()
                .into_string()
                .map_err(|_| "public-ID census root filename is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    names.sort();
    let allowed = [
        ".collector.lock",
        "attempts",
        "frames",
        "manifest.json",
        "preflight.json",
        "raw",
    ];
    if names.iter().any(|name| !allowed.contains(&name.as_str()))
        || (completed && names != allowed.map(str::to_string))
    {
        return Err("public-ID census root contains uncommitted entries".to_string());
    }
    Ok(())
}

fn ensure_exact_frame_files(
    frames_root: &Path,
    policy: &PublicIdCensusPolicy,
) -> Result<(), String> {
    let mut names = fs::read_dir(frames_root)
        .map_err(|error| format!("failed to list public-ID census frames: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| error.to_string())?
                .file_name()
                .into_string()
                .map_err(|_| "public-ID census frame filename is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    names.sort();
    let mut expected = policy
        .languages
        .iter()
        .map(|language| format!("{}.csv", language.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    expected.sort();
    if names != expected {
        return Err("public-ID census frame directory has uncommitted files".to_string());
    }
    Ok(())
}

fn remove_known_file(path: &Path) -> Result<(), String> {
    fs::remove_file(path)
        .map_err(|error| format!("failed to retire public-ID census journal file: {error}"))?;
    sync_directory(
        path.parent()
            .ok_or("public-ID census journal has no parent")?,
    )
}

pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or("public-ID census artifact has no parent directory")?;
    let mut temporary = Builder::new()
        .prefix(".sniff-census-")
        .tempfile_in(parent)
        .map_err(|error| format!("failed to stage public-ID census artifact: {error}"))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("failed to sync public-ID census artifact: {error}"))?;
    temporary.persist_noclobber(path).map_err(|error| {
        format!(
            "failed to publish public-ID census artifact {}: {}",
            path.display(),
            error.error
        )
    })?;
    sync_directory(parent)
}

pub(crate) fn plain_file_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(format!(
            "public-ID census checkpoint is not a plain file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "failed to inspect public-ID census checkpoint {}: {error}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync public-ID census directory: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_public_id_census_collector_tests.rs"]
mod tests;
