use super::preflight::read_or_fetch_v2_preflights;
use super::replay::replay_public_id_census_v2_with_source;
use super::{
    PublicIdCensusV2Manifest, PublicIdCensusV2Policy, prepare_public_id_census_v2_manifest,
    public_id_census_v2_manifest_bytes, public_id_census_v2_null_ledger_bytes,
    read_public_id_census_v2_manifest, validate_public_id_census_v2_manifest,
    validate_public_id_census_v2_policy,
};
use crate::benchmark::release::public_id_census::collector::{
    SourceRequest, cleanup_orphan_staging, ensure_empty_attempt_directory, ensure_exact_raw_files,
    fetch_with_retries, finish_committed_request, load_attempts, plain_file_exists, write_new,
};
use crate::benchmark::release::public_id_census::lock::CensusLock;
use crate::benchmark::release::public_id_census::{
    PublicIdCensusExchange, PublicIdCensusTransport, read_public_id_census_artifact,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_RAW_EXCHANGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

pub fn collect_public_id_census_v2<T: PublicIdCensusTransport>(
    policy: &PublicIdCensusV2Policy,
    artifact_root: &Path,
    transport: &mut T,
) -> Result<PublicIdCensusV2Manifest, String> {
    validate_public_id_census_v2_policy(policy)?;
    fs::create_dir_all(artifact_root)
        .map_err(|error| format!("failed to create public-ID census v2 root: {error}"))?;
    let root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("failed to resolve public-ID census v2 root: {error}"))?;
    let _lock = CensusLock::acquire(&root.join(".collector.lock"))?;
    if plain_file_exists(&root.join("manifest.json"))? {
        let manifest = read_public_id_census_v2_manifest(&root)?;
        if &manifest.policy != policy {
            return Err("public-ID census v2 completed root belongs to another policy".to_string());
        }
        ensure_empty_attempt_directory(&root.join("attempts"))?;
        ensure_completed_root(&root)?;
        return Ok(manifest);
    }

    cleanup_orphan_staging(&root)?;
    ensure_known_root_entries(&root)?;
    let (preflight, contract_preflight) = read_or_fetch_v2_preflights(policy, &root, transport)?;

    let raw_root = root.join("raw");
    fs::create_dir_all(&raw_root)
        .map_err(|error| format!("failed to create public-ID census v2 raw directory: {error}"))?;
    let attempts_root = root.join("attempts");
    fs::create_dir_all(&attempts_root).map_err(|error| {
        format!("failed to create public-ID census v2 attempt directory: {error}")
    })?;
    let mut exchange_paths = Vec::new();
    let replay =
        replay_public_id_census_v2_with_source(policy, &preflight, |request, url, body| {
            let sequence = exchange_paths.len();
            let relative = format!("raw/{sequence:08}.json");
            let path = root.join(&relative);
            let exchange = if plain_file_exists(&path)? {
                let bytes =
                    read_public_id_census_artifact(&root, &relative, MAX_RAW_EXCHANGE_BYTES)?;
                let exchange: PublicIdCensusExchange = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("invalid public-ID census v2 checkpoint: {error}"))?;
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
                    format!("failed to encode public-ID census v2 exchange: {error}")
                })?;
                if bytes.len() as u64 > MAX_RAW_EXCHANGE_BYTES {
                    return Err("public-ID census v2 exchange exceeds its size limit".to_string());
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
        .map_err(|error| format!("failed to create public-ID census v2 frames: {error}"))?;
    cleanup_orphan_staging(&frames_root)?;
    let mut frame_paths = BTreeMap::new();
    for language in &policy.languages {
        let relative = format!("frames/{}.csv", language.to_ascii_lowercase());
        write_or_compare(&root, &relative, &replay.frames[language])?;
        frame_paths.insert(language.clone(), relative);
    }
    let ledger_bytes = public_id_census_v2_null_ledger_bytes(&replay)?;
    write_or_compare(&root, "null-ledger.json", &ledger_bytes)?;
    let manifest = prepare_public_id_census_v2_manifest(
        policy.clone(),
        preflight,
        contract_preflight,
        &root,
        &exchange_paths,
        &frame_paths,
    )?;
    let bytes = public_id_census_v2_manifest_bytes(&manifest)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("public-ID census v2 manifest exceeds its size limit".to_string());
    }
    write_new(&root.join("manifest.json"), &bytes)?;
    validate_public_id_census_v2_manifest(&manifest, &root)?;
    ensure_completed_root(&root)?;
    Ok(manifest)
}

fn write_or_compare(root: &Path, relative: &str, expected: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    if plain_file_exists(&path)? {
        if read_public_id_census_artifact(root, relative, expected.len() as u64)? != expected {
            return Err(format!(
                "existing public-ID census v2 artifact differs: {relative}"
            ));
        }
    } else {
        write_new(&path, expected)?;
    }
    Ok(())
}

fn ensure_known_root_entries(root: &Path) -> Result<(), String> {
    let allowed = [
        ".collector.lock",
        "attempts",
        "contract-preflight.json",
        "frames",
        "manifest.json",
        "null-ledger.json",
        "preflight.json",
        "raw",
    ];
    let mut actual = fs::read_dir(root)
        .map_err(|error| format!("failed to list public-ID census v2 root: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| error.to_string())?;
            let kind = entry.file_type().map_err(|error| {
                format!("failed to type public-ID census v2 root entry: {error}")
            })?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "public-ID census v2 root filename is not UTF-8".to_string())?;
            let valid_kind = match name.as_str() {
                "raw" | "frames" | "attempts" => kind.is_dir(),
                _ => kind.is_file(),
            };
            if !valid_kind {
                return Err(
                    "public-ID census v2 root entry is not a plain file or directory".to_string(),
                );
            }
            Ok(name)
        })
        .collect::<Result<Vec<_>, String>>()?;
    actual.sort();
    if actual.iter().any(|name| !allowed.contains(&name.as_str())) {
        return Err("public-ID census v2 root contains uncommitted entries".to_string());
    }
    Ok(())
}

fn ensure_completed_root(root: &Path) -> Result<(), String> {
    ensure_known_root_entries(root)?;
    let expected = [
        ".collector.lock",
        "attempts",
        "contract-preflight.json",
        "frames",
        "manifest.json",
        "null-ledger.json",
        "preflight.json",
        "raw",
    ];
    if expected.iter().try_fold(false, |missing, name| {
        root.join(name)
            .try_exists()
            .map(|exists| missing || !exists)
            .map_err(|error| format!("failed to inspect public-ID census v2 root: {error}"))
    })? {
        return Err("public-ID census v2 completed root is incomplete".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_public_id_census_v2_collector_tests.rs"]
mod tests;
