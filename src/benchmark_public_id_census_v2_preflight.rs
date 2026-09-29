use super::PublicIdCensusV2Policy;
use super::manifest::{
    PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_COMMIT_SHA, PublicIdCensusV2ContractPreflight,
    validate_contract_preflight,
};
use super::replay::{PUBLIC_ID_CENSUS_V2_POLICY_COMMIT_SHA, validate_preflight};
use crate::benchmark::release::public_id_census::collector::write_new;
use crate::benchmark::release::public_id_census::{
    PublicIdCensusPreflight, PublicIdCensusTransport, read_public_id_census_artifact,
};
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_PREFLIGHT_BYTES: u64 = 1024 * 1024;

pub(crate) fn read_or_fetch_v2_preflights<T: PublicIdCensusTransport>(
    policy: &PublicIdCensusV2Policy,
    root: &Path,
    transport: &mut T,
) -> Result<(PublicIdCensusPreflight, PublicIdCensusV2ContractPreflight), String> {
    let policy_receipt = read_or_fetch_policy(policy, root, transport)?;
    let contract_receipt = read_or_fetch_contract(root, transport)?;
    Ok((policy_receipt, contract_receipt))
}

fn read_or_fetch_policy<T: PublicIdCensusTransport>(
    policy: &PublicIdCensusV2Policy,
    root: &Path,
    transport: &mut T,
) -> Result<PublicIdCensusPreflight, String> {
    let path = root.join("preflight.json");
    if path.try_exists().map_err(|error| error.to_string())? {
        let bytes = read_public_id_census_artifact(root, "preflight.json", MAX_PREFLIGHT_BYTES)?;
        let receipt: PublicIdCensusPreflight = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid public-ID census v2 policy receipt: {error}"))?;
        validate_preflight(policy, &receipt)?;
        return Ok(receipt);
    }
    let url = format!(
        "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_V2_POLICY_COMMIT_SHA}/sniffbench/historical-v3-id-census-v2/policy.json"
    );
    let response = transport
        .fetch_public_policy(&url)
        .map_err(|error| format!("public-ID census v2 policy fetch failed: {error:?}"))?;
    if response.body.len() as u64 > MAX_PREFLIGHT_BYTES {
        return Err("public-ID census v2 policy response exceeds its size limit".to_string());
    }
    let receipt = PublicIdCensusPreflight {
        public_policy_url: url,
        fetched_policy_sha256: sha256(response.body.as_bytes()),
        fetched_policy: response.body,
        fetched_at_utc: response.received_at_utc,
        response_status: response.status,
    };
    validate_preflight(policy, &receipt)?;
    let bytes = serde_json::to_vec(&receipt)
        .map_err(|error| format!("failed to encode public-ID census v2 policy receipt: {error}"))?;
    write_new(&path, &bytes)?;
    Ok(receipt)
}

fn read_or_fetch_contract<T: PublicIdCensusTransport>(
    root: &Path,
    transport: &mut T,
) -> Result<PublicIdCensusV2ContractPreflight, String> {
    let path = root.join("contract-preflight.json");
    if path.try_exists().map_err(|error| error.to_string())? {
        let bytes =
            read_public_id_census_artifact(root, "contract-preflight.json", MAX_PREFLIGHT_BYTES)?;
        let receipt: PublicIdCensusV2ContractPreflight = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid public-ID census v2 contract receipt: {error}"))?;
        validate_contract_preflight(&receipt)?;
        return Ok(receipt);
    }
    let url = format!(
        "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_COMMIT_SHA}/sniffbench/historical-v3-id-census-v2/artifact-contract.json"
    );
    let response = transport
        .fetch_public_policy(&url)
        .map_err(|error| format!("public-ID census v2 contract fetch failed: {error:?}"))?;
    if response.body.len() as u64 > MAX_PREFLIGHT_BYTES {
        return Err("public-ID census v2 contract response exceeds its size limit".to_string());
    }
    let receipt = PublicIdCensusV2ContractPreflight {
        public_contract_url: url,
        fetched_contract_sha256: sha256(response.body.as_bytes()),
        fetched_contract: response.body,
        fetched_at_utc: response.received_at_utc,
        response_status: response.status,
    };
    validate_contract_preflight(&receipt)?;
    let bytes = serde_json::to_vec(&receipt).map_err(|error| {
        format!("failed to encode public-ID census v2 contract receipt: {error}")
    })?;
    write_new(&path, &bytes)?;
    Ok(receipt)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_public_id_census_v2_preflight_tests.rs"]
mod tests;
