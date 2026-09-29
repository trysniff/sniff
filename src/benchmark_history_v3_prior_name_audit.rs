use super::{
    HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC, HistoricalV3PriorBenchmarkIdentitySeal,
    validate_historical_v3_prior_identity_seal,
};
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde::de::{self, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

pub const HISTORICAL_V3_PRIOR_NAME_AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_CONTRACT: &str = "sniffbench-historical-v3-prior-saved-name-observations-v1";
const PROOF_SCOPE: &str = "saved_name_lookup_only_not_historical_repository_identity";
const MAX_CHECKPOINT_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3PriorNameObservationStatus {
    ObservedPreCutoffId,
    ObservedPostCutoffId,
    ObservedNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorNameObservation {
    pub prior_name: String,
    pub status: HistoricalV3PriorNameObservationStatus,
    pub observed_repository_id: Option<u64>,
    pub observed_name: Option<String>,
    pub observed_created_at_utc: Option<String>,
    pub checkpoint_sha256: String,
    pub response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorNameAudit {
    pub schema_version: u32,
    pub audit_contract: String,
    pub proof_scope: String,
    pub prior_seal_sha256: String,
    pub cutoff_utc: String,
    pub observations: Vec<HistoricalV3PriorNameObservation>,
    pub audit_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema_version: u32,
    prior_seal_sha256: String,
    prior_name: String,
    request_url: String,
    #[serde(default)]
    final_url: Option<String>,
    #[serde(default)]
    redirected: Option<bool>,
    #[serde(default)]
    transport: Option<String>,
    status: u16,
    repository_id: Option<u64>,
    current_name: Option<String>,
    created_at: Option<String>,
    response_sha256: String,
    response_base64: String,
}

pub fn audit_historical_v3_prior_names(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
    directories: &[&Path],
) -> Result<HistoricalV3PriorNameAudit, String> {
    validate_historical_v3_prior_identity_seal(seal)?;
    if directories.is_empty() {
        return Err("historical-v3 prior-name audit has no checkpoint directories".to_string());
    }
    let cutoff = parse_utc(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC)?;
    let mut found = BTreeMap::new();
    for directory in directories {
        if !fs::symlink_metadata(directory)
            .map_err(|error| format!("failed to inspect prior-name audit directory: {error}"))?
            .file_type()
            .is_dir()
        {
            return Err("prior-name audit directory is not a plain directory".to_string());
        }
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("failed to list prior-name audit directory: {error}"))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("failed to inspect prior-name checkpoint: {error}"))?;
            if !metadata.file_type().is_file() || metadata.len() > MAX_CHECKPOINT_BYTES {
                return Err("prior-name checkpoint is not a plain bounded file".to_string());
            }
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let file = options
                .open(&path)
                .map_err(|error| format!("failed to open prior-name checkpoint: {error}"))?;
            let opened = file.metadata().map_err(|error| {
                format!("failed to inspect opened prior-name checkpoint: {error}")
            })?;
            if !opened.file_type().is_file() || opened.len() > MAX_CHECKPOINT_BYTES {
                return Err("prior-name checkpoint is not a plain bounded file".to_string());
            }
            let mut bytes = Vec::new();
            file.take(MAX_CHECKPOINT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("failed to read prior-name checkpoint: {error}"))?;
            if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
                return Err("prior-name checkpoint exceeds its size limit".to_string());
            }
            let checkpoint: Checkpoint = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid prior-name checkpoint: {error}"))?;
            if checkpoint.prior_seal_sha256 != seal.seal_sha256
                || seal
                    .repositories
                    .binary_search(&checkpoint.prior_name)
                    .is_err()
                || path.file_name().and_then(|name| name.to_str())
                    != Some(format!("{}.json", sha256(checkpoint.prior_name.as_bytes())).as_str())
            {
                return Err("prior-name checkpoint is not bound to the sealed name".to_string());
            }
            let observation = verify_checkpoint(&checkpoint, &bytes, cutoff)?;
            if found.insert(checkpoint.prior_name, observation).is_some() {
                return Err("prior-name audit repeats a sealed name".to_string());
            }
        }
    }
    if found.len() != seal.repositories.len() {
        return Err("prior-name audit omits a sealed name".to_string());
    }
    let mut audit = HistoricalV3PriorNameAudit {
        schema_version: HISTORICAL_V3_PRIOR_NAME_AUDIT_SCHEMA_VERSION,
        audit_contract: AUDIT_CONTRACT.to_string(),
        proof_scope: PROOF_SCOPE.to_string(),
        prior_seal_sha256: seal.seal_sha256.clone(),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        observations: found.into_values().collect(),
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit_sha256(&audit)?;
    Ok(audit)
}

pub fn verify_historical_v3_prior_name_audit(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
    directories: &[&Path],
    audit: &HistoricalV3PriorNameAudit,
) -> Result<(), String> {
    if audit.audit_sha256 != audit_sha256(audit)?
        || audit != &audit_historical_v3_prior_names(seal, directories)?
    {
        return Err("historical-v3 prior-name audit does not replay".to_string());
    }
    Ok(())
}

fn verify_checkpoint(
    checkpoint: &Checkpoint,
    bytes: &[u8],
    cutoff: DateTime<Utc>,
) -> Result<HistoricalV3PriorNameObservation, String> {
    let request_url = format!("https://api.github.com/repos/{}", checkpoint.prior_name);
    if checkpoint.request_url != request_url {
        return Err("prior-name checkpoint changed its request URL".to_string());
    }
    match checkpoint.schema_version {
        1 if checkpoint.transport.is_none()
            && checkpoint.final_url.is_some()
            && checkpoint.redirected.is_some() => {}
        2 if checkpoint.transport.as_deref() == Some("gh api")
            && checkpoint.final_url.is_none()
            && checkpoint.redirected.is_none() => {}
        _ => return Err("prior-name checkpoint uses an unsupported transport".to_string()),
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&checkpoint.response_base64)
        .map_err(|error| format!("invalid prior-name response encoding: {error}"))?;
    if sha256(&raw) != checkpoint.response_sha256 {
        return Err("prior-name response bytes changed".to_string());
    }
    let response = parse_unique_json(&raw)?;
    let (status, repository_id, current_name, created_at) = match checkpoint.status {
        200 => {
            let id = response["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .ok_or("prior-name response has no repository ID")?;
            let name = response["full_name"]
                .as_str()
                .filter(|name| !name.is_empty())
                .ok_or("prior-name response has no repository name")?;
            let created = response["created_at"]
                .as_str()
                .ok_or("prior-name response has no creation time")?;
            let created_at = parse_utc(created)?;
            if checkpoint.repository_id != Some(id)
                || checkpoint.current_name.as_deref() != Some(name)
                || !checkpoint
                    .created_at
                    .as_deref()
                    .is_some_and(|stored| stored_creation_time_matches(stored, created_at))
            {
                return Err("prior-name checkpoint disagrees with its raw response".to_string());
            }
            if checkpoint.schema_version == 1 {
                let expected_final = if checkpoint.redirected == Some(true) {
                    format!("https://api.github.com/repositories/{id}")
                } else {
                    request_url.clone()
                };
                if checkpoint.final_url.as_deref() != Some(expected_final.as_str()) {
                    return Err("prior-name checkpoint changed its redirect target".to_string());
                }
            }
            (
                if created_at <= cutoff {
                    HistoricalV3PriorNameObservationStatus::ObservedPreCutoffId
                } else {
                    HistoricalV3PriorNameObservationStatus::ObservedPostCutoffId
                },
                Some(id),
                Some(name.to_string()),
                Some(created_at.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
            )
        }
        404 if response["message"].as_str() == Some("Not Found")
            && checkpoint.repository_id.is_none()
            && checkpoint.current_name.is_none()
            && checkpoint.created_at.is_none() =>
        {
            if checkpoint.schema_version == 1
                && (checkpoint.redirected != Some(false)
                    || checkpoint.final_url.as_deref() != Some(request_url.as_str()))
            {
                return Err("prior-name 404 changed its request target".to_string());
            }
            (
                HistoricalV3PriorNameObservationStatus::ObservedNotFound,
                None,
                None,
                None,
            )
        }
        _ => return Err("prior-name checkpoint has an unsupported response".to_string()),
    };
    Ok(HistoricalV3PriorNameObservation {
        prior_name: checkpoint.prior_name.clone(),
        status,
        observed_repository_id: repository_id,
        observed_name: current_name,
        observed_created_at_utc: created_at,
        checkpoint_sha256: sha256(bytes),
        response_sha256: checkpoint.response_sha256.clone(),
    })
}

fn stored_creation_time_matches(stored: &str, expected: DateTime<Utc>) -> bool {
    if parse_utc(stored).is_ok_and(|parsed| parsed == expected) {
        return true;
    }
    ["%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"]
        .iter()
        .filter_map(|format| NaiveDateTime::parse_from_str(stored, format).ok())
        .any(|parsed| parsed.and_utc() == expected)
}

struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(UniqueJson(number.into()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(value.into()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(UniqueJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJson(values.into()))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
            if values.insert(key, value).is_some() {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(UniqueJson(values.into()))
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)
        .map_err(|error| format!("invalid prior-name response: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid prior-name response: {error}"))?;
    Ok(value)
}

fn parse_utc(value: &str) -> Result<DateTime<Utc>, String> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| "prior-name creation time is not RFC3339".to_string())?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err("prior-name creation time is not UTC".to_string());
    }
    Ok(parsed.with_timezone(&Utc))
}

fn audit_sha256(audit: &HistoricalV3PriorNameAudit) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        audit.schema_version,
        &audit.audit_contract,
        &audit.proof_scope,
        &audit.prior_seal_sha256,
        &audit.cutoff_utc,
        &audit.observations,
    ))
    .map_err(|error| format!("failed to commit prior-name audit: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v3_prior_name_audit_tests.rs"]
mod tests;
