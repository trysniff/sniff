use crate::pricing::PricingRates;
use crate::report_types::LLMVerdict;
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const JOURNAL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalStatus {
    Completed,
    RetryableUnresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct JournalEntry {
    version: u32,
    pub(super) scan_id: String,
    pub(super) unit_id: String,
    #[serde(default)]
    pub(super) expected_units: usize,
    pub(super) source_hash: String,
    pub(super) semantic_index_hash: String,
    pub(super) prompt_contract_version: String,
    pub(super) provider: String,
    pub(super) model: String,
    pub(super) endpoint: String,
    review_context_hash: String,
    status: JournalStatus,
    pub(super) verdict: Option<LLMVerdict>,
    pub(super) in_tok: usize,
    pub(super) out_tok: usize,
    #[serde(default)]
    pub(super) cached_in_tok: usize,
    pub(super) estimated_cost_usd: f64,
    timestamp_unix_ms: u64,
    pub(super) proof_level: String,
    pub(super) retry_on_resume: bool,
}

impl JournalEntry {
    pub(super) fn is_reusable(&self) -> bool {
        !self.retry_on_resume
    }
}

#[derive(Debug, Clone)]
pub(super) struct JournalCompletion {
    pub(super) verdict: Option<LLMVerdict>,
    pub(super) in_tok: usize,
    pub(super) out_tok: usize,
    pub(super) cached_in_tok: usize,
    pub(super) retry_on_resume: bool,
}

#[derive(Debug, Clone)]
struct JournalContext {
    scan_id: String,
    semantic_index_hash: String,
    prompt_contract_version: String,
    provider: String,
    model: String,
    endpoint: String,
    review_context_hash: String,
    expected_units: usize,
}

impl JournalContext {
    fn new(semantic_index_hash: &str, review_context: &str, expected_units: usize) -> Self {
        let fields = review_context
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<HashMap<_, _>>();
        let prompt_contract_version = fields
            .get("review_contract")
            .copied()
            .unwrap_or("unknown")
            .to_string();
        let model = fields
            .get("model")
            .copied()
            .unwrap_or("unknown")
            .to_string();
        let raw_endpoint = fields
            .get("endpoint")
            .copied()
            .unwrap_or("unknown")
            .to_string();
        let provider = provider_label(&raw_endpoint).to_string();
        let endpoint = safe_endpoint(&raw_endpoint);
        let review_context_hash = sha256_text(review_context);
        let scan_id = sha256_text(&format!("{semantic_index_hash}\n{review_context_hash}"));

        Self {
            scan_id,
            semantic_index_hash: semantic_index_hash.to_string(),
            prompt_contract_version,
            provider,
            model,
            endpoint,
            review_context_hash,
            expected_units,
        }
    }

    fn matches(&self, entry: &JournalEntry) -> bool {
        entry.version == JOURNAL_VERSION
            && entry.scan_id == self.scan_id
            && entry.semantic_index_hash == self.semantic_index_hash
            && entry.review_context_hash == self.review_context_hash
    }
}

pub(super) struct JournalStore {
    path: PathBuf,
    context: JournalContext,
    pub(super) completed: HashMap<String, JournalEntry>,
}

impl JournalStore {
    #[cfg(test)]
    pub(super) fn load<S: ToString>(
        path: &Path,
        semantic_index_hash: S,
        review_context: &str,
    ) -> Result<Self, String> {
        Self::load_with_expected(path, semantic_index_hash, review_context, 0)
    }

    pub(super) fn load_with_expected<S: ToString>(
        path: &Path,
        semantic_index_hash: S,
        review_context: &str,
        expected_units: usize,
    ) -> Result<Self, String> {
        let semantic_index_hash = semantic_index_hash.to_string();
        let context = JournalContext::new(&semantic_index_hash, review_context, expected_units);
        let completed = load_entries(path, &context)?;
        Ok(Self {
            path: path.to_path_buf(),
            context,
            completed,
        })
    }

    pub(super) fn record(
        &mut self,
        unit_id: String,
        source_hash: String,
        completion: JournalCompletion,
    ) -> Result<(), String> {
        let status = if completion.retry_on_resume {
            JournalStatus::RetryableUnresolved
        } else {
            JournalStatus::Completed
        };
        let proof_level = completion
            .verdict
            .as_ref()
            .map(|verdict| match verdict.tier {
                FindingTier::Slop | FindingTier::KindaSlop => "p0",
                FindingTier::Clean | FindingTier::Unresolved => "not_applicable",
            })
            .unwrap_or("not_applicable")
            .to_string();
        let estimated_cost_usd = PricingRates::from_env().cost(
            completion.in_tok,
            completion.cached_in_tok,
            completion.out_tok,
        );
        let entry = JournalEntry {
            version: JOURNAL_VERSION,
            scan_id: self.context.scan_id.clone(),
            unit_id: unit_id.clone(),
            expected_units: self.context.expected_units,
            source_hash,
            semantic_index_hash: self.context.semantic_index_hash.clone(),
            prompt_contract_version: self.context.prompt_contract_version.clone(),
            provider: self.context.provider.clone(),
            model: self.context.model.clone(),
            endpoint: self.context.endpoint.clone(),
            review_context_hash: self.context.review_context_hash.clone(),
            status,
            verdict: completion.verdict,
            in_tok: completion.in_tok,
            out_tok: completion.out_tok,
            cached_in_tok: completion.cached_in_tok,
            estimated_cost_usd,
            timestamp_unix_ms: now_unix_ms(),
            proof_level,
            retry_on_resume: completion.retry_on_resume,
        };

        append_entry(&self.path, &entry)?;
        self.completed.insert(unit_id, entry);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn remove(self) -> Result<(), String> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to remove completed Sniff journal {}: {err}",
                self.path.display()
            )),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct JournalSummary {
    pub scan_id: Option<String>,
    pub expected_units: usize,
    pub completed_units: usize,
    pub retryable_units: usize,
    pub slop: usize,
    pub kinda_slop: usize,
    pub unresolved: usize,
    pub input_tokens: usize,
    pub cached_input_tokens: usize,
    pub output_tokens: usize,
    pub estimated_cost_usd: f64,
    pub provider: Option<String>,
    pub model: Option<String>,
}

pub(super) fn summarize(path: &Path) -> Result<JournalSummary, String> {
    let entries = read_entries(path, false)?;
    let Some(latest_scan_id) = entries.last().map(|entry| entry.scan_id.clone()) else {
        return Ok(JournalSummary::default());
    };
    let current_scan = entries
        .into_iter()
        .filter(|entry| entry.scan_id == latest_scan_id)
        .collect::<Vec<_>>();
    let mut summary = JournalSummary {
        scan_id: Some(latest_scan_id),
        ..JournalSummary::default()
    };
    for entry in &current_scan {
        summary.expected_units = summary.expected_units.max(entry.expected_units);
        summary.input_tokens += entry.in_tok;
        summary.cached_input_tokens += entry.cached_in_tok;
        summary.output_tokens += entry.out_tok;
        summary.estimated_cost_usd += entry.estimated_cost_usd;
        summary.provider = Some(entry.provider.clone());
        summary.model = Some(entry.model.clone());
    }
    let mut latest = HashMap::new();
    for entry in current_scan {
        latest.insert(entry.unit_id.clone(), entry);
    }
    for entry in latest.values() {
        if entry.retry_on_resume {
            summary.retryable_units += 1;
            continue;
        }
        summary.completed_units += 1;
        if let Some(verdict) = &entry.verdict {
            match verdict.tier {
                FindingTier::Slop => summary.slop += 1,
                FindingTier::KindaSlop => summary.kinda_slop += 1,
                FindingTier::Unresolved => summary.unresolved += 1,
                FindingTier::Clean => {}
            }
        }
    }
    Ok(summary)
}

pub(super) fn sha256_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn provider_label(endpoint: &str) -> &'static str {
    let endpoint = endpoint.to_ascii_lowercase();
    if endpoint.contains("api.anthropic.com") || endpoint.contains("/anthropic") {
        "anthropic-compatible"
    } else if endpoint.contains("localhost") || endpoint.contains("127.0.0.1") {
        "local-openai-compatible"
    } else {
        "openai-compatible"
    }
}

fn safe_endpoint(endpoint: &str) -> String {
    let without_suffix = endpoint.split(['?', '#']).next().unwrap_or(endpoint).trim();
    let Some((scheme, remainder)) = without_suffix.split_once("://") else {
        return without_suffix.to_string();
    };
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let (authority, path) = remainder.split_at(authority_end);
    let safe_authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{safe_authority}{path}")
}

fn load_entries(
    path: &Path,
    context: &JournalContext,
) -> Result<HashMap<String, JournalEntry>, String> {
    Ok(read_entries(path, true)?
        .into_iter()
        .filter(|entry| context.matches(entry))
        .map(|entry| (entry.unit_id.clone(), entry))
        .collect())
}

fn read_entries(path: &Path, recover_torn_tail: bool) -> Result<Vec<JournalEntry>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "failed to read Sniff journal {}: {err}",
                path.display()
            ));
        }
    };
    let has_torn_tail = !bytes.is_empty() && !bytes.ends_with(b"\n");
    if has_torn_tail && recover_torn_tail {
        let valid_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|err| {
                format!(
                    "failed to open torn Sniff journal {} for recovery: {err}",
                    path.display()
                )
            })?;
        file.set_len(valid_len as u64)
            .and_then(|_| file.sync_data())
            .map_err(|err| {
                format!(
                    "failed to truncate torn Sniff journal {}: {err}",
                    path.display()
                )
            })?;
    }
    let lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let mut entries = Vec::new();

    for (index, raw_line) in lines.iter().enumerate() {
        if raw_line.is_empty() {
            continue;
        }
        if has_torn_tail && index + 1 == lines.len() {
            break;
        }
        let line = std::str::from_utf8(raw_line).map_err(|err| {
            format!(
                "Sniff journal {} contains invalid UTF-8 on line {}: {err}",
                path.display(),
                index + 1
            )
        })?;
        let entry =
            serde_json::from_str::<JournalEntry>(line.trim_end_matches('\r')).map_err(|err| {
                format!(
                    "Sniff journal {} contains invalid JSON on complete line {}: {err}",
                    path.display(),
                    index + 1
                )
            })?;
        entries.push(entry);
    }

    Ok(entries)
}

fn append_entry(path: &Path, entry: &JournalEntry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create Sniff journal directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open Sniff journal {}: {err}", path.display()))?;
    serde_json::to_writer(&mut file, entry)
        .map_err(|err| format!("failed to serialize Sniff journal event: {err}"))?;
    file.write_all(b"\n")
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_data())
        .map_err(|err| format!("failed to persist Sniff journal {}: {err}", path.display()))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "tests/analyzer_journal.rs"]
mod tests;
