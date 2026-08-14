use crate::pricing::PricingRates;
use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, FindingTier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const JOURNAL_VERSION: u32 = 2;
const BUDGET_PAUSE_PREFIX: &str = "Sniff budget pause:";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JournalStage {
    Role,
    #[default]
    Method,
}

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
    #[serde(default)]
    stage: JournalStage,
    #[serde(default)]
    is_manifest: bool,
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
    #[serde(default)]
    role: Option<String>,
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

pub(crate) struct JournalRoleCompletion {
    pub(crate) role: Option<String>,
    pub(crate) in_tok: usize,
    pub(crate) out_tok: usize,
    pub(crate) cached_in_tok: usize,
    pub(crate) retry_on_resume: bool,
}

#[derive(Debug, Clone)]
struct JournalContext {
    scan_id: String,
    stage: JournalStage,
    semantic_index_hash: String,
    prompt_contract_version: String,
    provider: String,
    model: String,
    endpoint: String,
    review_context_hash: String,
    expected_units: usize,
}

struct LoadedJournalState {
    completed: HashMap<String, JournalEntry>,
    spent_usd: f64,
    stage_usage: (usize, usize, usize),
}

impl JournalContext {
    fn new(
        scan_id: Option<&str>,
        stage: JournalStage,
        semantic_index_hash: &str,
        review_context: &str,
        expected_units: usize,
    ) -> Self {
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
        let scan_id = scan_id.map(str::to_string).unwrap_or_else(|| {
            sha256_text(&format!("{semantic_index_hash}\n{review_context_hash}"))
        });

        Self {
            scan_id,
            stage,
            semantic_index_hash: semantic_index_hash.to_string(),
            prompt_contract_version,
            provider,
            model,
            endpoint,
            review_context_hash,
            expected_units,
        }
    }

    fn matches_cache(&self, entry: &JournalEntry) -> bool {
        entry.version == JOURNAL_VERSION
            && entry.stage == self.stage
            && entry.review_context_hash == self.review_context_hash
    }
}

pub(super) struct JournalStore {
    path: PathBuf,
    context: JournalContext,
    pub(super) completed: HashMap<String, JournalEntry>,
    spent_usd: f64,
    stage_in_tok: usize,
    stage_out_tok: usize,
    stage_cached_in_tok: usize,
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
        let context = JournalContext::new(
            None,
            JournalStage::Method,
            &semantic_index_hash,
            review_context,
            expected_units,
        );
        let state = load_state(path, &context)?;
        Ok(Self {
            path: path.to_path_buf(),
            context,
            completed: state.completed,
            spent_usd: state.spent_usd,
            stage_in_tok: state.stage_usage.0,
            stage_out_tok: state.stage_usage.1,
            stage_cached_in_tok: state.stage_usage.2,
        })
    }

    pub(crate) fn load_for_scan<S: ToString>(
        path: &Path,
        scan_id: &str,
        stage: JournalStage,
        semantic_index_hash: S,
        review_context: &str,
        expected_units: usize,
    ) -> Result<Self, String> {
        let semantic_index_hash = semantic_index_hash.to_string();
        let context = JournalContext::new(
            Some(scan_id),
            stage,
            &semantic_index_hash,
            review_context,
            expected_units,
        );
        let state = load_state(path, &context)?;
        let mut store = Self {
            path: path.to_path_buf(),
            context,
            completed: state.completed,
            spent_usd: state.spent_usd,
            stage_in_tok: state.stage_usage.0,
            stage_out_tok: state.stage_usage.1,
            stage_cached_in_tok: state.stage_usage.2,
        };
        store.ensure_stage_manifest()?;
        Ok(store)
    }

    pub(super) fn record(
        &mut self,
        unit_id: String,
        source_hash: String,
        completion: JournalCompletion,
    ) -> Result<(), String> {
        if self.context.stage != JournalStage::Method {
            return Err(
                "method result cannot be written to a non-method journal stage".to_string(),
            );
        }
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
            stage: self.context.stage,
            is_manifest: false,
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
            role: None,
            in_tok: completion.in_tok,
            out_tok: completion.out_tok,
            cached_in_tok: completion.cached_in_tok,
            estimated_cost_usd,
            timestamp_unix_ms: now_unix_ms(),
            proof_level,
            retry_on_resume: completion.retry_on_resume,
        };

        append_entry(&self.path, &entry)?;
        self.spent_usd += entry.estimated_cost_usd;
        self.stage_in_tok += entry.in_tok;
        self.stage_out_tok += entry.out_tok;
        self.stage_cached_in_tok += entry.cached_in_tok;
        self.completed.insert(unit_id, entry);
        Ok(())
    }

    pub(crate) fn is_current_scan(&self, entry: &JournalEntry) -> bool {
        entry.scan_id == self.context.scan_id
    }

    pub(crate) fn reusable_role(&self, unit_id: &str) -> Option<(String, bool)> {
        self.completed
            .get(unit_id)
            .filter(|entry| entry.is_reusable())
            .and_then(|entry| {
                entry
                    .role
                    .as_ref()
                    .map(|role| (role.clone(), self.is_current_scan(entry)))
            })
    }

    pub(crate) fn record_role(
        &mut self,
        unit_id: String,
        source_hash: String,
        completion: JournalRoleCompletion,
    ) -> Result<(), String> {
        if self.context.stage != JournalStage::Role {
            return Err("role result cannot be written to a non-role journal stage".to_string());
        }
        let entry = JournalEntry {
            version: JOURNAL_VERSION,
            scan_id: self.context.scan_id.clone(),
            stage: self.context.stage,
            is_manifest: false,
            unit_id: unit_id.clone(),
            expected_units: self.context.expected_units,
            source_hash,
            semantic_index_hash: self.context.semantic_index_hash.clone(),
            prompt_contract_version: self.context.prompt_contract_version.clone(),
            provider: self.context.provider.clone(),
            model: self.context.model.clone(),
            endpoint: self.context.endpoint.clone(),
            review_context_hash: self.context.review_context_hash.clone(),
            status: if completion.retry_on_resume {
                JournalStatus::RetryableUnresolved
            } else {
                JournalStatus::Completed
            },
            verdict: None,
            role: completion.role,
            in_tok: completion.in_tok,
            out_tok: completion.out_tok,
            cached_in_tok: completion.cached_in_tok,
            estimated_cost_usd: PricingRates::from_env().cost(
                completion.in_tok,
                completion.cached_in_tok,
                completion.out_tok,
            ),
            timestamp_unix_ms: now_unix_ms(),
            proof_level: "not_applicable".to_string(),
            retry_on_resume: completion.retry_on_resume,
        };

        append_entry(&self.path, &entry)?;
        self.spent_usd += entry.estimated_cost_usd;
        self.stage_in_tok += entry.in_tok;
        self.stage_out_tok += entry.out_tok;
        self.stage_cached_in_tok += entry.cached_in_tok;
        self.completed.insert(unit_id, entry);
        Ok(())
    }

    pub(crate) fn record_usage(
        &mut self,
        in_tok: usize,
        out_tok: usize,
        cached_in_tok: usize,
    ) -> Result<(), String> {
        if in_tok == 0 && out_tok == 0 && cached_in_tok == 0 {
            return Ok(());
        }
        static NEXT_USAGE_EVENT: AtomicU64 = AtomicU64::new(0);
        let estimated_cost_usd = PricingRates::from_env().cost(in_tok, cached_in_tok, out_tok);
        let entry = JournalEntry {
            version: JOURNAL_VERSION,
            scan_id: self.context.scan_id.clone(),
            stage: self.context.stage,
            is_manifest: true,
            unit_id: format!(
                "__usage__:{:?}:{}:{}",
                self.context.stage,
                now_unix_ms(),
                NEXT_USAGE_EVENT.fetch_add(1, Ordering::Relaxed)
            )
            .to_ascii_lowercase(),
            expected_units: self.context.expected_units,
            source_hash: String::new(),
            semantic_index_hash: self.context.semantic_index_hash.clone(),
            prompt_contract_version: self.context.prompt_contract_version.clone(),
            provider: self.context.provider.clone(),
            model: self.context.model.clone(),
            endpoint: self.context.endpoint.clone(),
            review_context_hash: self.context.review_context_hash.clone(),
            status: JournalStatus::Completed,
            verdict: None,
            role: None,
            in_tok,
            out_tok,
            cached_in_tok,
            estimated_cost_usd,
            timestamp_unix_ms: now_unix_ms(),
            proof_level: "not_applicable".to_string(),
            retry_on_resume: false,
        };
        append_entry(&self.path, &entry)?;
        self.spent_usd += estimated_cost_usd;
        self.stage_in_tok += in_tok;
        self.stage_out_tok += out_tok;
        self.stage_cached_in_tok += cached_in_tok;
        Ok(())
    }

    pub(crate) fn spent_usd(&self) -> f64 {
        self.spent_usd
    }

    pub(crate) fn stage_usage(&self) -> (usize, usize, usize) {
        (
            self.stage_in_tok,
            self.stage_out_tok,
            self.stage_cached_in_tok,
        )
    }

    fn ensure_stage_manifest(&mut self) -> Result<(), String> {
        let entries = read_entries(&self.path, true)?;
        let manifest_id = format!("__manifest__:{:?}", self.context.stage).to_ascii_lowercase();
        if entries.iter().any(|entry| {
            entry.version == JOURNAL_VERSION
                && entry.scan_id == self.context.scan_id
                && entry.stage == self.context.stage
                && entry.is_manifest
                && entry.unit_id == manifest_id
        }) {
            return Ok(());
        }
        let entry = JournalEntry {
            version: JOURNAL_VERSION,
            scan_id: self.context.scan_id.clone(),
            stage: self.context.stage,
            is_manifest: true,
            unit_id: manifest_id,
            expected_units: self.context.expected_units,
            source_hash: String::new(),
            semantic_index_hash: self.context.semantic_index_hash.clone(),
            prompt_contract_version: self.context.prompt_contract_version.clone(),
            provider: self.context.provider.clone(),
            model: self.context.model.clone(),
            endpoint: self.context.endpoint.clone(),
            review_context_hash: self.context.review_context_hash.clone(),
            status: JournalStatus::Completed,
            verdict: None,
            role: None,
            in_tok: 0,
            out_tok: 0,
            cached_in_tok: 0,
            estimated_cost_usd: 0.0,
            timestamp_unix_ms: now_unix_ms(),
            proof_level: "not_applicable".to_string(),
            retry_on_resume: false,
        };
        append_entry(&self.path, &entry)
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
    pub expected_role_units: usize,
    pub completed_role_units: usize,
    pub retryable_role_units: usize,
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
        match entry.stage {
            JournalStage::Method => {
                summary.expected_units = summary.expected_units.max(entry.expected_units);
            }
            JournalStage::Role => {
                summary.expected_role_units = summary.expected_role_units.max(entry.expected_units);
            }
        }
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
        if entry.is_manifest {
            continue;
        }
        if entry.stage == JournalStage::Role {
            if entry.retry_on_resume {
                summary.retryable_role_units += 1;
            } else {
                summary.completed_role_units += 1;
            }
            continue;
        }
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

pub(crate) fn budget_pause(spent_usd: f64, limit_usd: f64) -> String {
    format!(
        "{BUDGET_PAUSE_PREFIX} estimated scan spend ${spent_usd:.4} reached the ${limit_usd:.4} limit. Completed work is journaled; resume with a higher --budget-usd limit. In-flight review batches may finish above the limit."
    )
}

pub(crate) fn is_budget_pause(error: &str) -> bool {
    error.starts_with(BUDGET_PAUSE_PREFIX)
}

pub(crate) fn scan_id(file_records: &[FileRecord], review_context: &str) -> String {
    let mut files = file_records.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    let mut identity = String::from(review_context);
    for file in files {
        identity.push('\n');
        identity.push_str(&file.file_path);
        identity.push('\n');
        identity.push_str(&file.language);
        identity.push('\n');
        identity.push_str(&sha256_text(&file.source));
    }
    sha256_text(&identity)
}

pub(crate) fn initialize_method_stage(
    path: &Path,
    scan_id: &str,
    review_context: &str,
    expected_units: usize,
) -> Result<(), String> {
    JournalStore::load_for_scan(
        path,
        scan_id,
        JournalStage::Method,
        "pending-semantic-index",
        review_context,
        expected_units,
    )
    .map(|_| ())
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

fn load_state(path: &Path, context: &JournalContext) -> Result<LoadedJournalState, String> {
    let entries = read_entries(path, true)?;
    let spent_usd = entries
        .iter()
        .filter(|entry| entry.version == JOURNAL_VERSION && entry.scan_id == context.scan_id)
        .map(|entry| entry.estimated_cost_usd)
        .sum();
    let stage_usage = entries
        .iter()
        .filter(|entry| {
            entry.version == JOURNAL_VERSION
                && entry.scan_id == context.scan_id
                && entry.stage == context.stage
        })
        .fold((0usize, 0usize, 0usize), |usage, entry| {
            (
                usage.0.saturating_add(entry.in_tok),
                usage.1.saturating_add(entry.out_tok),
                usage.2.saturating_add(entry.cached_in_tok),
            )
        });
    let completed = entries
        .into_iter()
        .filter(|entry| !entry.is_manifest && context.matches_cache(entry))
        .map(|entry| (entry.unit_id.clone(), entry))
        .collect();
    Ok(LoadedJournalState {
        completed,
        spent_usd,
        stage_usage,
    })
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
