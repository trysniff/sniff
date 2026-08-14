use crate::pricing::PricingRates;
use crate::report_types::RunReport;
use crate::review_journal::JournalSummary;
use crate::types::FileRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const COMPLETED_RUN_SCHEMA_VERSION: u32 = 2;

type CompletedSourceInventory = (Vec<CompletedRunSourceFile>, Vec<(String, String)>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedRunSourceFile {
    pub repository_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletedRunUsage {
    pub input_tokens: usize,
    pub cached_input_tokens: usize,
    pub output_tokens: usize,
    pub estimated_cost_usd: f64,
    pub pricing_snapshots: Vec<PricingRates>,
    pub pricing_provenance_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedRunCoverage {
    pub files_scanned: usize,
    pub source_files_committed: usize,
    pub methods_expected: usize,
    pub methods_completed: usize,
    pub compiler_methods_expected: usize,
    pub compiler_methods_covered: usize,
    pub role_units_expected: usize,
    pub role_units_completed: usize,
    pub synthesis_units_expected: usize,
    pub synthesis_units_completed: usize,
    pub adjudication_units_expected: usize,
    pub adjudication_units_completed: usize,
    pub proof_units_expected: usize,
    pub proof_units_completed: usize,
    pub cross_scan_reused_units: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedRunArtifact {
    pub schema_version: u32,
    pub run_id: String,
    pub scan_fingerprint: String,
    pub execution_commitment_sha256: String,
    pub sniff_version: String,
    pub completed_unix_ms: u64,
    pub provider: String,
    pub model: String,
    pub endpoint: String,
    pub prompt_contract_version: String,
    pub semantic_index_hashes: Vec<String>,
    pub source_files: Vec<CompletedRunSourceFile>,
    pub source_commitment_sha256: String,
    pub report_commitment_sha256: String,
    pub coverage: CompletedRunCoverage,
    pub usage: CompletedRunUsage,
    pub report: RunReport,
}

impl CompletedRunArtifact {
    pub fn verify(&self) -> Result<(), String> {
        if self.schema_version != COMPLETED_RUN_SCHEMA_VERSION {
            return Err(format!(
                "unsupported completed-run schema {}; expected {}",
                self.schema_version, COMPLETED_RUN_SCHEMA_VERSION
            ));
        }
        for (name, value) in [
            ("run_id", self.run_id.as_str()),
            ("scan_fingerprint", self.scan_fingerprint.as_str()),
            (
                "execution_commitment_sha256",
                self.execution_commitment_sha256.as_str(),
            ),
            (
                "source_commitment_sha256",
                self.source_commitment_sha256.as_str(),
            ),
            (
                "report_commitment_sha256",
                self.report_commitment_sha256.as_str(),
            ),
        ] {
            require_sha256(name, value)?;
        }
        for (name, value) in [
            ("sniff_version", self.sniff_version.as_str()),
            ("provider", self.provider.as_str()),
            ("model", self.model.as_str()),
            ("endpoint", self.endpoint.as_str()),
            (
                "prompt_contract_version",
                self.prompt_contract_version.as_str(),
            ),
        ] {
            require_text(name, value)?;
        }
        if self.semantic_index_hashes.is_empty() {
            return Err("completed-run has no finalized semantic index identity".to_string());
        }
        for hash in &self.semantic_index_hashes {
            require_sha256("semantic_index_hash", hash)?;
        }
        if !self.usage.estimated_cost_usd.is_finite() || self.usage.estimated_cost_usd < 0.0 {
            return Err("completed-run estimated cost must be finite and non-negative".to_string());
        }
        validate_source_inventory(&self.source_files)?;
        if self.coverage.source_files_committed != self.source_files.len() {
            return Err(
                "completed-run file coverage does not match its scanned source inventory"
                    .to_string(),
            );
        }
        validate_report_coverage(&self.report, &self.coverage)?;
        if source_commitment(&self.source_files)? != self.source_commitment_sha256 {
            return Err(
                "completed-run source commitment does not match its scanned source inventory"
                    .to_string(),
            );
        }
        if report_commitment(&self.report)? != self.report_commitment_sha256 {
            return Err("completed-run report commitment does not match its report".to_string());
        }
        if self.run_id
            != completed_run_id(
                &self.scan_fingerprint,
                &self.execution_commitment_sha256,
                &self.source_commitment_sha256,
                &self.report_commitment_sha256,
                &self.sniff_version,
            )
        {
            return Err("completed-run ID does not match its committed identity".to_string());
        }
        if self.report.stats.input_tokens != self.usage.input_tokens
            || self.report.stats.cached_input_tokens != self.usage.cached_input_tokens
            || self.report.stats.output_tokens != self.usage.output_tokens
            || self.report.stats.estimated_cost_usd.to_bits()
                != self.usage.estimated_cost_usd.to_bits()
            || self.report.stats.pricing_snapshots != self.usage.pricing_snapshots
            || self.report.stats.pricing_provenance_complete
                != self.usage.pricing_provenance_complete
        {
            return Err("completed-run usage does not match report statistics".to_string());
        }
        Ok(())
    }
}

pub(crate) fn build_completed_run(
    report: &RunReport,
    journal: &JournalSummary,
    files: &[FileRecord],
    repository_root: &Path,
) -> Result<CompletedRunArtifact, String> {
    let scan_fingerprint = journal
        .scan_id
        .as_deref()
        .ok_or_else(|| "completed-run export requires a journal scan fingerprint".to_string())?;
    let execution_commitment_sha256 = journal
        .execution_commitment_sha256
        .as_deref()
        .ok_or_else(|| "completed-run export requires committed journal events".to_string())?;
    require_sha256("execution_commitment_sha256", execution_commitment_sha256)?;
    let provider = required_journal_value("provider", journal.provider.as_deref())?;
    let model = required_journal_value("model", journal.model.as_deref())?;
    let endpoint = required_journal_value("endpoint", journal.endpoint.as_deref())?;
    let prompt_contract_version = required_journal_value(
        "prompt contract version",
        journal.prompt_contract_version.as_deref(),
    )?;
    if journal.expected_units != report.stats.method_reviews_expected
        || journal.completed_units != report.stats.method_reviews_completed
        || journal.retryable_units != 0
    {
        return Err(format!(
            "completed-run journal method coverage does not match the report: journal {}/{} with {} retryable, report {}/{}",
            journal.completed_units,
            journal.expected_units,
            journal.retryable_units,
            report.stats.method_reviews_completed,
            report.stats.method_reviews_expected
        ));
    }
    let coverage = CompletedRunCoverage {
        files_scanned: report.stats.files_scanned,
        source_files_committed: files.len(),
        methods_expected: report.stats.method_reviews_expected,
        methods_completed: report.stats.method_reviews_completed,
        compiler_methods_expected: report.stats.compiler_methods_expected,
        compiler_methods_covered: report.stats.compiler_methods_covered,
        role_units_expected: journal.expected_role_units,
        role_units_completed: journal.completed_role_units,
        synthesis_units_expected: journal.expected_synthesis_units,
        synthesis_units_completed: journal.completed_synthesis_units,
        adjudication_units_expected: journal.expected_adjudication_units,
        adjudication_units_completed: journal.completed_adjudication_units,
        proof_units_expected: journal.expected_proof_units,
        proof_units_completed: journal.completed_proof_units,
        cross_scan_reused_units: journal.reused_units,
    };
    let usage = CompletedRunUsage {
        input_tokens: report.stats.input_tokens,
        cached_input_tokens: report.stats.cached_input_tokens,
        output_tokens: report.stats.output_tokens,
        estimated_cost_usd: report.stats.estimated_cost_usd,
        pricing_snapshots: report.stats.pricing_snapshots.clone(),
        pricing_provenance_complete: report.stats.pricing_provenance_complete,
    };
    let completed_unix_ms = now_unix_ms();
    let (source_files, source_paths) = source_inventory(files, repository_root)?;
    let artifact_report = normalize_report_paths(report, &source_paths)?;
    let source_commitment_sha256 = source_commitment(&source_files)?;
    let report_commitment_sha256 = report_commitment(&artifact_report)?;
    let run_id = completed_run_id(
        scan_fingerprint,
        execution_commitment_sha256,
        &source_commitment_sha256,
        &report_commitment_sha256,
        env!("CARGO_PKG_VERSION"),
    );
    let artifact = CompletedRunArtifact {
        schema_version: COMPLETED_RUN_SCHEMA_VERSION,
        run_id,
        scan_fingerprint: scan_fingerprint.to_string(),
        execution_commitment_sha256: execution_commitment_sha256.to_string(),
        sniff_version: env!("CARGO_PKG_VERSION").to_string(),
        completed_unix_ms,
        provider,
        model,
        endpoint,
        prompt_contract_version,
        semantic_index_hashes: journal.semantic_index_hashes.clone(),
        source_files,
        source_commitment_sha256,
        report_commitment_sha256,
        coverage,
        usage,
        report: artifact_report,
    };
    artifact.verify()?;
    Ok(artifact)
}

pub(crate) fn build_final_completed_run(
    report: &RunReport,
    journal: &JournalSummary,
    files: &[FileRecord],
    repository_root: &Path,
) -> Result<Option<CompletedRunArtifact>, String> {
    if !journal_is_final(journal) {
        return Ok(None);
    }
    build_completed_run(report, journal, files, repository_root).map(Some)
}

pub(crate) fn journal_is_final(journal: &JournalSummary) -> bool {
    journal.retryable_units == 0
        && journal.retryable_role_units == 0
        && journal.retryable_synthesis_units == 0
        && journal.retryable_adjudication_units == 0
        && journal.retryable_proof_units == 0
}

pub(crate) fn write_completed_run(
    artifact: &CompletedRunArtifact,
    report_path: &Path,
) -> Result<(PathBuf, bool), String> {
    artifact.verify()?;
    let root = report_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".sniff")
        .join("runs");
    fs::create_dir_all(&root).map_err(|error| {
        format!(
            "failed to create completed-run directory {}: {error}",
            root.display()
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "failed to secure completed-run directory {}: {error}",
            root.display()
        )
    })?;
    let path = root.join(format!("{}.json", artifact.run_id));
    if path.exists() {
        let existing = fs::read(&path).map_err(|error| {
            format!(
                "failed to read existing completed-run artifact {}: {error}",
                path.display()
            )
        })?;
        let existing: CompletedRunArtifact =
            serde_json::from_slice(&existing).map_err(|error| {
                format!(
                    "existing completed-run artifact {} is invalid JSON: {error}",
                    path.display()
                )
            })?;
        existing.verify()?;
        if existing.run_id == artifact.run_id
            && existing.scan_fingerprint == artifact.scan_fingerprint
            && existing.source_commitment_sha256 == artifact.source_commitment_sha256
            && existing.report_commitment_sha256 == artifact.report_commitment_sha256
        {
            return Ok((path, false));
        }
        return Err(format!(
            "completed-run artifact {} conflicts with the same run identity",
            path.display()
        ));
    }
    let bytes = serde_json::to_vec_pretty(artifact)
        .map_err(|error| format!("failed to serialize completed-run artifact: {error}"))?;
    let temp = root.join(format!(".{}.{}.tmp", artifact.run_id, next_run_nonce()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| {
        let mut file = options.open(&temp).map_err(|error| {
            format!(
                "failed to create completed-run temporary file {}: {error}",
                temp.display()
            )
        })?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                format!(
                    "failed to persist completed-run temporary file {}: {error}",
                    temp.display()
                )
            })?;
        drop(file);
        fs::hard_link(&temp, &path).map_err(|error| {
            format!(
                "failed to commit completed-run artifact {}: {error}",
                path.display()
            )
        })?;
        fs::remove_file(&temp).map_err(|error| {
            format!(
                "completed-run artifact was committed at {}, but temporary file {} could not be removed: {error}",
                path.display(),
                temp.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map(|()| (path, true))
}

fn validate_report_coverage(
    report: &RunReport,
    coverage: &CompletedRunCoverage,
) -> Result<(), String> {
    let stats = &report.stats;
    if stats.ai_failed_reviews != 0 || stats.method_review_failures != 0 {
        return Err("completed-run export rejected failed reviews".to_string());
    }
    if stats.method_reviews_expected != stats.method_reviews_completed
        || stats.method_reviews_expected != report.method_review_records.len()
        || stats.compiler_methods_expected != stats.compiler_methods_covered
        || stats.compiler_methods_expected != stats.method_reviews_expected
    {
        return Err(
            "completed-run export requires exhaustive method and compiler coverage".to_string(),
        );
    }
    if coverage.methods_expected != stats.method_reviews_expected
        || coverage.methods_completed != stats.method_reviews_completed
        || coverage.compiler_methods_expected != stats.compiler_methods_expected
        || coverage.compiler_methods_covered != stats.compiler_methods_covered
        || coverage.files_scanned != stats.files_scanned
    {
        return Err("completed-run coverage ledger does not match report statistics".to_string());
    }
    for (stage, expected, completed) in [
        (
            "role",
            coverage.role_units_expected,
            coverage.role_units_completed,
        ),
        (
            "synthesis",
            coverage.synthesis_units_expected,
            coverage.synthesis_units_completed,
        ),
        (
            "adjudication",
            coverage.adjudication_units_expected,
            coverage.adjudication_units_completed,
        ),
        (
            "proof",
            coverage.proof_units_expected,
            coverage.proof_units_completed,
        ),
    ] {
        if expected != completed {
            return Err(format!(
                "completed-run export requires complete {stage} coverage: {completed}/{expected}"
            ));
        }
    }
    let mut units = HashSet::with_capacity(report.method_review_records.len());
    for record in &report.method_review_records {
        require_sha256("method source_hash", &record.source_hash)?;
        if !units.insert(record.unit_id.as_str()) {
            return Err(format!(
                "completed-run method census repeats unit {}",
                record.unit_id
            ));
        }
        if !report.llm_verdicts.iter().any(|verdict| {
            verdict.check_type == "method"
                && verdict == &record.verdict
                && verdict.file_path == record.file_path
                && verdict.method_name.as_deref() == Some(record.method_name.as_str())
                && verdict.start_line == record.start_line
                && verdict.end_line == record.end_line
        }) {
            return Err(format!(
                "completed-run method record {} has no matching final verdict",
                record.unit_id
            ));
        }
    }
    let method_verdicts = report
        .llm_verdicts
        .iter()
        .filter(|verdict| verdict.check_type == "method")
        .count();
    if method_verdicts != report.method_review_records.len() {
        return Err("completed-run final method verdict ledger is incomplete".to_string());
    }
    Ok(())
}

fn source_inventory(
    files: &[FileRecord],
    repository_root: &Path,
) -> Result<CompletedSourceInventory, String> {
    let root = std::fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve completed-run repository root {}: {error}",
            repository_root.display()
        )
    })?;
    let mut source_paths = Vec::with_capacity(files.len());
    let mut inventory = files
        .iter()
        .map(|file| {
            let path = std::fs::canonicalize(&file.file_path).map_err(|error| {
                format!(
                    "failed to resolve scanned source {}: {error}",
                    file.file_path
                )
            })?;
            let relative = path.strip_prefix(&root).map_err(|_| {
                format!(
                    "scanned source {} escapes repository root {}",
                    path.display(),
                    root.display()
                )
            })?;
            let repository_path = relative.to_string_lossy().replace('\\', "/");
            if repository_path.is_empty() {
                return Err("scanned source path resolves to the repository root".to_string());
            }
            let original = file.file_path.replace('\\', "/");
            let canonical = path.to_string_lossy().replace('\\', "/");
            source_paths.push((original, repository_path.clone()));
            if canonical != file.file_path.replace('\\', "/") {
                source_paths.push((canonical, repository_path.clone()));
            }
            Ok(CompletedRunSourceFile {
                repository_path,
                sha256: sha256_text(&file.source),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    inventory.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    validate_source_inventory(&inventory)?;
    source_paths.sort_by_key(|item| std::cmp::Reverse(item.0.len()));
    source_paths.dedup();
    Ok((inventory, source_paths))
}

fn normalize_report_paths(
    report: &RunReport,
    source_paths: &[(String, String)],
) -> Result<RunReport, String> {
    let normalize = |path: &str| normalize_source_path(path, source_paths);
    let mut normalized = report.clone();
    for verdict in &mut normalized.file_verdicts {
        verdict.file_path = normalize(&verdict.file_path)?;
    }
    for flag in &mut normalized.static_flags {
        flag.file_path = normalize(&flag.file_path)?;
    }
    for verdict in &mut normalized.llm_verdicts {
        verdict.file_path = normalize(&verdict.file_path)?;
    }
    for record in &mut normalized.method_review_records {
        record.file_path = normalize(&record.file_path)?;
        record.verdict.file_path = normalize(&record.verdict.file_path)?;
    }
    for case in &mut normalized.slop_cases {
        for evidence in &mut case.evidence {
            evidence.file_path = normalize(&evidence.file_path)?;
        }
        for edit in &mut case.counterfactual_edits {
            edit.file_path = normalize(&edit.file_path)?;
        }
        for provenance in &mut case.provenance {
            for (absolute, relative) in source_paths {
                *provenance = provenance
                    .replace(absolute, relative)
                    .replace(&absolute.replace('/', "\\"), relative);
            }
        }
    }
    Ok(normalized)
}

fn normalize_source_path(path: &str, source_paths: &[(String, String)]) -> Result<String, String> {
    let normalized = path.replace('\\', "/");
    source_paths
        .iter()
        .find(|(absolute, _)| absolute == &normalized)
        .map(|(_, relative)| relative.clone())
        .or_else(|| {
            source_paths
                .iter()
                .find(|(_, relative)| relative == &normalized)
                .map(|(_, relative)| relative.clone())
        })
        .ok_or_else(|| format!("completed-run report references unscanned source path {path}"))
}

fn validate_source_inventory(files: &[CompletedRunSourceFile]) -> Result<(), String> {
    if files.is_empty() {
        return Err("completed-run scanned source inventory is empty".to_string());
    }
    let mut paths = HashSet::with_capacity(files.len());
    for file in files {
        require_text("source repository_path", &file.repository_path)?;
        if file.repository_path.contains('\\')
            || file.repository_path.starts_with('/')
            || file.repository_path.split('/').any(|part| part == "..")
        {
            return Err(format!(
                "completed-run source path must be normalized and repository-relative: {}",
                file.repository_path
            ));
        }
        require_sha256("source file sha256", &file.sha256)?;
        if !paths.insert(file.repository_path.as_str()) {
            return Err(format!(
                "completed-run scanned source inventory repeats {}",
                file.repository_path
            ));
        }
    }
    Ok(())
}

fn source_commitment(files: &[CompletedRunSourceFile]) -> Result<String, String> {
    let mut inventory = files
        .iter()
        .map(|file| (file.repository_path.as_str(), file.sha256.as_str()))
        .collect::<Vec<_>>();
    inventory.sort_unstable();
    let bytes = serde_json::to_vec(&inventory)
        .map_err(|error| format!("failed to serialize completed-run source inventory: {error}"))?;
    Ok(sha256_bytes(&bytes))
}

fn report_commitment(report: &RunReport) -> Result<String, String> {
    let bytes = serde_json::to_vec(report)
        .map_err(|error| format!("failed to serialize completed-run report: {error}"))?;
    Ok(sha256_bytes(&bytes))
}

fn required_journal_value(name: &str, value: Option<&str>) -> Result<String, String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("completed-run journal is missing {name}"))
}

fn require_text(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("completed-run {name} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_sha256(name: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("completed-run {name} must be a SHA-256 hex digest"))
    }
}

fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn completed_run_id(
    scan_fingerprint: &str,
    execution_commitment_sha256: &str,
    source_commitment_sha256: &str,
    report_commitment_sha256: &str,
    sniff_version: &str,
) -> String {
    sha256_text(&format!(
        "schema={COMPLETED_RUN_SCHEMA_VERSION}\nscan={scan_fingerprint}\nexecution={execution_commitment_sha256}\nsource={source_commitment_sha256}\nreport={report_commitment_sha256}\nsniff={sniff_version}"
    ))
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn next_run_nonce() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
#[path = "tests/completed_run.rs"]
mod tests;
