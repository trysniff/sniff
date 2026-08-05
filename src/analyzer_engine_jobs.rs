use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, FindingTier, MethodRecord};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::task::JoinSet;

use super::dossier::MethodDossier;
use super::method_batch_review::BatchMethodReview;
use super::method_review::MethodReviewContext;
use super::{Analyzer, ReviewProgress, ReviewProgressCallback};

pub(super) enum ReviewJob {
    Method {
        index: usize,
        method: MethodRecord,
        static_signals: Vec<String>,
        dossier: MethodDossier,
    },
    File {
        index: usize,
        file: FileRecord,
        static_signals: Vec<String>,
    },
}

struct ReviewOutcome {
    index: usize,
    verdict: Option<LLMVerdict>,
    in_tok: usize,
    out_tok: usize,
    cached_in_tok: usize,
    retry_on_resume: bool,
}

async fn abort_and_drain<T: Send + 'static>(tasks: &mut JoinSet<T>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
async fn run_bounded_review_tasks<I, R, Start, Task, Complete>(
    pending: VecDeque<I>,
    max_concurrency: usize,
    start: Start,
    on_completed: Complete,
) -> Result<Vec<R>, String>
where
    I: Send + 'static,
    R: Send + 'static,
    Start: FnMut(I) -> Task,
    Task: Future<Output = Result<R, String>> + Send + 'static,
    Complete: FnMut(&R) -> Result<(), String>,
{
    run_bounded_review_tasks_keyed(pending, max_concurrency, start, on_completed, |_| {
        Vec::new()
    })
    .await
}

async fn run_bounded_review_tasks_keyed<I, R, Start, Task, Complete, Keys>(
    mut pending: VecDeque<I>,
    max_concurrency: usize,
    mut start: Start,
    mut on_completed: Complete,
    keys_for: Keys,
) -> Result<Vec<R>, String>
where
    I: Send + 'static,
    R: Send + 'static,
    Start: FnMut(I) -> Task,
    Task: Future<Output = Result<R, String>> + Send + 'static,
    Complete: FnMut(&R) -> Result<(), String>,
    Keys: Fn(&I) -> Vec<String>,
{
    let mut tasks = JoinSet::new();
    let mut completed = Vec::with_capacity(pending.len());
    let mut active_keys = std::collections::HashSet::new();
    let max_concurrency = max_concurrency.max(1);

    loop {
        while tasks.len() < max_concurrency {
            let Some(position) = pending
                .iter()
                .position(|item| keys_for(item).iter().all(|key| !active_keys.contains(key)))
            else {
                break;
            };
            let item = pending
                .remove(position)
                .expect("eligible pending review should exist");
            let keys = keys_for(&item);
            active_keys.extend(keys.iter().cloned());
            let task = start(item);
            tasks.spawn(async move { (keys, task.await) });
        }

        if tasks.is_empty() {
            break;
        }

        match tasks.join_next().await {
            Some(Ok((keys, Ok(result)))) => {
                for key in keys {
                    active_keys.remove(&key);
                }
                if let Err(err) = on_completed(&result) {
                    abort_and_drain(&mut tasks).await;
                    return Err(err);
                }
                completed.push(result);
            }
            Some(Ok((_, Err(err)))) => {
                abort_and_drain(&mut tasks).await;
                return Err(err);
            }
            Some(Err(err)) => {
                abort_and_drain(&mut tasks).await;
                return Err(format!("LLM review task failed: {err}"));
            }
            None => break,
        }
    }

    Ok(completed)
}

fn review_unit_cache_keys(unit: &[(String, ReviewJob)]) -> Vec<String> {
    let mut keys = unit
        .iter()
        .map(|(_, job)| match job {
            ReviewJob::Method { method, .. } => method.file_path.clone(),
            ReviewJob::File { file, .. } => file.file_path.clone(),
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointEntry {
    key: String,
    verdict: Option<LLMVerdict>,
    in_tok: usize,
    out_tok: usize,
    #[serde(default)]
    cached_in_tok: usize,
    #[serde(default)]
    retry_on_resume: Option<bool>,
}

fn checkpoint_entry_is_reusable(entry: &CheckpointEntry) -> bool {
    match entry.retry_on_resume {
        Some(retry_on_resume) => !retry_on_resume,
        None => !entry.verdict.as_ref().is_some_and(|verdict| {
            verdict.tier == FindingTier::Unresolved
                && verdict
                    .reason
                    .starts_with("AI review could not be validated.")
        }),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckpointFile {
    version: u32,
    fingerprint: u64,
    #[serde(default)]
    context: String,
    completed: Vec<CheckpointEntry>,
}

struct CheckpointStore {
    path: PathBuf,
    fingerprint: u64,
    context: String,
    completed: HashMap<String, CheckpointEntry>,
    migrated_from_previous_contract: bool,
}

impl CheckpointStore {
    fn load(path: &Path, fingerprint: u64, context: &str) -> Result<Self, String> {
        let (completed, migrated_from_previous_contract) = match std::fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str::<CheckpointFile>(&contents) {
                Ok(file)
                    if file.version == 2
                        && (same_review_context(&file.context, context)
                            || previous_contract_context(&file.context, context)) =>
                {
                    let migrated = previous_contract_context(&file.context, context);
                    (
                        file.completed
                            .into_iter()
                            .map(|entry| (entry.key.clone(), entry))
                            .collect(),
                        migrated,
                    )
                }
                Ok(file) if file.version == 1 => {
                    let legacy_keys = file.fingerprint != fingerprint
                        && !file.completed.is_empty()
                        && file
                            .completed
                            .iter()
                            .all(|entry| entry.key.split_once(':').is_some());
                    if file.fingerprint != fingerprint && !legacy_keys {
                        (HashMap::new(), false)
                    } else {
                        (
                            file.completed
                                .into_iter()
                                .map(|mut entry| {
                                    if legacy_keys
                                        && let Some((_, stable_key)) = entry.key.split_once(':')
                                    {
                                        entry.key = stable_key.to_string();
                                    }
                                    (entry.key.clone(), entry)
                                })
                                .collect(),
                            false,
                        )
                    }
                }
                Ok(_) => (HashMap::new(), false),
                Err(err) => {
                    eprintln!(
                        "Ignoring unreadable Sniff checkpoint {}: {}",
                        path.display(),
                        err
                    );
                    (HashMap::new(), false)
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (HashMap::new(), false),
            Err(err) => {
                return Err(format!(
                    "failed to read Sniff checkpoint {}: {err}",
                    path.display()
                ));
            }
        };

        Ok(Self {
            path: path.to_path_buf(),
            fingerprint,
            context: context.to_string(),
            completed,
            migrated_from_previous_contract,
        })
    }

    fn migrate_previous_contract(&mut self, jobs: &[ReviewJob]) -> Result<(), String> {
        if !self.migrated_from_previous_contract {
            return Ok(());
        }

        // Method-review contracts may change judgment or evidence semantics.
        // Only independent file reviews are safe to carry across that boundary.
        let reusable_file_keys = jobs
            .iter()
            .filter(|job| matches!(job, ReviewJob::File { .. }))
            .map(ReviewJob::checkpoint_key)
            .collect::<std::collections::HashSet<_>>();
        self.completed.retain(|key, entry| {
            reusable_file_keys.contains(key) && checkpoint_entry_is_reusable(entry)
        });
        self.migrated_from_previous_contract = false;
        self.persist()
    }

    fn record(&mut self, key: String, outcome: &ReviewOutcome) -> Result<(), String> {
        self.completed.insert(
            key.clone(),
            CheckpointEntry {
                key,
                verdict: outcome.verdict.clone(),
                in_tok: outcome.in_tok,
                out_tok: outcome.out_tok,
                cached_in_tok: outcome.cached_in_tok,
                retry_on_resume: Some(outcome.retry_on_resume),
            },
        );
        self.persist()
    }

    fn persist(&self) -> Result<(), String> {
        let mut completed: Vec<_> = self.completed.values().cloned().collect();
        completed.sort_by(|left, right| left.key.cmp(&right.key));
        let contents = serde_json::to_string_pretty(&CheckpointFile {
            version: 2,
            fingerprint: self.fingerprint,
            context: self.context.clone(),
            completed,
        })
        .map_err(|err| format!("failed to serialize Sniff checkpoint: {err}"))?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create Sniff checkpoint directory {}: {err}",
                    parent.display()
                )
            })?;
        }

        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, contents).map_err(|err| {
            format!(
                "failed to write Sniff checkpoint {}: {err}",
                temporary.display()
            )
        })?;
        let mut last_error = None;
        for attempt in 0..8 {
            if self.path.exists()
                && let Err(err) = std::fs::remove_file(&self.path)
            {
                last_error = Some(format!("failed to replace checkpoint: {err}"));
                std::thread::sleep(Duration::from_millis(100 * (attempt + 1)));
                continue;
            }

            match std::fs::rename(&temporary, &self.path) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last_error = Some(format!("failed to finalize checkpoint: {err}"));
                    std::thread::sleep(Duration::from_millis(100 * (attempt + 1)));
                }
            }
        }

        Err(format!(
            "failed to replace Sniff checkpoint {} after retries: {}",
            self.path.display(),
            last_error.unwrap_or_else(|| "unknown file replacement error".to_string())
        ))
    }

    #[cfg(test)]
    fn remove(self) -> Result<(), String> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to remove completed Sniff checkpoint {}: {err}",
                self.path.display()
            )),
        }
    }
}

impl ReviewJob {
    fn label(&self) -> String {
        match self {
            Self::Method { method, .. } => format!("method {}::{}", method.file_path, method.name),
            Self::File { file, .. } => format!("file {}", file.file_path),
        }
    }

    fn checkpoint_key(&self) -> String {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        match self {
            Self::Method {
                method,
                static_signals,
                dossier,
                ..
            } => {
                "method".hash(&mut hasher);
                method.file_path.hash(&mut hasher);
                method.name.hash(&mut hasher);
                method.source.hash(&mut hasher);
                method.start_line.hash(&mut hasher);
                method.end_line.hash(&mut hasher);
                let mut sorted_signals = static_signals.clone();
                sorted_signals.sort();
                sorted_signals.hash(&mut hasher);
                dossier.full_file.hash(&mut hasher);
                let mut sorted_boundaries = dossier.boundary_requirements.clone();
                sorted_boundaries.sort();
                sorted_boundaries.hash(&mut hasher);
                dossier
                    .repository_private_unused_candidate
                    .hash(&mut hasher);
                dossier.stale_discard_signature_proof.hash(&mut hasher);
                if let Some(proof) = super::dossier::duplicated_branch_construct(method) {
                    "duplicated_branch_construct".hash(&mut hasher);
                    proof.hash(&mut hasher);
                } else if let Some(rejected) =
                    super::dossier::rejected_non_exhaustive_duplicate_branch(method)
                {
                    "rejected_non_exhaustive_duplicate_branch".hash(&mut hasher);
                    rejected.hash(&mut hasher);
                }
                let compact_context = dossier
                    .context
                    .split_once("Method dossier:\n")
                    .map(|(_, context)| context)
                    .unwrap_or(&dossier.context);
                let mut context_lines = compact_context.lines().collect::<Vec<_>>();
                context_lines.sort_unstable();
                context_lines.hash(&mut hasher);
                let mut sorted_callees = dossier.callees.iter().collect::<Vec<_>>();
                sorted_callees.sort_by(|left, right| {
                    left.file_path
                        .cmp(&right.file_path)
                        .then(left.line.cmp(&right.line))
                        .then(left.snippet.cmp(&right.snippet))
                });
                for reference in sorted_callees {
                    reference.file_path.hash(&mut hasher);
                    reference.line.hash(&mut hasher);
                    reference.snippet.hash(&mut hasher);
                }
                let mut sorted_references = method.references.iter().collect::<Vec<_>>();
                sorted_references.sort_by(|left, right| {
                    left.file_path
                        .cmp(&right.file_path)
                        .then(left.line.cmp(&right.line))
                        .then(left.snippet.cmp(&right.snippet))
                });
                for reference in sorted_references {
                    reference.file_path.hash(&mut hasher);
                    reference.line.hash(&mut hasher);
                    reference.snippet.hash(&mut hasher);
                }
                crate::roles::file_role_label(crate::roles::classify_file_role(&method.file_path))
                    .hash(&mut hasher);
            }
            Self::File {
                file,
                static_signals,
                ..
            } => {
                "file".hash(&mut hasher);
                file.file_path.hash(&mut hasher);
                file.source.hash(&mut hasher);
                let mut sorted_signals = static_signals.clone();
                sorted_signals.sort();
                sorted_signals.hash(&mut hasher);
                crate::roles::file_role_label(crate::roles::classify_file_role(&file.file_path))
                    .hash(&mut hasher);
            }
        }
        // The job identity is already unique for a method or file. Do not
        // include the scan position: filesystem traversal order may change
        // between retries, but completed reviews must remain reusable.
        format!("{:016x}", hasher.finish())
    }

    fn method_file_path(&self) -> Option<&str> {
        match self {
            Self::Method { method, .. } => Some(&method.file_path),
            Self::File { .. } => None,
        }
    }
}

fn previous_contract_context(previous: &str, current: &str) -> bool {
    let previous = without_binary_version(previous);
    let current = without_binary_version(current);
    [
        "semantic-method-v12",
        "semantic-method-v13",
        "semantic-method-v14",
        "semantic-method-v15",
        "semantic-method-v16",
        "semantic-method-v17",
        "semantic-method-v18",
        "semantic-method-v19",
        "semantic-method-v20",
        "semantic-method-v21",
        "semantic-method-v22",
        "semantic-method-v23",
        "semantic-method-v24",
        "semantic-method-v25",
        "semantic-method-v26",
    ]
    .into_iter()
    .any(|version| {
        previous.replace(
            &format!("review_contract={version}"),
            "review_contract=semantic-method-v27",
        ) == current
            && previous.contains(&format!("review_contract={version}"))
    })
}

fn same_review_context(left: &str, right: &str) -> bool {
    without_binary_version(left) == without_binary_version(right)
}

fn without_binary_version(context: &str) -> String {
    context
        .lines()
        .filter(|line| !line.starts_with("sniff_version="))
        .collect::<Vec<_>>()
        .join("\n")
}

fn method_batch_size() -> usize {
    let configured = std::env::var("SNIFF_LLM_METHOD_BATCH_SIZE")
        .or_else(|_| std::env::var("LLM_METHOD_BATCH_SIZE"))
        .ok();
    parse_method_batch_size(configured.as_deref())
}

fn parse_method_batch_size(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(1, 8))
        .unwrap_or(8)
}

fn estimated_method_prompt_chars(job: &ReviewJob, include_shared_file: bool) -> Option<usize> {
    let ReviewJob::Method {
        method,
        static_signals,
        dossier,
        ..
    } = job
    else {
        return None;
    };
    let compact_context = dossier
        .context
        .find("Method dossier:\n")
        .map(|index| &dossier.context[index..])
        .unwrap_or(&dossier.context);
    let callers = method
        .references
        .iter()
        .map(|reference| reference.file_path.len() + reference.snippet.len() + 64)
        .sum::<usize>();
    let callees = dossier
        .callees
        .iter()
        .map(|reference| reference.file_path.len() + reference.snippet.len() + 64)
        .sum::<usize>();
    let signals = static_signals.iter().map(String::len).sum::<usize>();
    let shared = if include_shared_file {
        dossier.full_file.len() + 25_000
    } else {
        0
    };
    Some(
        shared + compact_context.len() + method.source.len() + callers + callees + signals + 12_000,
    )
}

fn group_pending_reviews(
    pending: Vec<(String, ReviewJob)>,
    batch_size: usize,
    max_prompt_chars: usize,
) -> VecDeque<Vec<(String, ReviewJob)>> {
    let mut chunks = Vec::new();
    let mut current = Vec::<(String, ReviewJob)>::new();
    let mut current_file = None::<String>;
    let mut current_estimate = 0usize;
    for entry in pending {
        let file_path = entry.1.method_file_path().map(str::to_string);
        let incremental_estimate =
            estimated_method_prompt_chars(&entry.1, current.is_empty()).unwrap_or(usize::MAX);
        let joins_current = !current.is_empty()
            && file_path.is_some()
            && file_path == current_file
            && current.len() < batch_size
            && current_estimate.saturating_add(incremental_estimate) <= max_prompt_chars;
        if !joins_current && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            current_estimate = 0;
        }
        current_file = file_path;
        let entry_estimate =
            estimated_method_prompt_chars(&entry.1, current.is_empty()).unwrap_or(usize::MAX);
        current_estimate = current_estimate.saturating_add(entry_estimate);
        current.push(entry);
        if current.len() >= batch_size || current_file.is_none() {
            chunks.push(std::mem::take(&mut current));
            current_file = None;
            current_estimate = 0;
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    let mut grouped = VecDeque::new();
    let mut packed = Vec::new();
    for chunk in chunks {
        let is_method_chunk = chunk[0].1.method_file_path().is_some();
        if !is_method_chunk {
            if !packed.is_empty() {
                grouped.push_back(std::mem::take(&mut packed));
            }
            grouped.push_back(chunk);
            continue;
        }

        let mut candidate_estimate = 0usize;
        let mut seen_files = std::collections::HashSet::new();
        for (_, job) in packed.iter().chain(&chunk) {
            let Some(file_path) = job.method_file_path() else {
                candidate_estimate = usize::MAX;
                break;
            };
            candidate_estimate = candidate_estimate.saturating_add(
                estimated_method_prompt_chars(job, seen_files.insert(file_path.to_string()))
                    .unwrap_or(usize::MAX),
            );
        }
        if !packed.is_empty()
            && (packed.len() + chunk.len() > batch_size || candidate_estimate > max_prompt_chars)
        {
            grouped.push_back(std::mem::take(&mut packed));
        }
        packed.extend(chunk);
    }
    if !packed.is_empty() {
        grouped.push_back(packed);
    }
    grouped
}

fn jobs_fingerprint(jobs: &[ReviewJob], review_context_key: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    review_context_key.hash(&mut hasher);
    let mut keys = jobs
        .iter()
        .map(ReviewJob::checkpoint_key)
        .collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        key.hash(&mut hasher);
    }
    hasher.finish()
}

async fn run_review_job(
    analyzer: Arc<Analyzer>,
    job: ReviewJob,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<ReviewOutcome, String> {
    match job {
        ReviewJob::Method {
            index,
            method,
            static_signals,
            dossier,
        } => match analyzer
            .analyze_method_review_with_context(
                &method,
                &static_signals,
                MethodReviewContext {
                    file_context: &dossier.context,
                    project_root: Some(&dossier.project_root),
                    callee_context: &dossier.callees,
                    boundary_requirements: &dossier.boundary_requirements,
                    repository_private_unused_candidate: dossier
                        .repository_private_unused_candidate,
                    stale_discard_signature_proof: dossier.stale_discard_signature_proof.as_deref(),
                },
                on_progress,
            )
            .await
        {
            Ok((Some(verdict), in_tok, out_tok)) => Ok(ReviewOutcome {
                index,
                verdict: Some(verdict),
                in_tok,
                out_tok,
                cached_in_tok: 0,
                retry_on_resume: false,
            }),
            Ok((None, _, _)) => Err(format!(
                "LLM review failed: method {}::{} returned no verdict",
                method.file_path, method.name
            )),
            Err(err) if recoverable_method_review_error(&err) => Ok(ReviewOutcome {
                index,
                verdict: Some(unresolved_method_verdict(&method, &err)),
                in_tok: 0,
                out_tok: 0,
                cached_in_tok: 0,
                retry_on_resume: true,
            }),
            Err(err) => Err(format!(
                "LLM review failed: method {}::{}: {}",
                method.file_path, method.name, err
            )),
        },
        ReviewJob::File {
            index,
            file,
            static_signals,
        } => match analyzer
            .analyze_file_with_progress(&file, &static_signals, on_progress)
            .await
        {
            Ok((verdict, in_tok, out_tok)) => Ok(ReviewOutcome {
                index,
                verdict,
                in_tok,
                out_tok,
                cached_in_tok: 0,
                retry_on_resume: false,
            }),
            Err(err) => Err(format!(
                "LLM review failed: file {}: {}",
                file.file_path, err
            )),
        },
    }
}

fn token_share(total: usize, index: usize, count: usize) -> usize {
    (total / count) + usize::from(index < total % count)
}

fn unresolved_batch_outcomes(
    keys: Vec<String>,
    indices: Vec<usize>,
    methods: Vec<BatchMethodReview>,
    batch_error: &str,
) -> Vec<(String, ReviewOutcome)> {
    keys.into_iter()
        .zip(indices)
        .zip(methods)
        .map(|((key, index), item)| {
            let error = format!(
                "AI batch review could not be validated after targeted repair: {batch_error}"
            );
            (
                key,
                ReviewOutcome {
                    index,
                    verdict: Some(unresolved_method_verdict(&item.method, &error)),
                    in_tok: 0,
                    out_tok: 0,
                    cached_in_tok: 0,
                    retry_on_resume: true,
                },
            )
        })
        .collect()
}

async fn run_review_unit_untracked(
    analyzer: Arc<Analyzer>,
    unit: Vec<(String, ReviewJob)>,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<Vec<(String, ReviewOutcome)>, String> {
    if unit.len() == 1 && matches!(&unit[0].1, ReviewJob::File { .. }) {
        let (key, job) = unit.into_iter().next().expect("single review unit");
        return run_review_job(analyzer, job, on_progress)
            .await
            .map(|outcome| vec![(key, outcome)]);
    }

    let mut keys = Vec::with_capacity(unit.len());
    let mut indices = Vec::with_capacity(unit.len());
    let mut methods = Vec::with_capacity(unit.len());
    for (key, job) in unit {
        let ReviewJob::Method {
            index,
            method,
            static_signals,
            dossier,
        } = job
        else {
            return Err("file review was incorrectly placed in a method batch".to_string());
        };
        keys.push(key);
        indices.push(index);
        methods.push(BatchMethodReview {
            method,
            static_signals,
            full_file: dossier.full_file,
            file_context: dossier.context,
            project_root: dossier.project_root,
            callee_context: dossier.callees,
            boundary_requirements: dossier.boundary_requirements,
            repository_private_unused_candidate: dossier.repository_private_unused_candidate,
            stale_discard_signature_proof: dossier.stale_discard_signature_proof,
        });
    }

    let mut pending_batches = VecDeque::from([(keys, indices, methods)]);
    let mut completed = Vec::new();
    while let Some((mut keys, mut indices, mut methods)) = pending_batches.pop_front() {
        match analyzer
            .analyze_method_review_batch(&methods, on_progress)
            .await
        {
            Ok((verdicts, input_tokens, output_tokens)) => {
                if verdicts.len() != methods.len() {
                    return Err(format!(
                        "method batch returned {} verdicts for {} methods",
                        verdicts.len(),
                        methods.len()
                    ));
                }
                let count = methods.len();
                completed.extend(keys.into_iter().zip(indices).zip(verdicts).enumerate().map(
                    |(position, ((key, index), verdict))| {
                        (
                            key,
                            ReviewOutcome {
                                index,
                                retry_on_resume: verdict.tier == FindingTier::Unresolved
                                    && verdict
                                        .reason
                                        .starts_with("AI review could not be validated."),
                                verdict: Some(verdict),
                                in_tok: token_share(input_tokens, position, count),
                                out_tok: token_share(output_tokens, position, count),
                                cached_in_tok: 0,
                            },
                        )
                    },
                ));
            }
            Err(err) if recoverable_method_review_error(&err) && methods.len() > 1 => {
                let split_at = methods.len() / 2;
                if let Some(callback) = on_progress {
                    callback(ReviewProgress::RetryingEvidence {
                        label: format!(
                            "splitting invalid batch of {} methods into {} and {}",
                            methods.len(),
                            split_at,
                            methods.len() - split_at
                        ),
                    });
                }
                let right_keys = keys.split_off(split_at);
                let right_indices = indices.split_off(split_at);
                let right_methods = methods.split_off(split_at);
                pending_batches.push_front((right_keys, right_indices, right_methods));
                pending_batches.push_front((keys, indices, methods));
            }
            Err(err) if recoverable_method_review_error(&err) => {
                completed.extend(unresolved_batch_outcomes(keys, indices, methods, &err));
            }
            Err(err) => return Err(format!("LLM method batch failed: {err}")),
        }
    }
    Ok(completed)
}

async fn run_review_unit(
    analyzer: Arc<Analyzer>,
    unit: Vec<(String, ReviewJob)>,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<Vec<(String, ReviewOutcome)>, String> {
    let (mut result, cached_input_tokens) = crate::llm::LLMClient::track_cached_input_tokens(
        run_review_unit_untracked(analyzer, unit, on_progress),
    )
    .await;
    if let Ok(outcomes) = result.as_mut() {
        let count = outcomes.len();
        for (position, (_, outcome)) in outcomes.iter_mut().enumerate() {
            outcome.cached_in_tok = token_share(cached_input_tokens, position, count);
        }
    }
    result
}

fn recoverable_method_review_error(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("semantic review remained invalid after repair")
        || normalized.contains("intent review remained invalid after repair")
        || normalized.contains("invalid intent review")
    {
        return true;
    }

    // A method review can exhaust lower-level schema retries before the
    // semantic wrapper adds its stage-specific error. Treat invalid model
    // output as unresolved, but keep exhausted transport/provider failures
    // fatal.
    let exhausted = normalized.contains("maximum attempt count")
        || normalized.contains("retry budget exhausted")
        || normalized.contains("response format remained invalid after");
    let invalid_model_output = normalized.contains("wrong field types:")
        || normalized.contains("missing fields:")
        || normalized.contains("no json object found")
        || normalized.contains("empty assistant content")
        || normalized.contains("empty response content")
        || normalized.contains("invalid json response");
    exhausted && invalid_model_output
}

fn unresolved_method_verdict(method: &MethodRecord, error: &str) -> LLMVerdict {
    LLMVerdict {
        verdict_type: "method".to_string(),
        file_path: method.file_path.clone(),
        method_name: Some(method.name.clone()),
        check_type: "method".to_string(),
        smelly: false,
        tier: FindingTier::Unresolved,
        cohesive: None,
        name_accurate: None,
        evidence: String::new(),
        reason: format!("AI review could not be validated. Missing evidence: {error}"),
        loc: method.loc,
        start_line: method.start_line,
        end_line: method.end_line,
    }
}

pub(super) async fn run_review_jobs(
    analyzer: Arc<Analyzer>,
    jobs: Vec<ReviewJob>,
    on_progress: Option<ReviewProgressCallback>,
    review_context_key: &str,
    checkpoint_path: Option<&Path>,
) -> Result<Vec<LLMVerdict>, String> {
    let fingerprint = jobs_fingerprint(&jobs, review_context_key);
    let mut checkpoint = checkpoint_path
        .map(|path| CheckpointStore::load(path, fingerprint, review_context_key))
        .transpose()?;
    if let Some(store) = checkpoint.as_mut() {
        store.migrate_previous_contract(&jobs)?;
    }
    let mut outcomes = Vec::with_capacity(jobs.len());
    let mut pending = Vec::new();
    for (index, job) in jobs.into_iter().enumerate() {
        let checkpoint_key = job.checkpoint_key();
        if let Some(entry) = checkpoint
            .as_ref()
            .and_then(|store| store.completed.get(&checkpoint_key))
            .filter(|entry| checkpoint_entry_is_reusable(entry))
        {
            analyzer.in_tok.fetch_add(entry.in_tok, Ordering::SeqCst);
            analyzer.out_tok.fetch_add(entry.out_tok, Ordering::SeqCst);
            analyzer
                .llm_client
                .restore_cached_input_tokens(entry.cached_in_tok);
            outcomes.push(ReviewOutcome {
                index,
                verdict: entry.verdict.clone(),
                in_tok: entry.in_tok,
                out_tok: entry.out_tok,
                cached_in_tok: entry.cached_in_tok,
                retry_on_resume: false,
            });
            if let Some(callback) = on_progress.as_ref() {
                callback(ReviewProgress::Completed);
            }
            continue;
        }

        pending.push((checkpoint_key, job));
    }
    let pending = group_pending_reviews(
        pending,
        method_batch_size(),
        analyzer.llm_client.max_prompt_chars(),
    );

    let completed = run_bounded_review_tasks_keyed(
        pending,
        analyzer.llm_client.max_concurrency(),
        |unit| {
            let analyzer = Arc::clone(&analyzer);
            let progress = on_progress.clone();
            async move {
                if let Some(callback) = progress.as_ref() {
                    for (_, job) in &unit {
                        callback(ReviewProgress::Started { label: job.label() });
                    }
                }
                run_review_unit(analyzer, unit, progress.as_ref()).await
            }
        },
        |unit| {
            for (checkpoint_key, outcome) in unit {
                analyzer.in_tok.fetch_add(outcome.in_tok, Ordering::SeqCst);
                analyzer
                    .out_tok
                    .fetch_add(outcome.out_tok, Ordering::SeqCst);
                if let Some(store) = checkpoint.as_mut() {
                    store.record(checkpoint_key.clone(), outcome)?;
                }
                if let Some(callback) = on_progress.as_ref() {
                    callback(ReviewProgress::Completed);
                }
            }
            Ok(())
        },
        |unit| review_unit_cache_keys(unit),
    )
    .await?;
    outcomes.extend(completed.into_iter().flatten().map(|(_, outcome)| outcome));

    if let Some(store) = checkpoint {
        store.persist()?;
    }

    outcomes.sort_by_key(|outcome| outcome.index);
    Ok(outcomes
        .into_iter()
        .filter_map(|outcome| outcome.verdict)
        .collect())
}

#[cfg(test)]
#[path = "tests/analyzer_engine_jobs.rs"]
mod tests;
