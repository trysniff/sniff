use crate::report_types::{LLMVerdict, MethodReviewRecord};
use crate::types::{FileRecord, FindingTier, MethodRecord};
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;

use super::dossier::MethodDossier;
use super::method_batch_review::BatchMethodReview;
use super::method_review::MethodReviewContext;
use super::{Analyzer, ReviewProgress, ReviewProgressCallback};
use crate::review_journal::{JournalCompletion, JournalEntry, JournalStore, sha256_text};

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
    method_record: Option<MethodReviewRecord>,
    in_tok: usize,
    out_tok: usize,
    cached_in_tok: usize,
    retry_on_resume: bool,
    persisted: bool,
}

type ReviewItemCompletionCallback =
    Arc<dyn Fn(&str, &ReviewOutcome) -> Result<(), String> + Send + Sync>;

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

#[cfg(test)]
async fn run_bounded_review_tasks_keyed<I, R, Start, Task, Complete, Keys>(
    pending: VecDeque<I>,
    max_concurrency: usize,
    start: Start,
    on_completed: Complete,
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
    run_bounded_review_tasks_keyed_until(
        pending,
        max_concurrency,
        start,
        on_completed,
        keys_for,
        || true,
    )
    .await
    .map(|run| run.completed)
}

struct BoundedTaskRun<R> {
    completed: Vec<R>,
    stopped_early: bool,
}

#[derive(Debug)]
struct SpendBudget {
    limit_usd: Option<f64>,
    spent_usd: f64,
}

impl SpendBudget {
    fn can_start(&self) -> bool {
        self.limit_usd.is_none_or(|limit| self.spent_usd < limit)
    }

    fn add(&mut self, cost_usd: f64) {
        self.spent_usd += cost_usd;
    }
}

async fn run_bounded_review_tasks_keyed_until<I, R, Start, Task, Complete, Keys, CanStart>(
    mut pending: VecDeque<I>,
    max_concurrency: usize,
    mut start: Start,
    mut on_completed: Complete,
    keys_for: Keys,
    mut can_start: CanStart,
) -> Result<BoundedTaskRun<R>, String>
where
    I: Send + 'static,
    R: Send + 'static,
    Start: FnMut(I) -> Task,
    Task: Future<Output = Result<R, String>> + Send + 'static,
    Complete: FnMut(&R) -> Result<(), String>,
    Keys: Fn(&I) -> Vec<String>,
    CanStart: FnMut() -> bool,
{
    let mut tasks = JoinSet::new();
    let mut completed = Vec::with_capacity(pending.len());
    let mut active_keys = std::collections::HashSet::new();
    let max_concurrency = max_concurrency.max(1);
    let mut first_error = None;

    loop {
        while first_error.is_none() && tasks.len() < max_concurrency {
            if !can_start() {
                break;
            }
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
            Some(Ok((keys, Err(err)))) => {
                for key in keys {
                    active_keys.remove(&key);
                }
                first_error.get_or_insert(err);
            }
            Some(Err(err)) => {
                first_error.get_or_insert_with(|| format!("LLM review task failed: {err}"));
            }
            None => break,
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(BoundedTaskRun {
            completed,
            stopped_early: !pending.is_empty(),
        }),
    }
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

fn journal_entry_is_reusable(entry: &JournalEntry) -> bool {
    entry.is_reusable()
}

fn push_identity_field(identity: &mut String, label: &str, value: &str) {
    identity.push_str(&label.len().to_string());
    identity.push(':');
    identity.push_str(label);
    identity.push_str(&value.len().to_string());
    identity.push(':');
    identity.push_str(value);
}

impl ReviewJob {
    fn label(&self) -> String {
        match self {
            Self::Method { method, .. } => format!("method {}::{}", method.file_path, method.name),
            Self::File { file, .. } => format!("file {}", file.file_path),
        }
    }

    fn journal_unit_id(&self) -> String {
        let mut identity = String::new();
        match self {
            Self::Method {
                method,
                static_signals,
                dossier,
                ..
            } => {
                push_identity_field(&mut identity, "kind", "method");
                push_identity_field(&mut identity, "file_path", &method.file_path);
                push_identity_field(&mut identity, "method_name", &method.name);
                push_identity_field(&mut identity, "source", &method.source);
                push_identity_field(&mut identity, "start_line", &method.start_line.to_string());
                push_identity_field(&mut identity, "end_line", &method.end_line.to_string());
                let mut sorted_signals = static_signals.clone();
                sorted_signals.sort();
                push_identity_field(
                    &mut identity,
                    "signal_count",
                    &sorted_signals.len().to_string(),
                );
                for signal in sorted_signals {
                    push_identity_field(&mut identity, "signal", &signal);
                }
                push_identity_field(&mut identity, "full_file", &dossier.full_file);
                let mut sorted_boundaries = dossier.boundary_requirements.clone();
                sorted_boundaries.sort();
                push_identity_field(
                    &mut identity,
                    "boundary_count",
                    &sorted_boundaries.len().to_string(),
                );
                for boundary in sorted_boundaries {
                    push_identity_field(&mut identity, "boundary", &boundary);
                }
                push_identity_field(
                    &mut identity,
                    "private_unused_candidate",
                    if dossier.repository_private_unused_candidate {
                        "true"
                    } else {
                        "false"
                    },
                );
                if let Some(proof) = dossier.stale_discard_signature_proof.as_deref() {
                    push_identity_field(&mut identity, "stale_discard_proof", "present");
                    push_identity_field(
                        &mut identity,
                        "discarded_parameter_count",
                        &proof.discarded_parameters.len().to_string(),
                    );
                    for parameter in &proof.discarded_parameters {
                        push_identity_field(&mut identity, "discarded_parameter", parameter);
                    }
                    push_identity_field(
                        &mut identity,
                        "caller_site_count",
                        &proof.caller_sites.len().to_string(),
                    );
                    for caller in &proof.caller_sites {
                        push_identity_field(&mut identity, "caller_site", caller);
                    }
                } else {
                    push_identity_field(&mut identity, "stale_discard_proof", "absent");
                }
                if let Some(proof) = super::dossier::duplicated_branch_construct(method) {
                    push_identity_field(&mut identity, "branch_proof", "duplicated");
                    push_identity_field(&mut identity, "branch_proof_value", &proof);
                } else if let Some(rejected) =
                    super::dossier::rejected_non_exhaustive_duplicate_branch(method)
                {
                    push_identity_field(&mut identity, "branch_proof", "rejected_non_exhaustive");
                    push_identity_field(&mut identity, "branch_proof_value", &rejected);
                } else {
                    push_identity_field(&mut identity, "branch_proof", "absent");
                }
                let compact_context = dossier
                    .context
                    .split_once("Method dossier:\n")
                    .map(|(_, context)| context)
                    .unwrap_or(&dossier.context);
                let mut context_lines = compact_context.lines().collect::<Vec<_>>();
                context_lines.sort_unstable();
                push_identity_field(
                    &mut identity,
                    "context_line_count",
                    &context_lines.len().to_string(),
                );
                for line in context_lines {
                    push_identity_field(&mut identity, "context_line", line);
                }
                let mut sorted_callees = dossier.callees.iter().collect::<Vec<_>>();
                sorted_callees.sort_by(|left, right| {
                    left.file_path
                        .cmp(&right.file_path)
                        .then(left.line.cmp(&right.line))
                        .then(left.snippet.cmp(&right.snippet))
                });
                push_identity_field(
                    &mut identity,
                    "callee_count",
                    &sorted_callees.len().to_string(),
                );
                for reference in sorted_callees {
                    push_identity_field(&mut identity, "callee_path", &reference.file_path);
                    push_identity_field(&mut identity, "callee_line", &reference.line.to_string());
                    push_identity_field(&mut identity, "callee_snippet", &reference.snippet);
                }
                let mut sorted_references = method.references.iter().collect::<Vec<_>>();
                sorted_references.sort_by(|left, right| {
                    left.file_path
                        .cmp(&right.file_path)
                        .then(left.line.cmp(&right.line))
                        .then(left.snippet.cmp(&right.snippet))
                });
                push_identity_field(
                    &mut identity,
                    "reference_count",
                    &sorted_references.len().to_string(),
                );
                for reference in sorted_references {
                    push_identity_field(&mut identity, "reference_path", &reference.file_path);
                    push_identity_field(
                        &mut identity,
                        "reference_line",
                        &reference.line.to_string(),
                    );
                    push_identity_field(&mut identity, "reference_snippet", &reference.snippet);
                }
                push_identity_field(
                    &mut identity,
                    "file_role",
                    crate::roles::file_role_label(crate::roles::classify_file_role(
                        &method.file_path,
                    )),
                );
            }
            Self::File {
                file,
                static_signals,
                ..
            } => {
                push_identity_field(&mut identity, "kind", "file");
                push_identity_field(&mut identity, "file_path", &file.file_path);
                push_identity_field(&mut identity, "source", &file.source);
                let mut sorted_signals = static_signals.clone();
                sorted_signals.sort();
                push_identity_field(
                    &mut identity,
                    "signal_count",
                    &sorted_signals.len().to_string(),
                );
                for signal in sorted_signals {
                    push_identity_field(&mut identity, "signal", &signal);
                }
                push_identity_field(
                    &mut identity,
                    "file_role",
                    crate::roles::file_role_label(crate::roles::classify_file_role(
                        &file.file_path,
                    )),
                );
            }
        }
        // The job identity is already unique for a method or file. Do not
        // include the scan position: filesystem traversal order may change
        // between retries, but completed reviews must remain reusable.
        sha256_text(&identity)
    }

    fn source_hash(&self) -> String {
        match self {
            Self::Method { method, .. } => sha256_text(&method.source),
            Self::File { file, .. } => sha256_text(&file.source),
        }
    }

    fn method_file_path(&self) -> Option<&str> {
        match self {
            Self::Method { method, .. } => Some(&method.file_path),
            Self::File { .. } => None,
        }
    }
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

fn semantic_index_hash(jobs: &[ReviewJob]) -> String {
    let mut keys = jobs
        .iter()
        .map(ReviewJob::journal_unit_id)
        .collect::<Vec<_>>();
    keys.sort();
    sha256_text(&keys.join("\n"))
}

async fn run_review_job(
    analyzer: Arc<Analyzer>,
    job: ReviewJob,
    on_progress: Option<&ReviewProgressCallback>,
) -> Result<ReviewOutcome, String> {
    let unit_id = job.journal_unit_id();
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
                method_record: Some(MethodReviewRecord::from_method(
                    unit_id,
                    sha256_text(&method.source),
                    &method,
                    verdict.clone(),
                )),
                verdict: Some(verdict),
                in_tok,
                out_tok,
                cached_in_tok: 0,
                retry_on_resume: false,
                persisted: false,
            }),
            Ok((None, _, _)) => Err(format!(
                "LLM review failed: method {}::{} returned no verdict",
                method.file_path, method.name
            )),
            Err(err) if recoverable_method_review_error(&err) => {
                let verdict = unresolved_method_verdict(&method, &err);
                Ok(ReviewOutcome {
                    index,
                    method_record: Some(MethodReviewRecord::from_method(
                        unit_id,
                        sha256_text(&method.source),
                        &method,
                        verdict.clone(),
                    )),
                    verdict: Some(verdict),
                    in_tok: 0,
                    out_tok: 0,
                    cached_in_tok: 0,
                    retry_on_resume: true,
                    persisted: false,
                })
            }
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
                method_record: None,
                in_tok,
                out_tok,
                cached_in_tok: 0,
                retry_on_resume: false,
                persisted: false,
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
            let verdict = unresolved_method_verdict(&item.method, &error);
            (
                key.clone(),
                ReviewOutcome {
                    index,
                    method_record: Some(MethodReviewRecord::from_method(
                        key.clone(),
                        sha256_text(&item.method.source),
                        &item.method,
                        verdict.clone(),
                    )),
                    verdict: Some(verdict),
                    in_tok: 0,
                    out_tok: 0,
                    cached_in_tok: 0,
                    retry_on_resume: true,
                    persisted: false,
                },
            )
        })
        .collect()
}

async fn run_review_unit_untracked(
    analyzer: Arc<Analyzer>,
    unit: Vec<(String, ReviewJob)>,
    on_progress: Option<&ReviewProgressCallback>,
    on_usage: Option<&super::method_batch_review::BatchUsageCallback>,
    on_item_completed: Option<&ReviewItemCompletionCallback>,
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
        let method_metadata = Arc::new(
            methods
                .iter()
                .map(|item| item.method.clone())
                .collect::<Vec<_>>(),
        );
        let completion_count = Arc::new(AtomicUsize::new(0));
        let batch_completion = on_item_completed.map(|callback| {
            let callback = Arc::clone(callback);
            let method_metadata = Arc::clone(&method_metadata);
            let completion_count = Arc::clone(&completion_count);
            let completion_keys = keys.clone();
            let completion_indices = indices.clone();
            Arc::new(move |position: usize, verdict: &LLMVerdict| {
                let key = completion_keys
                    .get(position)
                    .ok_or_else(|| format!("batch completed unknown method position {position}"))?;
                let index = *completion_indices
                    .get(position)
                    .ok_or_else(|| format!("batch completed unknown method position {position}"))?;
                let outcome = ReviewOutcome {
                    index,
                    method_record: Some(MethodReviewRecord::from_method(
                        key.clone(),
                        sha256_text(&method_metadata[position].source),
                        &method_metadata[position],
                        verdict.clone(),
                    )),
                    verdict: Some(verdict.clone()),
                    in_tok: 0,
                    out_tok: 0,
                    cached_in_tok: 0,
                    retry_on_resume: verdict.tier == FindingTier::Unresolved
                        && verdict
                            .reason
                            .starts_with("AI review could not be validated."),
                    persisted: true,
                };
                callback(key, &outcome)?;
                completion_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }) as super::method_batch_review::BatchCompletionCallback
        });
        match analyzer
            .analyze_method_review_batch(&methods, on_progress, on_usage, batch_completion.as_ref())
            .await
        {
            Ok((verdicts, _, _)) => {
                if verdicts.len() != methods.len() {
                    return Err(format!(
                        "method batch returned {} verdicts for {} methods",
                        verdicts.len(),
                        methods.len()
                    ));
                }
                let persisted = batch_completion.is_some();
                completed.extend(
                    keys.into_iter()
                        .zip(indices)
                        .zip(methods)
                        .zip(verdicts)
                        .map(|(((key, index), method), verdict)| {
                            (
                                key.clone(),
                                ReviewOutcome {
                                    index,
                                    method_record: Some(MethodReviewRecord::from_method(
                                        key.clone(),
                                        sha256_text(&method.method.source),
                                        &method.method,
                                        verdict.clone(),
                                    )),
                                    retry_on_resume: verdict.tier == FindingTier::Unresolved
                                        && verdict
                                            .reason
                                            .starts_with("AI review could not be validated."),
                                    verdict: Some(verdict),
                                    in_tok: 0,
                                    out_tok: 0,
                                    cached_in_tok: 0,
                                    persisted,
                                },
                            )
                        }),
                );
            }
            Err(err)
                if recoverable_method_review_error(&err)
                    && methods.len() > 1
                    && completion_count.load(Ordering::SeqCst) == 0 =>
            {
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
            Err(err)
                if recoverable_method_review_error(&err)
                    && completion_count.load(Ordering::SeqCst) > 0 =>
            {
                return Err(format!(
                    "LLM method batch failed after {} method(s) were durably completed; resume from the journal: {err}",
                    completion_count.load(Ordering::SeqCst)
                ));
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
    on_usage: Option<&super::method_batch_review::BatchUsageCallback>,
    on_item_completed: Option<&ReviewItemCompletionCallback>,
) -> Result<Vec<(String, ReviewOutcome)>, String> {
    let is_file = unit.len() == 1 && matches!(&unit[0].1, ReviewJob::File { .. });
    if !is_file {
        return run_review_unit_untracked(analyzer, unit, on_progress, on_usage, on_item_completed)
            .await;
    }
    let (mut result, usage) = crate::llm::LLMClient::track_usage(run_review_unit_untracked(
        analyzer,
        unit,
        on_progress,
        on_usage,
        on_item_completed,
    ))
    .await;
    if let Ok(outcomes) = result.as_mut() {
        let count = outcomes.len();
        for (position, (_, outcome)) in outcomes.iter_mut().enumerate() {
            outcome.cached_in_tok = token_share(usage.cached_input_tokens, position, count);
            outcome.in_tok += token_share(usage.failed_input_tokens, position, count);
            outcome.out_tok += token_share(usage.failed_output_tokens, position, count);
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

fn validate_method_coverage(
    expected_methods: &HashMap<String, (MethodRecord, String)>,
    outcomes: &[ReviewOutcome],
) -> Result<(), String> {
    let mut seen_methods = HashSet::with_capacity(expected_methods.len());
    for outcome in outcomes {
        let Some(verdict) = outcome.verdict.as_ref() else {
            continue;
        };
        if verdict.check_type != "method" {
            continue;
        }
        let Some(record) = outcome.method_record.as_ref() else {
            return Err(format!(
                "method review {} produced a verdict without a durable method record",
                verdict.method_name.as_deref().unwrap_or("<unnamed>")
            ));
        };
        let Some((method, source_hash)) = expected_methods.get(&record.unit_id) else {
            return Err(format!(
                "method review produced a record for an unknown unit {}",
                record.unit_id
            ));
        };
        if !record.matches_method(&record.unit_id, source_hash, method)
            || record.verdict != *verdict
        {
            return Err(format!(
                "method review record does not match its source identity for {}::{}",
                method.file_path, method.name
            ));
        }
        if !seen_methods.insert(record.unit_id.clone()) {
            return Err(format!(
                "method review produced duplicate durable record {}",
                record.unit_id
            ));
        }
    }
    let missing = expected_methods
        .keys()
        .filter(|unit_id| !seen_methods.contains(*unit_id))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "method review coverage incomplete: {} of {} eligible methods have durable records; missing {}",
            seen_methods.len(),
            expected_methods.len(),
            missing.join(", ")
        ));
    }
    Ok(())
}

pub(super) async fn run_review_jobs(
    analyzer: Arc<Analyzer>,
    jobs: Vec<ReviewJob>,
    on_progress: Option<ReviewProgressCallback>,
    review_context_key: &str,
    journal_path: Option<&Path>,
    scan_id: Option<&str>,
    budget_usd: Option<f64>,
) -> Result<Vec<LLMVerdict>, String> {
    let expected_methods = jobs
        .iter()
        .filter_map(|job| match job {
            ReviewJob::Method { method, .. } => {
                Some((job.journal_unit_id(), (method.clone(), job.source_hash())))
            }
            ReviewJob::File { .. } => None,
        })
        .collect::<HashMap<_, _>>();
    let semantic_index_hash = semantic_index_hash(&jobs);
    let source_hashes = jobs
        .iter()
        .map(|job| (job.journal_unit_id(), job.source_hash()))
        .collect::<HashMap<_, _>>();
    let expected_units = jobs.len();
    let mut journal = journal_path
        .map(|path| {
            if let Some(scan_id) = scan_id {
                JournalStore::load_for_scan(
                    path,
                    scan_id,
                    crate::review_journal::JournalStage::Method,
                    &semantic_index_hash,
                    review_context_key,
                    expected_units,
                )
            } else {
                JournalStore::load_with_expected(
                    path,
                    &semantic_index_hash,
                    review_context_key,
                    expected_units,
                )
            }
        })
        .transpose()?;
    if let Some(store) = journal.as_ref() {
        let (stage_in_tok, stage_out_tok, stage_cached_in_tok) = store.stage_usage();
        analyzer.in_tok.fetch_add(stage_in_tok, Ordering::SeqCst);
        analyzer.out_tok.fetch_add(stage_out_tok, Ordering::SeqCst);
        analyzer
            .llm_client
            .restore_cached_input_tokens(stage_cached_in_tok);
    }
    if budget_usd.is_some() && journal.is_none() {
        return Err(
            "--budget-usd requires a durable journal path so completed work can be resumed"
                .to_string(),
        );
    }
    let spend_budget = Arc::new(Mutex::new(SpendBudget {
        limit_usd: budget_usd,
        spent_usd: journal.as_ref().map_or(0.0, JournalStore::spent_usd),
    }));
    let mut outcomes = Vec::with_capacity(jobs.len());
    let mut pending = Vec::new();
    for (index, job) in jobs.into_iter().enumerate() {
        let journal_unit_id = job.journal_unit_id();
        if let Some(entry) = journal
            .as_ref()
            .and_then(|store| store.completed.get(&journal_unit_id))
            .filter(|entry| journal_entry_is_reusable(entry))
            .cloned()
        {
            let is_current_scan = journal
                .as_ref()
                .is_some_and(|store| store.is_current_scan(&entry));
            if !is_current_scan {
                let source_hash = source_hashes.get(&journal_unit_id).ok_or_else(|| {
                    format!("missing source hash for cached review {journal_unit_id}")
                })?;
                journal
                    .as_mut()
                    .expect("cached journal entry requires a store")
                    .record(
                        journal_unit_id.clone(),
                        source_hash.clone(),
                        JournalCompletion {
                            verdict: entry.verdict.clone(),
                            method_record: entry.method_record.clone(),
                            in_tok: 0,
                            out_tok: 0,
                            cached_in_tok: 0,
                            retry_on_resume: false,
                        },
                    )?;
            }
            outcomes.push(ReviewOutcome {
                index,
                verdict: entry.verdict.clone(),
                method_record: entry.method_record.clone(),
                in_tok: 0,
                out_tok: 0,
                cached_in_tok: 0,
                retry_on_resume: false,
                persisted: true,
            });
            if let Some(callback) = on_progress.as_ref() {
                callback(ReviewProgress::Completed);
            }
            continue;
        }

        pending.push((journal_unit_id, job));
    }
    let pending = group_pending_reviews(
        pending,
        method_batch_size(),
        analyzer.llm_client.max_prompt_chars(),
    );
    let journal = journal.map(|store| Arc::new(Mutex::new(store)));
    let source_hashes = Arc::new(source_hashes);
    let item_completion: ReviewItemCompletionCallback = {
        let analyzer = Arc::clone(&analyzer);
        let journal = journal.clone();
        let source_hashes = Arc::clone(&source_hashes);
        let progress = on_progress.clone();
        let spend_budget = Arc::clone(&spend_budget);
        Arc::new(move |journal_unit_id, outcome| {
            if let Some(store) = journal.as_ref() {
                let source_hash = source_hashes.get(journal_unit_id).ok_or_else(|| {
                    format!("missing source hash for completed review {journal_unit_id}")
                })?;
                store
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .record(
                        journal_unit_id.to_string(),
                        source_hash.clone(),
                        JournalCompletion {
                            verdict: outcome.verdict.clone(),
                            method_record: outcome.method_record.clone(),
                            in_tok: outcome.in_tok,
                            out_tok: outcome.out_tok,
                            cached_in_tok: outcome.cached_in_tok,
                            retry_on_resume: outcome.retry_on_resume,
                        },
                    )?;
            }
            analyzer.in_tok.fetch_add(outcome.in_tok, Ordering::SeqCst);
            analyzer
                .out_tok
                .fetch_add(outcome.out_tok, Ordering::SeqCst);
            if let Some(callback) = progress.as_ref() {
                callback(ReviewProgress::Completed);
            }
            spend_budget
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add(crate::pricing::PricingRates::from_env().cost(
                    outcome.in_tok,
                    outcome.cached_in_tok,
                    outcome.out_tok,
                ));
            Ok(())
        })
    };
    let usage_completion: super::method_batch_review::BatchUsageCallback = {
        let analyzer = Arc::clone(&analyzer);
        let journal = journal.clone();
        let spend_budget = Arc::clone(&spend_budget);
        Arc::new(move |usage| {
            if let Some(store) = journal.as_ref() {
                store
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .record_usage(usage.in_tok, usage.out_tok, usage.cached_in_tok)?;
            }
            analyzer.in_tok.fetch_add(usage.in_tok, Ordering::SeqCst);
            analyzer.out_tok.fetch_add(usage.out_tok, Ordering::SeqCst);
            spend_budget
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add(crate::pricing::PricingRates::from_env().cost(
                    usage.in_tok,
                    usage.cached_in_tok,
                    usage.out_tok,
                ));
            Ok(())
        })
    };

    let completed = run_bounded_review_tasks_keyed_until(
        pending,
        analyzer.llm_client.max_concurrency(),
        |unit| {
            let analyzer = Arc::clone(&analyzer);
            let progress = on_progress.clone();
            let usage_completion = Arc::clone(&usage_completion);
            let item_completion = Arc::clone(&item_completion);
            async move {
                if let Some(callback) = progress.as_ref() {
                    for (_, job) in &unit {
                        callback(ReviewProgress::Started { label: job.label() });
                    }
                }
                run_review_unit(
                    analyzer,
                    unit,
                    progress.as_ref(),
                    Some(&usage_completion),
                    Some(&item_completion),
                )
                .await
            }
        },
        |unit| {
            for (journal_unit_id, outcome) in unit {
                if !outcome.persisted {
                    item_completion(journal_unit_id, outcome)?;
                }
            }
            Ok(())
        },
        |unit| review_unit_cache_keys(unit),
        {
            let spend_budget = Arc::clone(&spend_budget);
            move || {
                spend_budget
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .can_start()
            }
        },
    )
    .await?;
    if completed.stopped_early {
        let budget = spend_budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        return Err(crate::review_journal::budget_pause(
            budget.spent_usd,
            budget.limit_usd.expect("early stop requires a budget"),
        ));
    }
    outcomes.extend(
        completed
            .completed
            .into_iter()
            .flatten()
            .map(|(_, outcome)| outcome),
    );

    validate_method_coverage(&expected_methods, &outcomes)?;

    outcomes.sort_by_key(|outcome| outcome.index);
    Ok(outcomes
        .into_iter()
        .filter_map(|outcome| outcome.verdict)
        .collect())
}

#[cfg(test)]
#[path = "tests/analyzer_engine_jobs.rs"]
mod tests;
