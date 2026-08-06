use super::super::Analyzer;
use super::super::dossier::MethodDossier;
use super::{
    CheckpointEntry, CheckpointStore, ReviewJob, ReviewOutcome, checkpoint_entry_is_reusable,
    group_pending_reviews, jobs_fingerprint, recoverable_method_review_error,
    run_bounded_review_tasks, run_bounded_review_tasks_keyed, run_review_jobs,
    unresolved_method_verdict,
};
use crate::config::ResolvedConfig;
use crate::llm::LLMClient;
use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, FindingTier, MethodRecord};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

fn method_job(source: &str) -> ReviewJob {
    ReviewJob::Method {
        index: 0,
        method: MethodRecord {
            name: "demo".to_string(),
            file_path: "src/demo.py".to_string(),
            source: source.to_string(),
            loc: 1,
            param_count: 0,
            start_line: 1,
            end_line: 1,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: Vec::new(),
            real_ref_count: 0,
        },
        static_signals: Vec::new(),
        dossier: MethodDossier {
            full_file: String::new().into(),
            context: String::new(),
            project_root: Box::new(PathBuf::new()),
            boundary_requirements: Vec::new(),
            callees: Vec::new(),
            repository_private_unused_candidate: false,
            stale_discard_signature_proof: None,
        },
    }
}

fn file_job(source: &str) -> ReviewJob {
    ReviewJob::File {
        index: 0,
        file: FileRecord {
            file_path: "src/demo.py".to_string(),
            source: source.to_string(),
            language: "python".to_string(),
            methods: vec![],
        },
        static_signals: vec![],
    }
}

fn temp_checkpoint_path() -> std::path::PathBuf {
    static NEXT_CHECKPOINT: AtomicUsize = AtomicUsize::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be available")
        .as_nanos();
    let sequence = NEXT_CHECKPOINT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sniff-checkpoint-{}-{nonce}-{sequence}.json",
        std::process::id()
    ))
}

#[test]
fn checkpoint_round_trip_preserves_completed_verdicts() {
    let path = temp_checkpoint_path();
    let job = method_job("def demo():\n    return 1\n");
    let key = job.checkpoint_key();
    let verdict = LLMVerdict {
        verdict_type: "method_review".to_string(),
        file_path: "src/demo.py".to_string(),
        method_name: Some("demo".to_string()),
        check_type: "method".to_string(),
        smelly: false,
        tier: FindingTier::Clean,
        cohesive: Some(true),
        name_accurate: Some(true),
        evidence: String::new(),
        reason: "clean".to_string(),
        loc: 2,
        start_line: 1,
        end_line: 2,
    };
    let outcome = ReviewOutcome {
        index: 0,
        verdict: Some(verdict),
        in_tok: 12,
        out_tok: 3,
        cached_in_tok: 2,
        retry_on_resume: false,
    };

    let mut store = CheckpointStore::load(&path, 77, "context").unwrap();
    store.record(key.clone(), &outcome).unwrap();
    let loaded = CheckpointStore::load(&path, 77, "context").unwrap();
    let entry = loaded.completed.get(&key).expect("checkpoint entry");
    assert_eq!(entry.in_tok, 12);
    assert_eq!(entry.out_tok, 3);
    assert_eq!(entry.cached_in_tok, 2);
    assert_eq!(entry.verdict.as_ref().unwrap().tier, FindingTier::Clean);
    loaded.remove().unwrap();
}

#[tokio::test]
async fn resumed_checkpoint_restores_cached_input_usage_without_an_api_call() {
    let path = temp_checkpoint_path();
    let job = method_job("def demo():\n    return 1\n");
    let context = "review_contract=test\nmodel=test";
    let fingerprint = jobs_fingerprint(std::slice::from_ref(&job), context);
    let key = job.checkpoint_key();
    let outcome = ReviewOutcome {
        index: 0,
        verdict: Some(LLMVerdict {
            verdict_type: "method".to_string(),
            file_path: "src/demo.py".to_string(),
            method_name: Some("demo".to_string()),
            check_type: "method".to_string(),
            smelly: false,
            tier: FindingTier::Clean,
            cohesive: None,
            name_accurate: None,
            evidence: String::new(),
            reason: "The method directly serves its contract.".to_string(),
            loc: 1,
            start_line: 1,
            end_line: 1,
        }),
        in_tok: 100,
        out_tok: 10,
        cached_in_tok: 75,
        retry_on_resume: false,
    };
    let mut store = CheckpointStore::load(&path, fingerprint, context).unwrap();
    store.record(key, &outcome).unwrap();

    let client = Arc::new(LLMClient::new(ResolvedConfig::default(), None));
    let analyzer = Arc::new(Analyzer {
        llm_client: Arc::clone(&client),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    });
    let verdicts = run_review_jobs(analyzer, vec![job], None, context, Some(&path))
        .await
        .unwrap();

    assert_eq!(verdicts.len(), 1);
    assert_eq!(client.cached_input_tokens(), 75);
    CheckpointStore::load(&path, fingerprint, context)
        .unwrap()
        .remove()
        .unwrap();
}

#[test]
fn validation_failure_unresolved_entries_are_retried_on_resume() {
    let validation_failure = CheckpointEntry {
        key: "validation".to_string(),
        verdict: Some(LLMVerdict {
            verdict_type: "method".to_string(),
            file_path: "src/demo.py".to_string(),
            method_name: Some("demo".to_string()),
            check_type: "method".to_string(),
            smelly: false,
            tier: FindingTier::Unresolved,
            cohesive: None,
            name_accurate: None,
            evidence: String::new(),
            reason: "AI review could not be validated. Missing evidence: malformed batch"
                .to_string(),
            loc: 1,
            start_line: 1,
            end_line: 1,
        }),
        in_tok: 0,
        out_tok: 0,
        cached_in_tok: 0,
        retry_on_resume: None,
    };
    let semantic_unresolved = CheckpointEntry {
        key: "semantic".to_string(),
        verdict: Some(LLMVerdict {
            reason:
                "The method contract could not be established. Missing evidence: external consumers"
                    .to_string(),
            ..validation_failure.verdict.clone().unwrap()
        }),
        ..validation_failure.clone()
    };
    let explicit_retry = CheckpointEntry {
        retry_on_resume: Some(true),
        ..semantic_unresolved.clone()
    };
    let explicit_complete = CheckpointEntry {
        retry_on_resume: Some(false),
        ..validation_failure.clone()
    };

    assert!(!checkpoint_entry_is_reusable(&validation_failure));
    assert!(checkpoint_entry_is_reusable(&semantic_unresolved));
    assert!(!checkpoint_entry_is_reusable(&explicit_retry));
    assert!(checkpoint_entry_is_reusable(&explicit_complete));
}

#[test]
fn changed_scan_fingerprint_does_not_reuse_old_reviews() {
    let path = temp_checkpoint_path();
    let job = method_job("def demo():\n    return 1\n");
    let key = job.checkpoint_key();
    let outcome = ReviewOutcome {
        index: 0,
        verdict: None,
        in_tok: 1,
        out_tok: 1,
        cached_in_tok: 0,
        retry_on_resume: false,
    };

    let mut store = CheckpointStore::load(&path, 77, "context").unwrap();
    store.record(key, &outcome).unwrap();
    let changed = CheckpointStore::load(&path, 78, "changed-context").unwrap();
    assert!(changed.completed.is_empty());
    changed.remove().unwrap();
}

#[test]
fn same_context_reuses_completed_entries_when_job_fingerprint_changes() {
    let path = temp_checkpoint_path();
    let job = method_job("def demo():\n    return 1\n");
    let key = job.checkpoint_key();
    let outcome = ReviewOutcome {
        index: 0,
        verdict: None,
        in_tok: 1,
        out_tok: 1,
        cached_in_tok: 0,
        retry_on_resume: false,
    };

    let mut store = CheckpointStore::load(&path, 77, "context").unwrap();
    store.record(key.clone(), &outcome).unwrap();
    let loaded = CheckpointStore::load(&path, 78, "context").unwrap();
    assert!(loaded.completed.contains_key(&key));
    loaded.remove().unwrap();
}

#[test]
fn binary_version_change_reuses_the_same_semantic_checkpoint() {
    let path = temp_checkpoint_path();
    let job = method_job("def demo():\n    return 1\n");
    let key = job.checkpoint_key();
    let outcome = ReviewOutcome {
        index: 0,
        verdict: None,
        in_tok: 1,
        out_tok: 1,
        cached_in_tok: 0,
        retry_on_resume: false,
    };
    let old = "sniff_version=0.1.5\nreview_contract=semantic-method-v28\nmodel=test";
    let current = "review_contract=semantic-method-v28\nmodel=test";

    let mut store = CheckpointStore::load(&path, 77, old).unwrap();
    store.record(key.clone(), &outcome).unwrap();
    let loaded = CheckpointStore::load(&path, 78, current).unwrap();

    assert!(!loaded.migrated_from_previous_contract);
    assert!(loaded.completed.contains_key(&key));
    loaded.remove().unwrap();
}

#[test]
fn v28_checkpoint_migration_preserves_files_and_drops_v27_method_reviews() {
    let path = temp_checkpoint_path();
    let method = method_job("def ordinary():\n    return 1\n");
    let file = file_job("def ordinary():\n    return 1\n");
    let method_key = method.checkpoint_key();
    let file_key = file.checkpoint_key();
    let outcome = ReviewOutcome {
        index: 0,
        verdict: None,
        in_tok: 1,
        out_tok: 1,
        cached_in_tok: 0,
        retry_on_resume: false,
    };
    let v27 = "sniff_version=0.1.5\nreview_contract=semantic-method-v27\nmodel=test";
    let v28 = "sniff_version=0.1.5\nreview_contract=semantic-method-v28\nmodel=test";

    let mut store = CheckpointStore::load(&path, 77, v27).unwrap();
    store.record(method_key.clone(), &outcome).unwrap();
    store.record(file_key.clone(), &outcome).unwrap();

    let mut migrated = CheckpointStore::load(&path, 78, v28).unwrap();
    assert!(migrated.migrated_from_previous_contract);
    migrated.migrate_previous_contract(&[method, file]).unwrap();
    assert!(!migrated.completed.contains_key(&method_key));
    assert!(migrated.completed.contains_key(&file_key));

    let reloaded = CheckpointStore::load(&path, 78, v28).unwrap();
    assert!(!reloaded.migrated_from_previous_contract);
    assert!(!reloaded.completed.contains_key(&method_key));
    assert!(reloaded.completed.contains_key(&file_key));
    reloaded.remove().unwrap();
}

#[test]
fn checkpoint_fingerprint_is_independent_of_job_order() {
    let first = vec![
        method_job("def first():\n    return 1\n"),
        method_job("def second():\n    return 2\n"),
    ];
    let second = vec![
        method_job("def second():\n    return 2\n"),
        method_job("def first():\n    return 1\n"),
    ];

    assert_eq!(
        jobs_fingerprint(&first, "context"),
        jobs_fingerprint(&second, "context")
    );
}

#[test]
fn pending_small_file_chunks_share_available_batch_capacity() {
    let mut other_file = method_job("def other():\n    return 2\n");
    if let ReviewJob::Method { method, .. } = &mut other_file {
        method.file_path = "src/other.py".to_string();
    }
    let pending = vec![
        ("a".to_string(), method_job("def first():\n    return 1\n")),
        ("b".to_string(), method_job("def second():\n    return 2\n")),
        ("c".to_string(), other_file),
    ];

    let groups = group_pending_reviews(pending, 4, usize::MAX);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].len(), 3);
}

#[test]
fn pending_method_batches_shrink_to_fit_the_prompt_limit() {
    let pending = vec![
        ("a".to_string(), method_job("def first():\n    return 1\n")),
        ("b".to_string(), method_job("def second():\n    return 2\n")),
    ];

    let groups = group_pending_reviews(pending, 8, 45_000);

    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].len(), 1);
    assert_eq!(groups[1].len(), 1);
}

#[test]
fn method_batch_size_defaults_and_clamps_to_the_supported_range() {
    assert_eq!(super::parse_method_batch_size(None), 8);
    assert_eq!(super::parse_method_batch_size(Some("invalid")), 8);
    assert_eq!(super::parse_method_batch_size(Some("0")), 1);
    assert_eq!(super::parse_method_batch_size(Some("6")), 6);
    assert_eq!(super::parse_method_batch_size(Some("99")), 8);
}

#[test]
fn checkpoint_key_ignores_rendered_dossier_order() {
    let mut first = method_job("def demo():\n    return 1\n");
    let mut second = method_job("def demo():\n    return 1\n");
    if let ReviewJob::Method { dossier, .. } = &mut first {
        dossier.context = "callers:\n- first\n- second".to_string();
    }
    if let ReviewJob::Method { dossier, .. } = &mut second {
        dossier.context = "callers:\n- second\n- first".to_string();
    }

    assert_eq!(first.checkpoint_key(), second.checkpoint_key());
}

#[test]
fn checkpoint_key_canonicalizes_unordered_method_context() {
    let mut first = method_job("def demo():\n    return 1\n");
    let mut second = method_job("def demo():\n    return 1\n");
    if let ReviewJob::Method {
        method,
        static_signals,
        dossier,
        ..
    } = &mut first
    {
        method.references = vec![
            crate::types::Reference {
                file_path: "src/z.py".to_string(),
                line: 9,
                snippet: "z".to_string(),
            },
            crate::types::Reference {
                file_path: "src/a.py".to_string(),
                line: 2,
                snippet: "a".to_string(),
            },
        ];
        *static_signals = vec!["z signal".to_string(), "a signal".to_string()];
        dossier.boundary_requirements = vec!["z boundary".to_string(), "a boundary".to_string()];
    }
    if let ReviewJob::Method {
        method,
        static_signals,
        dossier,
        ..
    } = &mut second
    {
        method.references = vec![
            crate::types::Reference {
                file_path: "src/a.py".to_string(),
                line: 2,
                snippet: "a".to_string(),
            },
            crate::types::Reference {
                file_path: "src/z.py".to_string(),
                line: 9,
                snippet: "z".to_string(),
            },
        ];
        *static_signals = vec!["a signal".to_string(), "z signal".to_string()];
        dossier.boundary_requirements = vec!["a boundary".to_string(), "z boundary".to_string()];
    }

    assert_eq!(first.checkpoint_key(), second.checkpoint_key());
}

#[test]
fn legacy_indexed_checkpoint_keys_are_migrated() {
    let path = temp_checkpoint_path();
    let key = method_job("def demo():\n    return 1\n").checkpoint_key();
    let contents = serde_json::json!({
        "version": 1,
        "fingerprint": 76,
        "completed": [{
            "key": format!("0:{key}"),
            "verdict": null,
            "in_tok": 1,
            "out_tok": 1
        }]
    });
    std::fs::write(&path, serde_json::to_string(&contents).unwrap()).unwrap();

    let loaded = CheckpointStore::load(&path, 77, "context").unwrap();
    assert!(loaded.completed.contains_key(&key));
    loaded.remove().unwrap();
}

#[test]
fn invalid_semantic_review_becomes_explicit_unresolved() {
    let method = MethodRecord {
        name: "demo".to_string(),
        file_path: "src/demo.py".to_string(),
        source: "def demo():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let error = "method semantic review remained invalid after repair: wrong field types";

    assert!(recoverable_method_review_error(error));
    let verdict = unresolved_method_verdict(&method, error);
    assert_eq!(verdict.tier, FindingTier::Unresolved);
    assert!(!verdict.smelly);
    assert!(verdict.reason.contains("Missing evidence"));
}

#[test]
fn exhausted_schema_validation_becomes_unresolved() {
    assert!(recoverable_method_review_error(
        "LLM maximum attempt count (128) reached after 128 attempts; last error: wrong field types: simplification"
    ));
    assert!(recoverable_method_review_error(
        "LLM retry budget exhausted after 1800s; last error: missing fields: evidence"
    ));
    assert!(recoverable_method_review_error(
        "LLM response format remained invalid after 3 repair attempts; last error: missing fields: quote, quote"
    ));
}

#[test]
fn exhausted_transport_failure_remains_fatal() {
    assert!(!recoverable_method_review_error(
        "LLM maximum attempt count (128) reached after 128 attempts; last error: error sending request"
    ));
}

#[tokio::test]
async fn bounded_review_tasks_overlap_without_exceeding_the_limit() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let pending = (0usize..8).collect::<VecDeque<_>>();

    let completed = run_bounded_review_tasks(
        pending,
        4,
        |index| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            async move {
                let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now_active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(index)
            }
        },
        |_| Ok(()),
    )
    .await
    .unwrap();

    assert_eq!(completed.len(), 8);
    assert_eq!(peak.load(Ordering::SeqCst), 4);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn keyed_review_tasks_serialize_shared_files_but_overlap_distinct_files() {
    let active_files = Arc::new(Mutex::new(HashSet::new()));
    let active_count = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let pending = VecDeque::from([
        ("src/a.rs".to_string(), 0usize),
        ("src/a.rs".to_string(), 1usize),
        ("src/b.rs".to_string(), 2usize),
        ("src/b.rs".to_string(), 3usize),
    ]);

    let completed = run_bounded_review_tasks_keyed(
        pending,
        4,
        |(file, index)| {
            let active_files = Arc::clone(&active_files);
            let active_count = Arc::clone(&active_count);
            let peak = Arc::clone(&peak);
            async move {
                if !active_files.lock().unwrap().insert(file.clone()) {
                    return Err(format!("two review units raced for {file}"));
                }
                let now_active = active_count.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now_active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                active_count.fetch_sub(1, Ordering::SeqCst);
                active_files.lock().unwrap().remove(&file);
                Ok(index)
            }
        },
        |_| Ok(()),
        |(file, _)| vec![file.clone()],
    )
    .await
    .unwrap();

    assert_eq!(completed.len(), 4);
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert!(active_files.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bounded_review_tasks_checkpoint_completed_work_before_a_failure() {
    let path = temp_checkpoint_path();
    let mut checkpoint = CheckpointStore::load(&path, 77, "context").unwrap();
    let pending = VecDeque::from([0usize, 1, 2]);

    let error = run_bounded_review_tasks(
        pending,
        2,
        |index| async move {
            match index {
                0 => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    Ok(index)
                }
                1 => {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Err("provider failed".to_string())
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(index)
                }
            }
        },
        |index| {
            let outcome = ReviewOutcome {
                index: *index,
                verdict: None,
                in_tok: 1,
                out_tok: 1,
                cached_in_tok: 0,
                retry_on_resume: false,
            };
            checkpoint.record(format!("method-{index}"), &outcome)
        },
    )
    .await
    .unwrap_err();

    assert_eq!(error, "provider failed");
    let loaded = CheckpointStore::load(&path, 77, "context").unwrap();
    assert!(loaded.completed.contains_key("method-0"));
    assert!(!loaded.completed.contains_key("method-1"));
    assert!(!loaded.completed.contains_key("method-2"));
    loaded.remove().unwrap();
}
