use super::{JournalCompletion, JournalStore, sha256_text};
use crate::report_types::LLMVerdict;
use crate::types::FindingTier;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_journal_path() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "sniff-journal-{}-{nonce}-{}.jsonl",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn clean_completion() -> JournalCompletion {
    JournalCompletion {
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
            reason: "The method serves its contract.".to_string(),
            loc: 1,
            start_line: 1,
            end_line: 1,
        }),
        in_tok: 120,
        out_tok: 12,
        cached_in_tok: 80,
        retry_on_resume: false,
    }
}

#[test]
fn journal_appends_one_durable_event_per_completed_unit() {
    let path = temp_journal_path();
    let context = "review_contract=semantic-method-v28\nmodel=test\nendpoint=http://127.0.0.1:9";
    let mut store = JournalStore::load(&path, "semantic-hash", context).unwrap();
    store
        .record(
            "unit-a".to_string(),
            sha256_text("source-a"),
            clean_completion(),
        )
        .unwrap();
    store
        .record(
            "unit-b".to_string(),
            sha256_text("source-b"),
            clean_completion(),
        )
        .unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.lines().count(), 2);
    let loaded = JournalStore::load(&path, "semantic-hash", context).unwrap();
    assert_eq!(loaded.completed.len(), 2);
    assert_eq!(
        loaded.completed["unit-a"].provider,
        "local-openai-compatible"
    );
    assert_eq!(loaded.completed["unit-a"].proof_level, "not_applicable");
    assert!(loaded.completed["unit-a"].estimated_cost_usd > 0.0);
    loaded.remove().unwrap();
}

#[test]
fn journal_ignores_only_a_torn_final_event() {
    let path = temp_journal_path();
    let context =
        "review_contract=semantic-method-v28\nmodel=test\nendpoint=https://example.invalid";
    let mut store = JournalStore::load(&path, "semantic-hash", context).unwrap();
    store
        .record(
            "unit-a".to_string(),
            sha256_text("source-a"),
            clean_completion(),
        )
        .unwrap();
    let mut contents = std::fs::read(&path).unwrap();
    contents.extend_from_slice(b"{\"version\":1");
    std::fs::write(&path, contents).unwrap();

    let mut loaded = JournalStore::load(&path, "semantic-hash", context).unwrap();
    assert_eq!(loaded.completed.len(), 1);
    loaded
        .record(
            "unit-b".to_string(),
            sha256_text("source-b"),
            clean_completion(),
        )
        .unwrap();
    let reloaded = JournalStore::load(&path, "semantic-hash", context).unwrap();
    assert_eq!(reloaded.completed.len(), 2);
    reloaded.remove().unwrap();
}

#[test]
fn changed_semantic_or_provider_context_does_not_reuse_events() {
    let path = temp_journal_path();
    let first =
        "review_contract=semantic-method-v28\nmodel=first\nendpoint=https://example.invalid";
    let mut store = JournalStore::load(&path, "semantic-a", first).unwrap();
    store
        .record(
            "unit-a".to_string(),
            sha256_text("source-a"),
            clean_completion(),
        )
        .unwrap();

    assert!(
        JournalStore::load(&path, "semantic-b", first)
            .unwrap()
            .completed
            .is_empty()
    );
    let second =
        "review_contract=semantic-method-v28\nmodel=second\nendpoint=https://example.invalid";
    let loaded = JournalStore::load(&path, "semantic-a", second).unwrap();
    assert!(loaded.completed.is_empty());
    loaded.remove().unwrap();
}

#[test]
fn retryable_completion_remains_visible_but_is_not_reusable() {
    let path = temp_journal_path();
    let context =
        "review_contract=semantic-method-v28\nmodel=test\nendpoint=https://example.invalid";
    let mut completion = clean_completion();
    completion.retry_on_resume = true;
    let mut store = JournalStore::load(&path, "semantic-hash", context).unwrap();
    store
        .record("unit-a".to_string(), sha256_text("source-a"), completion)
        .unwrap();

    let loaded = JournalStore::load(&path, "semantic-hash", context).unwrap();
    assert!(!loaded.completed["unit-a"].is_reusable());
    loaded.remove().unwrap();
}

#[test]
fn journal_does_not_persist_endpoint_credentials_or_query_secrets() {
    let path = temp_journal_path();
    let context = "review_contract=semantic-method-v28\nmodel=test\nendpoint=https://user:secret@example.com/v1?token=hidden#fragment";
    let mut store = JournalStore::load(&path, "semantic-hash", context).unwrap();
    store
        .record(
            "unit-a".to_string(),
            sha256_text("source-a"),
            clean_completion(),
        )
        .unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("https://example.com/v1"));
    assert!(!contents.contains("secret"));
    assert!(!contents.contains("hidden"));
    store.remove().unwrap();
}
