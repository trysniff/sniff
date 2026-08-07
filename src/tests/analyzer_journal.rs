use super::{
    JournalCompletion, JournalRoleCompletion, JournalStage, JournalStore, scan_id, sha256_text,
    summarize,
};
use crate::report_types::LLMVerdict;
use crate::types::{FileRecord, FindingTier};
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
        method_record: None,
        in_tok: 120,
        out_tok: 12,
        cached_in_tok: 80,
        retry_on_resume: false,
    }
}

fn completion(tier: FindingTier, in_tok: usize, out_tok: usize) -> JournalCompletion {
    let mut completion = clean_completion();
    completion.verdict.as_mut().unwrap().tier = tier;
    completion.in_tok = in_tok;
    completion.out_tok = out_tok;
    completion.cached_in_tok = 0;
    completion
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
fn changed_provider_context_does_not_reuse_events() {
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

#[test]
fn summary_uses_latest_event_per_unit_from_latest_scan() {
    let path = temp_journal_path();
    let first =
        "review_contract=semantic-method-v28\nmodel=first\nendpoint=https://example.invalid";
    let mut old_scan = JournalStore::load_with_expected(&path, "semantic-a", first, 2).unwrap();
    old_scan
        .record(
            "old-unit".to_string(),
            sha256_text("old-source"),
            completion(FindingTier::Slop, 900, 90),
        )
        .unwrap();

    let second =
        "review_contract=semantic-method-v28\nmodel=second\nendpoint=https://example.invalid";
    let mut latest_scan = JournalStore::load_with_expected(&path, "semantic-b", second, 3).unwrap();
    let mut retryable = completion(FindingTier::Unresolved, 10, 1);
    retryable.retry_on_resume = true;
    latest_scan
        .record("unit-a".to_string(), sha256_text("source-a"), retryable)
        .unwrap();
    latest_scan
        .record(
            "unit-a".to_string(),
            sha256_text("source-a"),
            completion(FindingTier::KindaSlop, 20, 2),
        )
        .unwrap();
    latest_scan
        .record(
            "unit-b".to_string(),
            sha256_text("source-b"),
            completion(FindingTier::Slop, 30, 3),
        )
        .unwrap();

    let summary = summarize(&path).unwrap();
    assert_eq!(summary.expected_units, 3);
    assert_eq!(summary.completed_units, 2);
    assert_eq!(summary.retryable_units, 0);
    assert_eq!(summary.slop, 1);
    assert_eq!(summary.kinda_slop, 1);
    assert_eq!(summary.unresolved, 0);
    assert_eq!(summary.input_tokens, 60);
    assert_eq!(summary.output_tokens, 6);
    assert_eq!(summary.model.as_deref(), Some("second"));
    latest_scan.remove().unwrap();
}

#[test]
fn summary_of_missing_journal_is_empty() {
    let summary = summarize(&temp_journal_path()).unwrap();

    assert_eq!(summary, super::JournalSummary::default());
}

#[test]
fn one_scan_summary_combines_role_and_method_usage_without_mixing_coverage() {
    let path = temp_journal_path();
    let context =
        "review_contract=semantic-method-v28\nmodel=test\nendpoint=https://example.invalid";
    let mut roles =
        JournalStore::load_for_scan(&path, "run-a", JournalStage::Role, "role-index", context, 2)
            .unwrap();
    roles
        .record_role(
            "role-a".to_string(),
            sha256_text("role-source"),
            JournalRoleCompletion {
                role: Some("core_library".to_string()),
                in_tok: 10,
                out_tok: 1,
                cached_in_tok: 4,
                retry_on_resume: false,
            },
        )
        .unwrap();
    let mut methods = JournalStore::load_for_scan(
        &path,
        "run-a",
        JournalStage::Method,
        "semantic-index",
        context,
        3,
    )
    .unwrap();
    methods
        .record(
            "method-a".to_string(),
            sha256_text("method-source"),
            completion(FindingTier::Clean, 20, 2),
        )
        .unwrap();

    let summary = summarize(&path).unwrap();
    assert_eq!(summary.expected_units, 3);
    assert_eq!(summary.completed_units, 1);
    assert_eq!(summary.expected_role_units, 2);
    assert_eq!(summary.completed_role_units, 1);
    assert_eq!(summary.input_tokens, 30);
    assert_eq!(summary.output_tokens, 3);
    assert_eq!(summary.cached_input_tokens, 4);
    assert_eq!(methods.spent_usd(), summary.estimated_cost_usd);
    methods.remove().unwrap();
}

#[test]
fn scan_identity_is_order_independent_and_source_sensitive() {
    let file = |path: &str, source: &str| FileRecord {
        file_path: path.to_string(),
        source: source.to_string(),
        language: "python".to_string(),
        methods: vec![],
    };
    let first = vec![file("b.py", "b = 1"), file("a.py", "a = 1")];
    let reordered = vec![file("a.py", "a = 1"), file("b.py", "b = 1")];
    let changed = vec![file("a.py", "a = 2"), file("b.py", "b = 1")];

    assert_eq!(scan_id(&first, "context"), scan_id(&reordered, "context"));
    assert_ne!(scan_id(&first, "context"), scan_id(&changed, "context"));
    assert_ne!(scan_id(&first, "context"), scan_id(&first, "other"));
}

#[test]
fn unchanged_unit_is_available_as_a_cross_scan_content_cache_hit() {
    let path = temp_journal_path();
    let context =
        "review_contract=semantic-method-v28\nmodel=test\nendpoint=https://example.invalid";
    let mut first = JournalStore::load_for_scan(
        &path,
        "run-a",
        JournalStage::Method,
        "semantic-a",
        context,
        1,
    )
    .unwrap();
    first
        .record(
            "stable-unit".to_string(),
            sha256_text("stable-source"),
            completion(FindingTier::Clean, 100, 10),
        )
        .unwrap();

    let second = JournalStore::load_for_scan(
        &path,
        "run-b",
        JournalStage::Method,
        "semantic-b",
        context,
        1,
    )
    .unwrap();
    let cached = second.completed.get("stable-unit").unwrap();
    assert!(!second.is_current_scan(cached));
    second.remove().unwrap();
}

#[test]
fn usage_events_count_cost_without_counting_as_completed_units() {
    let path = temp_journal_path();
    let context =
        "review_contract=semantic-method-v28\nmodel=test\nendpoint=https://example.invalid";
    let mut store = JournalStore::load_for_scan(
        &path,
        "run-a",
        JournalStage::Method,
        "semantic-index",
        context,
        2,
    )
    .unwrap();

    store.record_usage(100, 10, 40).unwrap();

    let summary = summarize(&path).unwrap();
    assert_eq!(summary.completed_units, 0);
    assert_eq!(summary.expected_units, 2);
    assert_eq!(summary.input_tokens, 100);
    assert_eq!(summary.cached_input_tokens, 40);
    assert_eq!(summary.output_tokens, 10);
    assert_eq!(store.completed.len(), 0);
    assert!((store.spent_usd() - summary.estimated_cost_usd).abs() < f64::EPSILON);
    store.remove().unwrap();
}
