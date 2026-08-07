use super::*;

fn role_response(role: &str) -> String {
    serde_json::json!({
        "choices": [{
            "message": {
                "content": serde_json::json!({
                    "role": role,
                    "reason": "The file provides repository library behavior."
                })
                .to_string()
            }
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 1}
    })
    .to_string()
}

fn ambiguous_role_files() -> Vec<FileRecord> {
    vec![
        FileRecord {
            file_path: "reporting_one.rs".to_string(),
            source: "pub fn first_role_fixture() {}\n".to_string(),
            language: "rust".to_string(),
            methods: vec![],
        },
        FileRecord {
            file_path: "reporting_two.rs".to_string(),
            source: "pub fn second_role_fixture() {}\n".to_string(),
            language: "rust".to_string(),
            methods: vec![],
        },
    ]
}

fn role_journal_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sniff-role-{label}-journal-test-{}-{}.jsonl",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

async fn assert_role_transport_failure_preserves_completed_work(
    failure: ScriptedRoleAction,
    expected_error: &str,
) {
    let _role_lock = ROLE_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    clear_file_role_cache();
    let files = ambiguous_role_files();
    let (endpoint, hits) = spawn_scripted_role_server(vec![
        ScriptedRoleAction::Json(role_response("library")),
        failure,
        ScriptedRoleAction::Json(role_response("adapter_integration")),
    ]);
    let client = Arc::new(
        LLMClient::new(cfg(&endpoint), Some("test-key".to_string())).with_max_attempt_count(1),
    );
    let journal_path = role_journal_path("transport");

    let error = resolve_file_roles_with_journal(
        &files,
        Arc::clone(&client),
        Some(&journal_path),
        Some("run-a"),
        None,
    )
    .await
    .expect_err("the second role request should fail");
    assert!(error.contains("Role resolution failed"), "{error}");
    assert!(error.contains(expected_error), "{error}");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let interrupted = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(interrupted.completed_role_units, 1);
    assert_eq!(interrupted.retryable_role_units, 1);

    clear_file_role_cache();
    resolve_file_roles_with_journal(&files, client, Some(&journal_path), Some("run-b"), None)
        .await
        .expect("resume should reuse the first role and retry only the second");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    let resumed = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(resumed.expected_role_units, 2);
    assert_eq!(resumed.completed_role_units, 2);
    assert_eq!(resumed.retryable_role_units, 0);

    std::fs::remove_file(journal_path).unwrap();
}

#[tokio::test]
async fn ambiguous_role_uses_llm_and_is_cached() {
    let _role_lock = ROLE_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    clear_file_role_cache();
    let body = r#"{"choices":[{"message":{"content":"{\"role\":\"adapter_integration\",\"reason\":\"framework glue\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));
    let file = FileRecord {
        file_path: "reporting.rs".to_string(),
        source: "use reqwest::Client;\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };

    let (in_tok, out_tok) = resolve_file_roles(&[file], Arc::clone(&client))
        .await
        .unwrap();
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        classify_file_role("reporting.rs"),
        FileRole::AdapterIntegration
    );
}

#[tokio::test]
async fn ambiguous_role_failure_aborts_resolution() {
    let _role_lock = ROLE_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    clear_file_role_cache();
    let (endpoint, hits) = spawn_http_status_server(402, r#"{"error":"insufficient balance"}"#);
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));
    let file = FileRecord {
        file_path: "reporting.rs".to_string(),
        source: "use reqwest::Client;\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let journal_path = std::env::temp_dir().join(format!(
        "sniff-role-failure-journal-test-{}.jsonl",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let err = resolve_file_roles_with_journal(
        &[file],
        Arc::clone(&client),
        Some(&journal_path),
        None,
        None,
    )
    .await
    .expect_err("expected role resolution to fail hard");
    assert!(err.contains("Role resolution failed"));
    assert!(err.contains("HTTP 402"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let summary = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(summary.completed_role_units, 0);
    assert_eq!(summary.retryable_role_units, 1);
    std::fs::remove_file(journal_path).unwrap();
}

#[tokio::test]
async fn role_http_402_preserves_completed_work_for_resume() {
    assert_role_transport_failure_preserves_completed_work(
        ScriptedRoleAction::Status(402, r#"{"error":"insufficient balance"}"#.to_string()),
        "HTTP 402",
    )
    .await;
}

#[tokio::test]
async fn role_network_loss_preserves_completed_work_for_resume() {
    assert_role_transport_failure_preserves_completed_work(
        ScriptedRoleAction::Disconnect,
        "error sending request",
    )
    .await;
}

#[tokio::test]
async fn cancelled_role_stage_resumes_without_repeating_completed_work() {
    let _role_lock = ROLE_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    clear_file_role_cache();
    let files = ambiguous_role_files();
    let (endpoint, hits) = spawn_scripted_role_server(vec![
        ScriptedRoleAction::Json(role_response("library")),
        ScriptedRoleAction::Stall,
        ScriptedRoleAction::Json(role_response("adapter_integration")),
    ]);
    let client = Arc::new(
        LLMClient::new(cfg(&endpoint), Some("test-key".to_string())).with_max_attempt_count(1),
    );
    let journal_path = role_journal_path("cancelled");
    let task_files = files.clone();
    let task_client = Arc::clone(&client);
    let task_journal = journal_path.clone();
    let task = tokio::spawn(async move {
        resolve_file_roles_with_journal(
            &task_files,
            task_client,
            Some(&task_journal),
            Some("run-a"),
            None,
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        while hits.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the second role request should start");
    task.abort();
    assert!(
        task.await
            .expect_err("role task should be cancelled")
            .is_cancelled()
    );

    let interrupted = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(interrupted.completed_role_units, 1);
    assert_eq!(interrupted.retryable_role_units, 0);

    clear_file_role_cache();
    resolve_file_roles_with_journal(&files, client, Some(&journal_path), Some("run-b"), None)
        .await
        .expect("resume should reuse the completed role and retry the interrupted role");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    let resumed = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(resumed.completed_role_units, 2);

    std::fs::remove_file(journal_path).unwrap();
}

#[tokio::test]
async fn role_journal_reuses_completed_classification_without_an_api_call() {
    let _role_lock = ROLE_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    clear_file_role_cache();
    let body = r#"{"choices":[{"message":{"content":"{\"role\":\"adapter_integration\",\"reason\":\"framework glue\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));
    let file = FileRecord {
        file_path: "reporting.rs".to_string(),
        source: "use reqwest::Client;\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let journal_path = std::env::temp_dir().join(format!(
        "sniff-role-journal-test-{}.jsonl",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    resolve_file_roles_with_journal(
        std::slice::from_ref(&file),
        Arc::clone(&client),
        Some(&journal_path),
        Some("run-a"),
        None,
    )
    .await
    .unwrap();
    assert!(journal_path.exists());
    clear_file_role_cache();
    resolve_file_roles_with_journal(&[file], client, Some(&journal_path), Some("run-b"), None)
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let summary = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(summary.expected_role_units, 1);
    assert_eq!(summary.completed_role_units, 1);
    assert_eq!(summary.retryable_role_units, 0);
    assert_eq!(summary.input_tokens, 0);
    assert_eq!(summary.output_tokens, 0);

    std::fs::remove_file(&journal_path).unwrap();
}

#[tokio::test]
async fn zero_budget_pauses_before_role_classification_and_leaves_a_manifest() {
    let _role_lock = ROLE_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    clear_file_role_cache();
    let body = r#"{"choices":[{"message":{"content":"{\"role\":\"adapter_integration\",\"reason\":\"framework glue\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));
    let file = FileRecord {
        file_path: "reporting.rs".to_string(),
        source: "use reqwest::Client;\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let journal_path = std::env::temp_dir().join(format!(
        "sniff-role-budget-journal-test-{}.jsonl",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let error = resolve_file_roles_with_journal(
        &[file],
        client,
        Some(&journal_path),
        Some("budget-run"),
        Some(0.0),
    )
    .await
    .expect_err("zero budget should pause before role review admission");

    assert!(crate::review_journal::is_budget_pause(&error));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let summary = crate::review_journal::summarize(&journal_path).unwrap();
    assert_eq!(summary.expected_role_units, 1);
    assert_eq!(summary.completed_role_units, 0);
    std::fs::remove_file(journal_path).unwrap();
}

#[test]
fn nested_src_files_default_to_library() {
    assert_eq!(
        classify_file_role("src/bumpkin/release_job.py"),
        FileRole::Library
    );
    assert_eq!(
        classify_file_role("src/bumpkin/orchestrator/pipeline.py"),
        FileRole::Library
    );
    assert_eq!(
        classify_file_role("ui/background/core/runtime-wireup.ts"),
        FileRole::Library
    );
}

#[test]
fn pure_reexport_modules_are_detected() {
    let file = FileRecord {
            file_path: "src/prompt_pack.py".to_string(),
            source: "from bumpkin.prompt_pack import (\n    PromptPack,\n    build_messages,\n)\n\n__all__ = [\n    \"PromptPack\",\n    \"build_messages\",\n]\n"
                .to_string(),
            language: "python".to_string(),
            methods: vec![],
        };

    assert!(is_pure_reexport_module(&file));
}

#[test]
fn pure_reexport_modules_with_alias_assignments_are_detected() {
    let file = FileRecord {
            file_path: "src/bumpkin/analysis/finding_python_surface.py".to_string(),
            source: "from bumpkin.analysis import finding_python_all_contract as _all_contract\nfrom bumpkin.analysis import finding_python_public_names as _public_names\n\nextract_python_all_contract = _all_contract.extract_python_all_contract\nextract_python_public_names = _public_names.extract_python_public_names\n".to_string(),
            language: "python".to_string(),
            methods: vec![],
        };

    assert!(is_pure_reexport_module(&file));
}

#[test]
fn pure_reexport_modules_with_star_imports_are_detected() {
    let file = FileRecord {
        file_path: "src/bumpkin/orchestrator/explanation_facts.py".to_string(),
        source: "from bumpkin.analysis.explanation_facts import *  # noqa: F403\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    assert!(is_pure_reexport_module(&file));
}

#[test]
fn pure_reexport_modules_with_ts_export_stars_are_detected() {
    let file = FileRecord {
        file_path: "src/reexports.ts".to_string(),
        source: "export * from './impl';\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![],
    };

    assert!(is_pure_reexport_module(&file));
}

#[test]
fn pure_reexport_modules_with_rust_pub_use_are_detected() {
    let file = FileRecord {
        file_path: "src/reexports.rs".to_string(),
        source: "pub use crate::analysis::explanation_facts::*;\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };

    assert!(is_pure_reexport_module(&file));
}

#[test]
fn rust_module_barrels_are_detected() {
    let file = FileRecord {
        file_path: "src/lib.rs".to_string(),
        source: "pub mod analyzer;\npub mod callgraph;\npub mod cli;\npub mod config;\n"
            .to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };

    assert!(is_module_barrel_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn react_main_entrypoints_classify_as_entrypoints() {
    assert_eq!(
        classify_file_role("C:\\Users\\User\\Brandset\\Brandset\\ui\\src\\main.tsx"),
        FileRole::Entrypoint
    );
    assert_eq!(
        classify_file_role("C:\\Users\\User\\Brandset\\Brandset\\ui\\src\\main.jsx"),
        FileRole::Entrypoint
    );
}

#[test]
fn support_plumbing_modules_are_detected_from_absolute_paths() {
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\analysis\diff_text.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\analysis\finding_diff.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\release\candidate.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\eval\fixtures.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\analyzer_support.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\analyzer_verdicts_rules.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\analyzer_verdicts_rules_analysis.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\file_verdicts_builder.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\parser_impl.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\parser_impl\python_extractor.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\parser_impl\kotlin_extractor.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\signal_layers_similarity_roles.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\llm_json.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\analyzer.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\scorer_name_utils.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\symbol_graph_resolver.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Sniff\src\walker.rs"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Brandset\Brandset\ui\src\lib\logo-drag.ts"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Brandset\Brandset\ui\src\lib\smart-filler\dom-utils.ts"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Brandset\Brandset\ui\src\lib\smart-filler\heuristics.ts"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Brandset\Brandset\ui\src\session\session.types.ts"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\apps\android\host\reminder-host-jvm\src\main\kotlin\com\onpill\androidhost\HostLocalization.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\apps\android\host\reminder-host-jvm\src\main\kotlin\com\onpill\androidhost\HostServiceOpsSupport.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\apps\android\src\commonMain\kotlin\com\pillit\apps\android\services\AndroidAppStoreHostPortAdapters.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\apps\android\host\app\src\main\java\com\pillit\androidhost\HostSyncRuntime.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\contract\src\commonMain\kotlin\com\pillit\shared\uicontract\PreferencesContract.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\core\src\commonMain\kotlin\com\pillit\shared\core\VaultSyncHttpProtocol.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\core\src\commonMain\kotlin\com\pillit\shared\core\appstore\PillitAppStoreModel.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\core\src\commonMain\kotlin\com\pillit\shared\core\appstore\PillitAppStoreShadowRuntimeHandlers.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\core\src\commonMain\kotlin\com\pillit\shared\core\ReminderPresentationStatePlanner.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\core\src\commonMain\kotlin\com\pillit\shared\core\appstore\PillitMedicationDetailsCabinetRows.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\Pillit\Pillit\shared\contract\src\commonMain\kotlin\com\pillit\shared\uicontract\design\PillitDesignTokens.kt"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\explanation_facts.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\base_classification.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\analysis_stage.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\explainability.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\explanation_polish.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\court_output.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\court_payload.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\court_setup.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\adjudication.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\orchestrator\scope.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\config.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\planner.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\versioning\tags.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\prompt_pack.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\licensing\policy.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\io\tokens.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\policies\guards.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\guards.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\events.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\server.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\runtime.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\persistence_postgres_publish_decision_ops.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\persistence_serialization.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\integrations\github\persistence_ephemeral.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\providers\llm_transport.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\providers\llm_payloads.py"
    ));
    assert!(is_support_plumbing_module(
        r"C:\Users\User\bumpkin\src\bumpkin\retry.py"
    ));
}

#[test]
fn common_test_paths_are_treated_as_tests() {
    assert!(is_test_path(
        "shared/core/src/commonTest/kotlin/com/pillit/shared/core/PlatformServicesIntegrationServiceTest.kt",
        "PlatformServicesIntegrationServiceTest.kt"
    ));
    assert!(is_test_path(
        "apps/ios/src/commonTest/kotlin/com/pillit/apps/ios/services/IosPlatformServiceAdaptersTest.kt",
        "IosPlatformServiceAdaptersTest.kt"
    ));
}

#[test]
fn config_validation_modules_are_detected() {
    let file = FileRecord {
        file_path: "src/bumpkin/config.py".to_string(),
        source: "from dataclasses import dataclass\n\n@dataclass\nclass BumpkinConfig:\n    policy_mode: str\n\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_ensure_bool".to_string(),
                file_path: "src/bumpkin/config.py".to_string(),
                source: "def _ensure_bool(value, field_name):\n    return bool(value)\n".to_string(),
                loc: 2,
                param_count: 2,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_ensure_policy_mode".to_string(),
                file_path: "src/bumpkin/config.py".to_string(),
                source: "def _ensure_policy_mode(value):\n    return value\n".to_string(),
                loc: 2,
                param_count: 1,
                start_line: 3,
                end_line: 4,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "load_bumpkin_config".to_string(),
                file_path: "src/bumpkin/config.py".to_string(),
                source: "def load_bumpkin_config(path=None):\n    return None\n".to_string(),
                loc: 2,
                param_count: 1,
                start_line: 5,
                end_line: 6,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_config_validation_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn detector_support_modules_are_detected_from_absolute_paths() {
    assert!(is_detector_support_module(
        r"C:\Users\User\Sniff\src\analyzer_file_verdicts.rs"
    ));
    assert!(is_detector_support_module(
        r"C:\Users\User\Sniff\src\roles_surface_presentation.rs"
    ));
    assert!(is_detector_support_module(
        r"C:\Users\User\Sniff\src\reporter_console.rs"
    ));
    assert!(is_detector_support_module(
        r"C:\Users\User\Sniff\src\scorer_file.rs"
    ));
    assert!(is_detector_support_module(
        r"C:\Users\User\Sniff\src\analyzer_verdicts_rules.rs"
    ));
    assert!(is_detector_support_module(
        r"C:\Users\User\Sniff\src\file_verdicts_builder.rs"
    ));
}

#[test]
fn protocol_surface_modules_are_detected() {
    let file = FileRecord {
            file_path: "src/bumpkin/integrations/github/persistence_protocols.py".to_string(),
            source: "from __future__ import annotations\n\nfrom datetime import datetime\nfrom typing import Any, Protocol\n\nclass ApprovalPersistenceStore(Protocol):\n    def close(self) -> None: ...\n    def delete_approvals(self, *, repository: str, pull_request_number: int) -> int: ...\n".to_string(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "close".to_string(),
                    file_path: "src/bumpkin/integrations/github/persistence_protocols.py".to_string(),
                    source: "def close(self) -> None: ...".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 8,
                    end_line: 8,
                    is_exported: true,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "delete_approvals".to_string(),
                    file_path: "src/bumpkin/integrations/github/persistence_protocols.py".to_string(),
                    source: "def delete_approvals(self, *, repository: str, pull_request_number: int) -> int: ...".to_string(),
                    loc: 1,
                    param_count: 2,
                    start_line: 9,
                    end_line: 9,
                    is_exported: true,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };

    assert!(is_protocol_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn small_kotlin_compose_surface_with_many_small_methods_is_detected() {
    let mut methods = Vec::new();
    let mut source = String::from("package com.onpill.shared.uicompose.components\n\n");
    for idx in 0..12 {
        source.push_str(&format!(
            "@Composable\npublic fun component{idx:02}() {{}}\n",
            idx = idx
        ));
        methods.push(MethodRecord {
            name: format!("component{idx:02}", idx = idx),
            file_path:
                "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                    .to_string(),
            source: format!("@Composable\npublic fun component{idx:02}() {{}}\n", idx = idx),
            loc: 2,
            param_count: 0,
            start_line: idx * 2 + 1,
            end_line: idx * 2 + 2,
            is_exported: true,
            language: "kotlin".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        });
    }
    source.push_str("public object OnPillSemanticColors { public val warning: Int = 0 }\n");
    let file = FileRecord {
        file_path:
            "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                .to_string(),
        source,
        language: "kotlin".to_string(),
        methods,
    };

    assert!(is_presentation_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn longer_kotlin_compose_screen_surfaces_are_still_detected() {
    let mut methods = Vec::new();
    let mut source = String::from("package com.onpill.shared.uicompose.screens\n\n@Composable\n");
    for idx in 0..9 {
        source.push_str(&format!(
            "public fun screenHelper{idx:02}() {{}}\n",
            idx = idx
        ));
        methods.push(MethodRecord {
            name: format!("screenHelper{idx:02}", idx = idx),
            file_path:
                "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                    .to_string(),
            source: format!("public fun screenHelper{idx:02}() {{}}\n", idx = idx),
            loc: if idx == 0 { 97 } else { 4 },
            param_count: 0,
            start_line: idx * 3 + 1,
            end_line: idx * 3 + 3,
            is_exported: idx == 0,
            language: "kotlin".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        });
    }
    let file = FileRecord {
        file_path:
            "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                .to_string(),
        source,
        language: "kotlin".to_string(),
        methods,
    };

    assert!(is_presentation_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn parsed_protocol_stub_methods_are_detected() {
    let method = MethodRecord {
        name: "handle_github_webhook".to_string(),
        file_path: "src/bumpkin/integrations/github/server.py".to_string(),
        source: "def handle_github_webhook(self, *, headers, raw_body): ...".to_string(),
        loc: 1,
        param_count: 2,
        start_line: 1,
        end_line: 1,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    assert!(is_protocol_stub_method(&method));
}
