use super::*;

#[tokio::test]
async fn method_review_keeps_llm_verdict() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"return 1\",\"reason\":\"small helper\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "sample".to_string(),
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected method verdict");
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn speculative_method_reasons_are_cleared() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return Err(err.to_string());\",\"reason\":\"format string uses placeholder and indicates a previous version copy-paste\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "probe".to_string(),
        file_path: "src/llm_impl.rs".to_string(),
        source: "pub async fn probe(&self) -> Result<(), String> {\n    return Err(err.to_string());\n}\n"
            .to_string(),
        loc: 3,
        param_count: 1,
        start_line: 1,
        end_line: 3,
        is_exported: false,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected method verdict");
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn empty_method_reasons_are_cleared() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return 1\",\"reason\":\"\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "sample".to_string(),
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected method verdict");
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn thin_wrapper_methods_are_reviewed_instead_of_skipped() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "render_label".to_string(),
        file_path: "src/labels.py".to_string(),
        source: "from labels_impl import render_label as _render_label_impl\n\n\
def render_label(value):\n    return _render_label_impl(value)\n"
            .to_string(),
        loc: 4,
        param_count: 1,
        start_line: 1,
        end_line: 4,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected method verdict");
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(hits.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn file_review_keeps_llm_verdict() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"def sample()\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    let (verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn empty_file_reasons_are_cleared() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"def sample():\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    let (verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn llm_error_fails_scan_without_starting_later_review_jobs() {
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        env::set_var("SNIFF_LLM_MAX_CONCURRENCY", "1");
    }

    let (endpoint, hits) = spawn_http_status_sequence_server(
        vec![500, 200],
        r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"def beta():\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#,
    );
    let client = Arc::new(
        LLMClient::new(cfg(&endpoint), Some("test-key".to_string())).with_max_attempt_count(1),
    );

    let files = vec![
        FileRecord {
            file_path: "src/alpha.py".to_string(),
            source: "def alpha():\n    return 1\n".to_string(),
            language: "python".to_string(),
            methods: vec![],
        },
        FileRecord {
            file_path: "src/beta.py".to_string(),
            source: "def beta():\n    return 2\n".to_string(),
            language: "python".to_string(),
            methods: vec![],
        },
    ];

    let result = analyze_with_client(&files, &[], client, true, None).await;

    unsafe {
        env::remove_var("SNIFF_LLM_MAX_CONCURRENCY");
    }
    drop(lock);

    let err = result.expect_err("a partial AI scan must not produce a successful report");
    assert!(err.contains("LLM review failed"));
    assert!(err.contains("src/alpha.py"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn llm_probe_surfaces_provider_failure() {
    let (endpoint, hits) = spawn_http_status_server(402, r#"{"error":"insufficient balance"}"#);
    let client = LLMClient::new(cfg(&endpoint), Some("test-key".to_string()));

    let err = client.probe().await.expect_err("expected probe failure");
    assert!(err.contains("LLM preflight failed"));
    assert!(err.contains("LLM provider balance is insufficient"));
    assert!(err.contains("HTTP 402"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_api_key_fails_when_reviews_are_required() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "sample".to_string(),
            file_path: "sample.py".to_string(),
            source: "def sample():\n    return 1\n".to_string(),
            loc: 2,
            param_count: 0,
            start_line: 1,
            end_line: 2,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    unsafe {
        env::remove_var("SNIFF_API_KEY");
    }

    let err = analyze(&[file], &[], ResolvedConfig::default(), false, None)
        .await
        .expect_err("expected missing api key to fail when reviews are needed");
    assert!(err.contains("AI config is missing"));
}

#[tokio::test]
async fn file_review_includes_method_inventory() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"def process_webhook()\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits, captured) = spawn_openai_style_server_with_capture(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/services/webhook_service.py".to_string(),
        source: "def process_webhook():\n    return None\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "process_webhook".to_string(),
            file_path: "src/services/webhook_service.py".to_string(),
            source: "def process_webhook():\n    return None\n".to_string(),
            loc: 126,
            param_count: 3,
            start_line: 1,
            end_line: 2,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let (_verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let request = captured.lock().unwrap().clone();
    assert!(request.contains("Method inventory:"));
    assert!(request.contains("- process_webhook (126 LOC, 3 params)"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn method_review_includes_file_path() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits, captured) = spawn_openai_style_server_with_capture(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "process_webhook".to_string(),
        file_path: "src/services/webhook_service.py".to_string(),
        source: "def process_webhook():\n    return None\n".to_string(),
        loc: 126,
        param_count: 3,
        start_line: 1,
        end_line: 2,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (_verdict, _, _) = analyzer
        .analyze_method_review_with_context(
            &method,
            &[],
            MethodReviewContext {
                file_context:
                    "class WebhookService:\n    def other_handler(self):\n        return None",
                project_root: None,
                callee_context: &[],
                boundary_requirements: &[],
                repository_private_unused_candidate: false,
                stale_discard_signature_proof: None,
            },
            None,
        )
        .await
        .unwrap();
    let request = captured.lock().unwrap().clone();
    assert!(request.contains("File path:"));
    assert!(request.contains("src/services/webhook_service.py"));
    assert!(request.contains("Surrounding file context:"));
    assert!(request.contains("class WebhookService:"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn method_review_sends_the_complete_method_source() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, _hits, captured) = spawn_openai_style_server_with_capture(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method_tail = "METHOD_SOURCE_TAIL_SENTINEL";
    let source = format!(
        "def long_method(value):\n{}\n    return {method_tail}\n",
        "    value = value\n".repeat(260)
    );
    let method = MethodRecord {
        name: "long_method".to_string(),
        file_path: "src/long.py".to_string(),
        source,
        loc: 262,
        param_count: 1,
        start_line: 1,
        end_line: 263,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let request = captured.lock().unwrap().clone();
    assert!(
        request.contains(method_tail),
        "the method review prompt must contain the tail of a long method"
    );
}

#[tokio::test]
async fn file_review_sends_the_complete_file_source() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, _hits, captured) = spawn_openai_style_server_with_capture(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file_tail = "FILE_SOURCE_TAIL_SENTINEL";
    let source = format!(
        "{}\n# {file_tail}\n",
        "def helper(value):\n    return value\n".repeat(180)
    );
    let file = FileRecord {
        file_path: "src/large.py".to_string(),
        source,
        language: "python".to_string(),
        methods: vec![],
    };

    analyzer.analyze_file(&file, &[]).await.unwrap();
    let request = captured.lock().unwrap().clone();
    assert!(
        request.contains(file_tail),
        "the file review prompt must contain the tail of a long file"
    );
}

#[tokio::test]
async fn file_review_rejects_evidence_only_present_in_rust_cfg_test_code() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn test_only_helper() {}\",\"cohesive\":false,\"name_accurate\":true,\"reason\":\"file does too much\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/lib.rs".to_string(),
        source:
            "pub fn production() {}\n\n#[cfg(test)]\nmod tests {\n    fn test_only_helper() {}\n}\n"
                .to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };

    let (verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::Unresolved);
    assert!(!verdict.smelly);
    assert!(verdict.reason.contains("evidence"));
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn invalid_file_evidence_is_rejected() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"dict[str, str] = 1\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"type annotation mismatch\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    let (verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::Unresolved);
    assert!(!verdict.smelly);
    assert!(verdict.reason.contains("evidence"));
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn invalid_method_evidence_is_rejected() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"dict[str, list[JsTsFunctionSignature]] = 2\",\"reason\":\"type annotation mismatch\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "run_js_ts_export_detection".to_string(),
        file_path: "sample.ts".to_string(),
        source: "export function run_js_ts_export_detection() {\n    return [];\n}\n".to_string(),
        loc: 3,
        param_count: 0,
        start_line: 1,
        end_line: 3,
        is_exported: true,
        language: "typescript".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected method verdict");
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalid_evidence_retries_can_rescue_a_valid_slop_verdict() {
    let invalid = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"not in source\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"small helper\"}"}}]}"#;
    let valid = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"return 1\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"small helper\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![invalid, invalid, valid, valid]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_sink = Arc::clone(&events);
    let on_progress: ReviewProgressCallback = Arc::new(move |event| {
        events_sink.lock().unwrap().push(event);
    });
    let (verdicts, _, _) = analyze_with_client(
        std::slice::from_ref(&file),
        &[],
        Arc::clone(&analyzer.llm_client),
        true,
        Some(on_progress),
    )
    .await
    .unwrap();
    let verdict = verdicts.into_iter().next().expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(verdict.smelly);
    assert_eq!(verdict.reason, "small helper");
    assert_eq!(verdict.evidence, "return 1");
    assert_eq!(hits.load(Ordering::SeqCst), 4);
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            ReviewProgress::Started {
                label: "file sample.py".to_string(),
            },
            ReviewProgress::RetryingEvidence {
                label: "file sample.py".to_string(),
            },
            ReviewProgress::Started {
                label: "file sample.py".to_string(),
            },
            ReviewProgress::Completed,
        ]
    );
}

#[tokio::test]
async fn no_json_response_retries_same_request_once() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let first = r#"{"choices":[{"message":{"content":"I am thinking aloud, not JSON."}}]}"#;
    let second = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"return 1\",\"reason\":\"small helper\"}"}}]}"#;
    let third = second;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![first, second, third]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "sample".to_string(),
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected method verdict");
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn broad_clean_method_still_gets_a_scoped_parameter_discard_adjudication() {
    let intent = r#"{"choices":[{"message":{"content":"{\"intent\":\"Preserve a compatibility signature while returning the configured value.\",\"contract_status\":\"unknown\",\"necessity_check\":\"The signature contract is not established.\",\"missing_evidence\":[\"external signature consumers\"]}"}}]}"#;
    let clean = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Preserve a compatibility signature while returning the configured value.\",\"reason\":\"The broad method contract is coherent.\",\"necessity_check\":\"The compatibility signature is retained.\",\"contract_status\":\"required\",\"contract_impact\":\"The signature remains available to consumers.\",\"dependency_impact\":\"Callers may use the compatibility signature.\",\"simplification\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}"}}]}"#;
    let scoped = r#"{"choices":[{"message":{"content":"{\"tier\":\"kinda_slop\",\"reason\":\"The pure discard expression makes readers inspect a statement with no semantic effect.\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![intent, clean, scoped]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "compat_value".to_string(),
        file_path: "compat.py".to_string(),
        source: "def compat_value(model=None):\n    _ = (model,)\n    return 1\n".to_string(),
        loc: 3,
        param_count: 1,
        start_line: 1,
        end_line: 3,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected a scoped verdict");
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert_eq!(verdict.evidence, "    _ = (model,)");
    assert!(
        verdict
            .reason
            .contains("Delete only the no-op parameter-discard block.")
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn typed_stale_signature_proof_builds_exact_finding_from_ai_severity() {
    let intent = r#"{"choices":[{"message":{"content":"{\"intent\":\"Normalize a value through a private repository helper.\",\"contract_status\":\"required\",\"necessity_check\":\"The helper has one resolved caller.\",\"missing_evidence\":[]}"}}]}"#;
    let clean = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Normalize a value through a private repository helper.\",\"reason\":\"The method has a coherent purpose.\",\"necessity_check\":\"The resolved caller uses the helper.\",\"contract_status\":\"required\",\"contract_impact\":\"The helper contract remains available.\",\"dependency_impact\":\"The caller invokes the helper.\",\"simplification\":\"none\",\"change_scope\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}"}}]}"#;
    let severity = r#"{"choices":[{"message":{"content":"{\"tier\":\"kinda_slop\",\"reason\":\"Two stale parameters mildly obscure the private helper's real contract.\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![intent, clean, severity]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "_legacy_callback".to_string(),
        file_path: "records.py".to_string(),
        source: "def _legacy_callback(value, event, context):\n    _ = (event, context)\n    return value.strip()\n".to_string(),
        loc: 3,
        param_count: 3,
        start_line: 1,
        end_line: 3,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![crate::types::Reference {
            file_path: "records.py".to_string(),
            line: 6,
            snippet: "return _legacy_callback(value, object(), object())".to_string(),
        }],
        real_ref_count: 1,
    };
    let proof = StaleDiscardSignatureProof {
        discarded_parameters: vec!["context".to_string(), "event".to_string()],
        caller_sites: vec![
            "records.py:6: return _legacy_callback(value, object(), object())".to_string(),
        ],
    };

    let (verdict, _, _) = analyzer
        .analyze_method_review_with_context(
            &method,
            &[],
            MethodReviewContext {
                file_context: "closed-world stale discarded-parameter signature proof: established",
                project_root: None,
                callee_context: &[],
                boundary_requirements: &[],
                repository_private_unused_candidate: false,
                stale_discard_signature_proof: Some(&proof),
            },
            None,
        )
        .await
        .unwrap();

    let verdict = verdict.expect("expected proof-backed stale-signature verdict");
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(verdict.reason.contains("Remove parameters context, event"));
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn duplicated_branch_uses_ai_severity_and_deterministic_proof() {
    let intent = r#"{"choices":[{"message":{"content":"{\"intent\":\"Return a normalized value.\",\"contract_status\":\"required\",\"necessity_check\":\"The return behavior is required.\",\"missing_evidence\":[]}"}}]}"#;
    let clean = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Return a normalized value.\",\"reason\":\"The method has a coherent purpose.\",\"necessity_check\":\"The return behavior is required.\",\"contract_status\":\"required\",\"contract_impact\":\"The callable contract remains available.\",\"dependency_impact\":\"Callers receive the same value.\",\"simplification\":\"none\",\"change_scope\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}"}}]}"#;
    let severity = r#"{"choices":[{"message":{"content":"{\"tier\":\"slop\",\"reason\":\"The fake decision path materially obscures that both inputs receive identical behavior.\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![intent, clean, severity]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "choose_label".to_string(),
        file_path: "names.py".to_string(),
        source: "def choose_label(enabled, value):\n    if enabled:\n        return value.strip()\n    return value.strip()\n"
            .to_string(),
        loc: 4,
        param_count: 2,
        start_line: 9,
        end_line: 12,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 1,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    let verdict = verdict.expect("expected proof-backed duplicate-branch verdict");
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.reason.contains("Replace the duplicated branch"));
    assert_eq!(
        verdict.evidence,
        "    if enabled:\n        return value.strip()\n    return value.strip()"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn broad_clean_private_unused_method_gets_final_adjudication() {
    let intent = r#"{"choices":[{"message":{"content":"{\"intent\":\"Delegate normalization.\",\"contract_status\":\"unknown\",\"necessity_check\":\"No consumer is established.\",\"missing_evidence\":[\"consumer\"]}"}}]}"#;
    let clean = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Delegate normalization.\",\"reason\":\"The delegate is coherent.\",\"necessity_check\":\"The body is direct.\",\"contract_status\":\"required\",\"contract_impact\":\"The method shape is retained.\",\"dependency_impact\":\"No dependency change.\",\"simplification\":\"none\",\"change_scope\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}"}}]}"#;
    let scoped = r#"{"choices":[{"message":{"content":"{\"tier\":\"slop\",\"pattern\":\"needless_indirection\",\"intent\":\"Unused private delegation.\",\"reason\":\"The closed-world dossier proves the private method has no consumer.\",\"necessity_check\":\"No caller, registration, export, test, protocol, or compatibility path exists.\",\"contract_status\":\"unnecessary\",\"contract_impact\":\"Deleting a repository-private unused method changes no callable contract.\",\"dependency_impact\":\"No repository dependency references the method.\",\"simplification\":\"Delete the unused private method.\",\"change_scope\":\"whole_method\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[{\"start_line\":1,\"end_line\":2,\"quote\":\"def _stale_delegate(value):\\n    return normalize(value)\"}]}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![intent, clean, scoped]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "_stale_delegate".to_string(),
        file_path: "src/main.py".to_string(),
        source: "def _stale_delegate(value):\n    return normalize(value)\n".to_string(),
        loc: 2,
        param_count: 1,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer
        .analyze_method_review_with_context(
            &method,
            &[],
            MethodReviewContext {
                file_context:
                    "closed-world private-unused candidate for final AI adjudication: true",
                project_root: None,
                callee_context: &[],
                boundary_requirements: &[],
                repository_private_unused_candidate: true,
                stale_discard_signature_proof: None,
            },
            None,
        )
        .await
        .unwrap();
    let verdict = verdict.expect("expected adjudicated private-unused verdict");
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert_eq!(verdict.evidence, method.source);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn unresolved_adversarial_review_retries_after_history_expansion() {
    let intent = r#"{"choices":[{"message":{"content":"{\"intent\":\"Preserve a repository contract.\",\"contract_status\":\"required\",\"necessity_check\":\"The source has a coherent purpose.\",\"missing_evidence\":[]}"}}]}"#;
    let unresolved = r#"{"choices":[{"message":{"content":"{\"tier\":\"unresolved\",\"pattern\":\"none\",\"intent\":\"Preserve a repository contract.\",\"reason\":\"Compatibility history has not been checked.\",\"necessity_check\":\"The current dossier cannot establish whether compatibility requires this shape.\",\"contract_status\":\"unknown\",\"contract_impact\":\"The contract impact is unknown.\",\"dependency_impact\":\"Compatibility dependencies are unknown.\",\"simplification\":\"none\",\"change_scope\":\"none\",\"behavior_status\":\"unknown\",\"missing_evidence\":[\"git history\"],\"evidence\":[]}"}}]}"#;
    let clean = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Preserve a repository contract.\",\"reason\":\"\",\"necessity_check\":\"The implementation directly serves its repository contract.\",\"contract_status\":\"required\",\"contract_impact\":\"The callable contract requires the current behavior.\",\"dependency_impact\":\"Repository dependencies use the current behavior.\",\"simplification\":\"none\",\"change_scope\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![intent, unresolved, clean]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "sample".to_string(),
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let context = "Method dossier:\n- repository evidence:\ngit history: not queried because no compatibility/migration signal was detected";

    let (verdict, _, _) = analyzer
        .analyze_method_review_with_context(
            &method,
            &[],
            MethodReviewContext {
                file_context: context,
                project_root: Some(std::path::Path::new(".")),
                callee_context: &[],
                boundary_requirements: &[],
                repository_private_unused_candidate: false,
                stale_discard_signature_proof: None,
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        verdict.expect("expected final verdict").tier,
        FindingTier::Clean
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn interrupted_method_reviews_resume_from_journal() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        env::set_var("SNIFF_LLM_MAX_CONCURRENCY", "1");
        env::set_var("SNIFF_LLM_METHOD_BATCH_SIZE", "4");
    }
    let valid = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Implement the method contract.\",\"reason\":\"clean\",\"necessity_check\":\"The implementation is required by its contract.\",\"contract_status\":\"required\",\"contract_impact\":\"The method contract requires the current shape.\",\"dependency_impact\":\"Known callers depend on the current behavior.\",\"simplification\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}"}}],"usage":{"prompt_tokens":10,"completion_tokens":1}}"#;
    let _ = &valid;
    let partial_batch_intent = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"intent\":\"Implement first.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]}]}"}}],"usage":{"prompt_tokens":7,"completion_tokens":1,"prompt_cache_hit_tokens":3}}"#;
    let batch_intent = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"intent\":\"Implement first.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]},{\"method_key\":\"m1\",\"intent\":\"Implement second.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]},{\"method_key\":\"m2\",\"intent\":\"Implement third.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]},{\"method_key\":\"m3\",\"intent\":\"Implement fourth.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]}]}"}}],"usage":{"prompt_tokens":101,"completion_tokens":11,"prompt_cache_hit_tokens":51}}"#;
    let batch_semantic = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Implement first.\",\"reason\":\"clean\",\"necessity_check\":\"Direct implementation.\",\"contract_status\":\"required\",\"contract_impact\":\"Required.\",\"dependency_impact\":\"Callers use it.\",\"simplification\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]},{\"method_key\":\"m1\",\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Implement second.\",\"reason\":\"clean\",\"necessity_check\":\"Direct implementation.\",\"contract_status\":\"required\",\"contract_impact\":\"Required.\",\"dependency_impact\":\"Callers use it.\",\"simplification\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]},{\"method_key\":\"m2\",\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Implement third.\",\"reason\":\"clean\",\"necessity_check\":\"Direct implementation.\",\"contract_status\":\"required\",\"contract_impact\":\"Required.\",\"dependency_impact\":\"Callers use it.\",\"simplification\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]},{\"method_key\":\"m3\",\"tier\":\"clean\",\"pattern\":\"none\",\"intent\":\"Implement fourth.\",\"reason\":\"clean\",\"necessity_check\":\"Direct implementation.\",\"contract_status\":\"required\",\"contract_impact\":\"Required.\",\"dependency_impact\":\"Callers use it.\",\"simplification\":\"none\",\"behavior_status\":\"preserved\",\"missing_evidence\":[],\"evidence\":[]}]}"}}],"usage":{"prompt_tokens":202,"completion_tokens":22}}"#;
    let _ = &batch_semantic;
    let compact_batch_semantic = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"tier\":\"clean\",\"reason\":\"clean\"},{\"method_key\":\"m1\",\"tier\":\"clean\",\"reason\":\"clean\"},{\"method_key\":\"m2\",\"tier\":\"clean\",\"reason\":\"clean\"},{\"method_key\":\"m3\",\"tier\":\"clean\",\"reason\":\"clean\"}]}"}}],"usage":{"prompt_tokens":202,"completion_tokens":22}}"#;
    let single_batch_intent = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"intent\":\"Implement fifth.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]}]}"}}],"usage":{"prompt_tokens":10,"completion_tokens":1}}"#;
    let single_batch_semantic = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"tier\":\"clean\",\"reason\":\"clean\"}]}"}}],"usage":{"prompt_tokens":10,"completion_tokens":1}}"#;
    let (endpoint, hits) = spawn_http_status_sequence_server_with_bodies(
        vec![200, 200, 200, 500, 200, 200],
        vec![
            partial_batch_intent,
            batch_intent,
            compact_batch_semantic,
            "provider failure",
            single_batch_intent,
            single_batch_semantic,
        ],
    );
    let client = Arc::new(
        LLMClient::new(cfg(&endpoint), Some("test-key".to_string())).with_max_attempt_count(1),
    );
    let source = "def first():\n    return 1\n\ndef second():\n    return 2\n\ndef third():\n    return 3\n\ndef fourth():\n    return 4\n\ndef fifth():\n    return 5\n";
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: source.to_string(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "first".to_string(),
                file_path: "sample.py".to_string(),
                source: "def first():\n    return 1\n".to_string(),
                loc: 2,
                param_count: 0,
                start_line: 1,
                end_line: 2,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "second".to_string(),
                file_path: "sample.py".to_string(),
                source: "def second():\n    return 2\n".to_string(),
                loc: 2,
                param_count: 0,
                start_line: 4,
                end_line: 5,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "third".to_string(),
                file_path: "sample.py".to_string(),
                source: "def third():\n    return 3\n".to_string(),
                loc: 2,
                param_count: 0,
                start_line: 7,
                end_line: 8,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "fourth".to_string(),
                file_path: "sample.py".to_string(),
                source: "def fourth():\n    return 4\n".to_string(),
                loc: 2,
                param_count: 0,
                start_line: 10,
                end_line: 11,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "fifth".to_string(),
                file_path: "sample.py".to_string(),
                source: "def fifth():\n    return 5\n".to_string(),
                loc: 2,
                param_count: 0,
                start_line: 13,
                end_line: 14,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let journal = std::env::temp_dir().join(format!(
        "sniff-review-resume-{}.jsonl",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let first_result = analyze_with_client_and_graph_and_journal(
        std::slice::from_ref(&file),
        &[],
        Arc::clone(&client),
        false,
        None,
        None,
        Some(&journal),
    )
    .await;
    let journal_exists_after_failure = journal.exists();
    assert!(
        first_result.is_err(),
        "the injected provider failure should stop the first run; hits={}",
        hits.load(Ordering::SeqCst)
    );
    assert!(
        journal_exists_after_failure,
        "completed batch should be journaled before the later failure; error={:?}; hits={}",
        first_result.as_ref().err(),
        hits.load(Ordering::SeqCst)
    );
    let completed = std::fs::read_to_string(&journal)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let journal_input_tokens = completed
        .iter()
        .map(|entry| entry["in_tok"].as_u64().unwrap())
        .sum::<u64>();
    let journal_output_tokens = completed
        .iter()
        .map(|entry| entry["out_tok"].as_u64().unwrap())
        .sum::<u64>();
    let journal_cached_input_tokens = completed
        .iter()
        .map(|entry| entry["cached_in_tok"].as_u64().unwrap())
        .sum::<u64>();
    assert!(completed.iter().all(|entry| entry["status"] == "completed"));
    assert!(completed.iter().all(|entry| {
        entry["source_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    }));
    assert!(completed.iter().all(|entry| {
        entry["semantic_index_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    }));
    assert!(
        completed
            .iter()
            .all(|entry| entry["prompt_contract_version"] == "semantic-method-v28")
    );
    let resumed_client = Arc::new(
        LLMClient::new(cfg(&endpoint), Some("test-key".to_string())).with_max_attempt_count(1),
    );
    let resumed = analyze_with_client_and_graph_and_journal(
        std::slice::from_ref(&file),
        &[],
        Arc::clone(&resumed_client),
        false,
        None,
        None,
        Some(&journal),
    )
    .await;
    let hit_count = hits.load(Ordering::SeqCst);
    let journal_exists_after_resume = journal.exists();
    unsafe {
        env::remove_var("SNIFF_LLM_MAX_CONCURRENCY");
        env::remove_var("SNIFF_LLM_METHOD_BATCH_SIZE");
    }

    let (verdicts, input_tokens, output_tokens) = resumed.expect("the resumed run should complete");
    assert_eq!(completed.len(), 4);
    assert_eq!(journal_input_tokens, 310);
    assert_eq!(journal_output_tokens, 34);
    assert_eq!(journal_cached_input_tokens, 54);
    assert_eq!(input_tokens, 330);
    assert_eq!(output_tokens, 36);
    assert_eq!(resumed_client.cached_input_tokens(), 54);
    assert_eq!(verdicts.len(), 5);
    assert_eq!(hit_count, 6);
    assert!(journal_exists_after_resume);
    std::fs::remove_file(journal).ok();
}

#[tokio::test]
async fn partial_batch_repairs_only_the_missing_method_key() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        env::set_var("SNIFF_LLM_MAX_CONCURRENCY", "1");
        env::set_var("SNIFF_LLM_METHOD_BATCH_SIZE", "4");
    }
    let partial_batch_intent = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"intent\":\"Implement first.\",\"contract_status\":\"required\",\"necessity_check\":\"Direct implementation.\",\"missing_evidence\":[]}] }"}}]}"#;
    let batch_semantic = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"tier\":\"clean\",\"reason\":\"The direct return serves the established contract.\"},{\"method_key\":\"m1\",\"tier\":\"clean\",\"reason\":\"The direct return serves the established contract.\"}]}"}}]}"#;
    let file_clean = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"cohesive file\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![
        partial_batch_intent,
        partial_batch_intent,
        batch_semantic,
        batch_semantic,
        file_clean,
        file_clean,
    ]);
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));
    let source = "def first():\n    return 1\n\ndef second():\n    return 2\n";
    let method = |name: &str, start_line: usize, value: usize| MethodRecord {
        name: name.to_string(),
        file_path: "sample.py".to_string(),
        source: format!("def {name}():\n    return {value}\n"),
        loc: 2,
        param_count: 0,
        start_line,
        end_line: start_line + 1,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: source.to_string(),
        language: "python".to_string(),
        methods: vec![method("first", 1, 1), method("second", 4, 2)],
    };

    let result = analyze_with_client(std::slice::from_ref(&file), &[], client, false, None).await;
    unsafe {
        env::remove_var("SNIFF_LLM_MAX_CONCURRENCY");
        env::remove_var("SNIFF_LLM_METHOD_BATCH_SIZE");
    }

    let (verdicts, _, _) = result.expect("targeted batch repair should complete");
    assert_eq!(verdicts.len(), 2);
    assert!(
        verdicts
            .iter()
            .all(|verdict| verdict.tier == FindingTier::Clean),
        "unexpected compact batch verdicts: {verdicts:#?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn malformed_batch_is_split_until_each_method_receives_a_valid_review() {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe {
        env::set_var("SNIFF_LLM_MAX_CONCURRENCY", "1");
        env::set_var("SNIFF_LLM_METHOD_BATCH_SIZE", "2");
    }
    let malformed_batch = r#"{"choices":[{"message":{"content":"{\"tier\":\"clean\"}"}}]}"#;
    let singleton_intent = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"intent\":\"Return the configured value.\",\"contract_status\":\"required\",\"necessity_check\":\"The direct return implements the method contract.\",\"missing_evidence\":[]}] }"}}]}"#;
    let singleton_clean = r#"{"choices":[{"message":{"content":"{\"reviews\":[{\"method_key\":\"m0\",\"tier\":\"clean\",\"reason\":\"The direct return serves the established contract.\"}]}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![
        malformed_batch,
        malformed_batch,
        singleton_intent,
        singleton_clean,
        singleton_intent,
        singleton_clean,
    ]);
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));
    let method = |name: &str, start_line: usize, value: usize| MethodRecord {
        name: name.to_string(),
        file_path: "sample.py".to_string(),
        source: format!("def {name}():\n    return {value}\n"),
        loc: 2,
        param_count: 0,
        start_line,
        end_line: start_line + 1,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let file = FileRecord {
        file_path: "sample.py".to_string(),
        source: "def first():\n    return 1\n\ndef second():\n    return 2\n".to_string(),
        language: "python".to_string(),
        methods: vec![method("first", 1, 1), method("second", 4, 2)],
    };

    let result = analyze_with_client(std::slice::from_ref(&file), &[], client, false, None).await;
    unsafe {
        env::remove_var("SNIFF_LLM_MAX_CONCURRENCY");
        env::remove_var("SNIFF_LLM_METHOD_BATCH_SIZE");
    }

    let (verdicts, _, _) = result.expect("split batch review should complete");
    assert_eq!(verdicts.len(), 2);
    assert!(
        verdicts
            .iter()
            .all(|verdict| verdict.tier == FindingTier::Clean),
        "unexpected split batch verdicts: {verdicts:#?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn disagreement_runs_a_final_adjudication_pass() {
    let slop = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"return 1\",\"reason\":\"unnecessary machinery\"}"}}]}"#;
    let clean = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server_sequence(vec![slop, clean, slop]);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let method = MethodRecord {
        name: "sample".to_string(),
        file_path: "sample.py".to_string(),
        source: "def sample():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, _, _) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    assert_eq!(verdict.unwrap().tier, FindingTier::Slop);
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}
