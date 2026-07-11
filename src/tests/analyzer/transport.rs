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
    assert_eq!(hits.load(Ordering::SeqCst), 2);
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
        env::set_var("SNIFF_LLM_MAX_ATTEMPTS", "1");
    }

    let (endpoint, hits) = spawn_http_status_sequence_server(
        vec![500, 200],
        r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"def beta():\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#,
    );
    let client = Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string())));

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

    let result = analyze_with_client(&files, &[], client, true, None::<fn()>).await;

    unsafe {
        env::remove_var("SNIFF_LLM_MAX_CONCURRENCY");
        env::remove_var("SNIFF_LLM_MAX_ATTEMPTS");
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

    let err = analyze(&[file], &[], ResolvedConfig::default(), false, None::<fn()>)
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
            "class WebhookService:\n    def other_handler(self):\n        return None",
        )
        .await
        .unwrap();
    let request = captured.lock().unwrap().clone();
    assert!(request.contains("File path:"));
    assert!(request.contains("src/services/webhook_service.py"));
    assert!(request.contains("Surrounding file context"));
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
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
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
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
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

    let (verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(verdict.smelly);
    assert_eq!(verdict.reason, "small helper");
    assert_eq!(verdict.evidence, "return 1");
    assert_eq!(hits.load(Ordering::SeqCst), 4);
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
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}
