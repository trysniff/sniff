use super::*;

#[tokio::test]
async fn finding_diff_module_is_reviewed_by_llm() {
    let (endpoint, hits) = spawn_openai_style_server(
        r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"parse_diff_files\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#,
    );
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };

    let file = FileRecord {
        file_path: "src/bumpkin/analysis/finding_diff.py".to_string(),
        source: "def parse_diff_files(diff_text: str) -> list[FileDiff]:\n    return []\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "parse_diff_files".to_string(),
            file_path: "src/bumpkin/analysis/finding_diff.py".to_string(),
            source: "def parse_diff_files(diff_text: str) -> list[FileDiff]:\n    return []\n"
                .to_string(),
            loc: 60,
            param_count: 1,
            start_line: 1,
            end_line: 2,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&file, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert!(hits.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn eval_fixtures_module_is_reviewed_by_llm() {
    let (endpoint, hits) = spawn_openai_style_server(
        r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"load_fixture_cases\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#,
    );
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };

    let file = FileRecord {
        file_path: "src/bumpkin/eval/fixtures.py".to_string(),
        source: "def load_fixture_cases(fixtures_dir):\n    return []\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "load_fixture_cases".to_string(),
            file_path: "src/bumpkin/eval/fixtures.py".to_string(),
            source: "def load_fixture_cases(fixtures_dir):\n    return []\n".to_string(),
            loc: 60,
            param_count: 1,
            start_line: 1,
            end_line: 2,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&file, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert!(hits.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn parsing_helper_modules_stay_clean_on_branchy_control_flow_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"_status_for_outcome\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"_status_for_outcome: branchy control flow (5 branches)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/integrations/github/webhook_parsing.py".to_string(),
        source: "def _status_for_outcome(outcome: str) -> int:\n    return 500\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "_status_for_outcome".to_string(),
            file_path: "src/bumpkin/integrations/github/webhook_parsing.py".to_string(),
            source: "def _status_for_outcome(outcome: str) -> int:\n    return 500\n".to_string(),
            loc: 7,
            param_count: 1,
            start_line: 1,
            end_line: 7,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "_status_for_outcome".to_string(),
        reason: "_status_for_outcome: branchy control flow (5 branches)".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn utility_surface_modules_stay_clean_on_helper_bag_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"stableStringify(value)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"filename is vague 'helpers'; mergeHeaderTokens: branchy control flow (2 branches); parseBooleanFlag: branchy control flow (3 branches)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/utils/helpers.ts".to_string(),
            source: "export function stableStringify(value: any): string { return JSON.stringify(value); }".to_string(),
            language: "typescript".to_string(),
            methods: vec![
                MethodRecord {
                    name: "stableStringify".to_string(),
                    file_path: "src/utils/helpers.ts".to_string(),
                    source: "export function stableStringify(value: any): string { return JSON.stringify(value); }".to_string(),
                    loc: 12,
                    param_count: 1,
                    start_line: 1,
                    end_line: 12,
                    is_exported: true,
                    language: "typescript".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "jsonResponse".to_string(),
                    file_path: "src/utils/helpers.ts".to_string(),
                    source: "export function jsonResponse(body: unknown, init: ResponseInit = {}) { return new Response(JSON.stringify(body), { ...init }); }".to_string(),
                    loc: 16,
                    param_count: 3,
                    start_line: 13,
                    end_line: 28,
                    is_exported: true,
                    language: "typescript".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "parseBooleanFlag".to_string(),
                    file_path: "src/utils/helpers.ts".to_string(),
                    source: "export function parseBooleanFlag(raw: string | undefined, fallback: boolean): boolean { return fallback; }".to_string(),
                    loc: 8,
                    param_count: 2,
                    start_line: 29,
                    end_line: 36,
                    is_exported: false,
                    language: "typescript".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "stableStringify(value)".to_string(),
            reason: "filename is vague 'helpers'; mergeHeaderTokens: branchy control flow (2 branches); parseBooleanFlag: branchy control flow (3 branches)".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn camel_case_utility_surface_modules_stay_clean_on_message_mapper_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"mapByMessagePattern(raw)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file mixes a pattern-matching message mapper with a fallback chain that delegates to another module, making the name 'user-safe-toast-message' too narrow for the actual logic\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
        source: "function normalizeCode(value: unknown): string { return String(value || '').trim().toUpperCase(); }\n\
                 function normalizeFallback(fallback: string): string { return fallback || 'Something went wrong. Please retry.'; }\n\
                 function extractRawMessage(input: unknown): string { return ''; }\n\
                 function normalizeMessage(raw: string): string { return String(raw || '').trim().toLowerCase(); }\n\
                 function mapByMessagePattern(raw: string): string | null { return null; }\n\
                 function asFailureLike(input: unknown): { code?: unknown; message?: unknown } | null { return null; }\n\
                 export function getUserSafeToastMessage(input: unknown, fallback: string): string { return fallback; }\n"
            .to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "normalizeCode".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 1,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalizeFallback".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 2,
                end_line: 2,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "extractRawMessage".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 3,
                end_line: 3,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalizeMessage".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 4,
                end_line: 4,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "mapByMessagePattern".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 5,
                end_line: 5,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "asFailureLike".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 6,
                end_line: 6,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getUserSafeToastMessage".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 2,
                start_line: 7,
                end_line: 7,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "mapByMessagePattern(raw)".to_string(),
        reason: "file mixes a pattern-matching message mapper with a fallback chain that delegates to another module, making the name 'user-safe-toast-message' too narrow for the actual logic".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn analysis_finding_workspace_modules_stay_clean_on_branchy_control_flow_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"python_module_candidates(path)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"python_module_candidates: branchy control flow (3 branches); python_package_root: branchy control flow (4 branches)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/finding_workspace.py".to_string(),
        source: "def python_module_candidates(path: str) -> set[str]:\n    return set()\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "python_module_candidates".to_string(),
                file_path: "src/bumpkin/analysis/finding_workspace.py".to_string(),
                source: "def python_module_candidates(path: str) -> set[str]:\n    return set()\n"
                    .to_string(),
                loc: 10,
                param_count: 1,
                start_line: 1,
                end_line: 10,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "python_package_root".to_string(),
                file_path: "src/bumpkin/analysis/finding_workspace.py".to_string(),
                source: "def python_package_root(path: str) -> str | None:\n    return None\n"
                    .to_string(),
                loc: 12,
                param_count: 1,
                start_line: 11,
                end_line: 22,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "python_module_candidates(path)".to_string(),
            reason: "python_module_candidates: branchy control flow (3 branches); python_package_root: branchy control flow (4 branches)".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn versioning_tag_modules_stay_clean_on_helper_surface_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"module has sprawling helper surface\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module has sprawling helper surface (5 exported methods, 7-51 LOC spread); _select_current_tag: overbuilt logic: checks monotonicity of tag source order\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/versioning/tags.py".to_string(),
        source: "def parse_tag(tag: str) -> ParsedTag | None:\n    return None\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "parse_tag".to_string(),
            file_path: "src/bumpkin/versioning/tags.py".to_string(),
            source: "def parse_tag(tag: str) -> ParsedTag | None:\n    return None\n".to_string(),
            loc: 7,
            param_count: 1,
            start_line: 1,
            end_line: 7,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "module has sprawling helper surface".to_string(),
            reason: "module has sprawling helper surface (5 exported methods, 7-51 LOC spread); _select_current_tag: overbuilt logic: checks monotonicity of tag source order".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
