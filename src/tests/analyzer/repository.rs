use super::*;

#[tokio::test]
async fn brandset_worker_helpers_get_reviewed_as_slop() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"export function stableStringify(value: any): string {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    thread::spawn(move || {
        for _ in 0..4 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 16384];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    let endpoint = format!("http://{}", addr);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/utils/helpers.ts".to_string(),
            source: "export function stableStringify(value: any): string {\n  return JSON.stringify(value);\n}\n\nexport function jsonResponse(body: unknown, init: ResponseInit = {}) {\n  return new Response(JSON.stringify(body), { ...init });\n}\n".to_string(),
            language: "typescript".to_string(),
            methods: vec![],
        };

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.smelly);
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert!(hits.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn parsing_helper_modules_stay_clean_on_helper_surface_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"module has sprawling helper surface\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module has sprawling helper surface (8 exported methods, 4-25 LOC spread)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/integrations/github/persistence_record_parsing.py".to_string(),
            source: "from typing import Any\n".to_string(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "_optional_text".to_string(),
                    file_path: "src/bumpkin/integrations/github/persistence_record_parsing.py".to_string(),
                    source: "def _optional_text(row: Mapping[str, object], key: str) -> str | None:\n    return None\n".to_string(),
                    loc: 3,
                    param_count: 2,
                    start_line: 1,
                    end_line: 3,
                    is_exported: false,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "build_stored_event_record".to_string(),
                    file_path: "src/bumpkin/integrations/github/persistence_record_parsing.py".to_string(),
                    source: "def build_stored_event_record(row: Mapping[str, object]) -> StoredEventRecord:\n    return StoredEventRecord(...)\n".to_string(),
                    loc: 25,
                    param_count: 1,
                    start_line: 4,
                    end_line: 28,
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
        evidence: "module has sprawling helper surface".to_string(),
        reason: "module has sprawling helper surface (8 exported methods, 4-25 LOC spread)"
            .to_string(),
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
async fn support_plumbing_modules_stay_clean_on_branchy_control_flow_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"post_json_request\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"post_json_request: branchy control flow (8 branches)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/providers/llm_transport.py".to_string(),
            source: "def post_json_request(...):\n    return {}\n".to_string(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "provider_mode_for_endpoint".to_string(),
                    file_path: "src/bumpkin/providers/llm_transport.py".to_string(),
                    source: "def provider_mode_for_endpoint(endpoint: str) -> str:\n    return 'openai-compatible'\n".to_string(),
                    loc: 3,
                    param_count: 1,
                    start_line: 1,
                    end_line: 3,
                    is_exported: true,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "post_json_request".to_string(),
                    file_path: "src/bumpkin/providers/llm_transport.py".to_string(),
                    source: "def post_json_request(...):\n    return {}\n".to_string(),
                    loc: 20,
                    param_count: 5,
                    start_line: 4,
                    end_line: 23,
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
        evidence: "post_json_request".to_string(),
        reason: "post_json_request: branchy control flow (8 branches)".to_string(),
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
async fn ui_helper_modules_stay_clean_on_mixed_support_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"stageDropPayload(token, dataUrl, filename, mimeType)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file mixes drag setup, token generation, base64 conversion, and storage staging; name 'logo-drag' is vague for a file that also handles token staging and file conversion\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };

    let logo_drag = FileRecord {
        file_path: "ui/src/lib/logo-drag.ts".to_string(),
        source: "export function setupLogoDrag() {}\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "generateDropToken".to_string(),
                file_path: "ui/src/lib/logo-drag.ts".to_string(),
                source: String::new(),
                loc: 10,
                param_count: 0,
                start_line: 1,
                end_line: 10,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "stageDropPayload".to_string(),
                file_path: "ui/src/lib/logo-drag.ts".to_string(),
                source: String::new(),
                loc: 18,
                param_count: 4,
                start_line: 11,
                end_line: 28,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "base64ToFile".to_string(),
                file_path: "ui/src/lib/logo-drag.ts".to_string(),
                source: String::new(),
                loc: 14,
                param_count: 2,
                start_line: 29,
                end_line: 42,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "setupLogoDrag".to_string(),
                file_path: "ui/src/lib/logo-drag.ts".to_string(),
                source: String::new(),
                loc: 30,
                param_count: 2,
                start_line: 43,
                end_line: 72,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let mut logo_verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: logo_drag.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "stageDropPayload(token, dataUrl, filename, mimeType)".to_string(),
        reason: "file mixes drag setup, token generation, base64 conversion, and storage staging; name 'logo-drag' is vague for a file that also handles token staging and file conversion".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&logo_drag, &analyzer.llm_client, &mut logo_verdict);
    assert_eq!(logo_verdict.tier, FindingTier::Clean);
    assert!(!logo_verdict.smelly);
    assert!(logo_verdict.reason.is_empty());
    assert!(logo_verdict.evidence.is_empty());

    let dom_utils = FileRecord {
        file_path: "ui/src/lib/smart-filler/dom-utils.ts".to_string(),
        source: "export function findNestedFormControl() {}\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "findNestedFormControl".to_string(),
                file_path: "ui/src/lib/smart-filler/dom-utils.ts".to_string(),
                source: String::new(),
                loc: 22,
                param_count: 2,
                start_line: 1,
                end_line: 22,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "isElementVisible".to_string(),
                file_path: "ui/src/lib/smart-filler/dom-utils.ts".to_string(),
                source: String::new(),
                loc: 12,
                param_count: 1,
                start_line: 23,
                end_line: 34,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "isLikelyBlockedByUiLayer".to_string(),
                file_path: "ui/src/lib/smart-filler/dom-utils.ts".to_string(),
                source: String::new(),
                loc: 60,
                param_count: 1,
                start_line: 35,
                end_line: 94,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let mut dom_verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: dom_utils.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "findNestedFormControl".to_string(),
        reason: "findNestedFormControl: branchy control flow (11 branches); isLikelyBlockedByUiLayer: branchy control flow (11 branches); isShadowHostForElement: branchy control flow (3 branches)".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&dom_utils, &analyzer.llm_client, &mut dom_verdict);
    assert_eq!(dom_verdict.tier, FindingTier::Clean);
    assert!(!dom_verdict.smelly);
    assert!(dom_verdict.reason.is_empty());
    assert!(dom_verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn smart_filler_heuristics_modules_stay_clean_on_name_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"scoreFieldSemantic(input)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file mixes generic heuristic utilities with a specific scoring function for form fields, and the name 'heuristics' is vague about what kind of heuristics\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "ui/src/lib/smart-filler/heuristics.ts".to_string(),
        source: "export function hasKeywordMatch() {}\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "hasKeywordMatch".to_string(),
                file_path: "ui/src/lib/smart-filler/heuristics.ts".to_string(),
                source: String::new(),
                loc: 16,
                param_count: 2,
                start_line: 1,
                end_line: 16,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "optionMatchesType".to_string(),
                file_path: "ui/src/lib/smart-filler/heuristics.ts".to_string(),
                source: String::new(),
                loc: 22,
                param_count: 4,
                start_line: 17,
                end_line: 38,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "scoreDropdownField".to_string(),
                file_path: "ui/src/lib/smart-filler/heuristics.ts".to_string(),
                source: String::new(),
                loc: 68,
                param_count: 3,
                start_line: 39,
                end_line: 106,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "scoreFieldSemantic".to_string(),
                file_path: "ui/src/lib/smart-filler/heuristics.ts".to_string(),
                source: String::new(),
                loc: 103,
                param_count: 1,
                start_line: 107,
                end_line: 209,
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
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "scoreFieldSemantic(input)".to_string(),
        reason: "file mixes generic heuristic utilities with a specific scoring function for form fields, and the name 'heuristics' is vague about what kind of heuristics".to_string(),
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
async fn session_state_contract_modules_stay_clean_on_display_helper_noise() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"describeSessionPendingState(reason)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file mixes type definitions with UI display logic, making it do more than type declarations\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "ui/src/session/session.types.ts".to_string(),
        source: "export type SessionStatus = 'starting' | 'running';\nexport function isActiveSessionStatus(status: unknown): status is SessionStatus { return true; }\nexport function normalizeSessionPendingReason(reason: unknown): string | null { return null; }\nexport function describeSessionPendingState(reason: unknown): { title: string; description: string } { return { title: '', description: '' }; }\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "isActiveSessionStatus".to_string(),
                file_path: "ui/src/session/session.types.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 1,
                end_line: 3,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalizeSessionPendingReason".to_string(),
                file_path: "ui/src/session/session.types.ts".to_string(),
                source: String::new(),
                loc: 36,
                param_count: 1,
                start_line: 4,
                end_line: 39,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "describeSessionPendingState".to_string(),
                file_path: "ui/src/session/session.types.ts".to_string(),
                source: String::new(),
                loc: 62,
                param_count: 1,
                start_line: 40,
                end_line: 102,
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
        evidence: "describeSessionPendingState(reason)".to_string(),
        reason: "file mixes type definitions with UI display logic, making it do more than type declarations".to_string(),
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
async fn diff_text_and_candidate_modules_are_reviewed_by_llm() {
    let (endpoint, hits) = spawn_openai_style_server(
        r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"file does too much\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#,
    );
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };

    let diff_text_file = FileRecord {
        file_path: "src/bumpkin/analysis/diff_text.py".to_string(),
        source: "def _build_diff_text(...):\n    return \"\"\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };
    let candidate_file = FileRecord {
        file_path: "src/bumpkin/release/candidate.py".to_string(),
        source: "def _build_release_candidate(...):\n    return None\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    let (diff_verdict, diff_in, diff_out) =
        analyzer.analyze_file(&diff_text_file, &[]).await.unwrap();
    let (candidate_verdict, candidate_in, candidate_out) =
        analyzer.analyze_file(&candidate_file, &[]).await.unwrap();

    assert!(diff_verdict.is_some());
    assert!(candidate_verdict.is_some());
    assert!(diff_in + candidate_in > 0);
    assert!(diff_out + candidate_out > 0);
    assert!(hits.load(Ordering::SeqCst) >= 2);
}
