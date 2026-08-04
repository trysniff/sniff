use super::*;

#[tokio::test]
async fn analysis_finding_helpers_with_vague_names_stay_clean() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"python_packaging.py\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"Filename suggests general Python packaging utilities, but file only extracts Python version floor from metadata files; does too little for its name and mixes parsing logic for three different file formats in one module.\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/analysis/finding_python_packaging.py".to_string(),
            source: "def extract_requires_python_floor(path: str, lines: list[str]) -> tuple[int, ...] | None:\n    return None\n".to_string(),
            language: "python".to_string(),
            methods: vec![MethodRecord {
                name: "extract_requires_python_floor".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_packaging.py".to_string(),
                source: "def extract_requires_python_floor(path: str, lines: list[str]) -> tuple[int, ...] | None:\n    return None\n".to_string(),
                loc: 2,
                param_count: 2,
                start_line: 1,
                end_line: 2,
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
        evidence: "sprawling helper surface".to_string(),
        reason: "module has sprawling helper surface (10 exported methods, 6-69 LOC spread)"
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
async fn analysis_finding_parameter_compat_helpers_stay_clean() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"sprawling helper surface\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module has sprawling helper surface (10 exported methods, 6-69 LOC spread)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
            source: "import ast\nfrom dataclasses import dataclass\n\ndef parse_python_parameter_specs(params: str) -> list[str] | None:\n    return None\n".to_string(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "is_optional_param".to_string(),
                    file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                    source: "def is_optional_param(token: str) -> bool:\n    return False\n".to_string(),
                    loc: 2,
                    param_count: 1,
                    start_line: 1,
                    end_line: 2,
                    is_exported: true,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "parse_python_parameter_specs".to_string(),
                    file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                    source: "def parse_python_parameter_specs(params: str) -> list[str] | None:\n    return None\n".to_string(),
                    loc: 69,
                    param_count: 1,
                    start_line: 4,
                    end_line: 5,
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
        evidence: "sprawling helper surface".to_string(),
        reason: "module has sprawling helper surface (10 exported methods, 6-69 LOC spread)"
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

#[test]
fn support_plumbing_copy_paste_noise_is_cleared() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/planner.py".to_string(),
        source: "def to_dict():\n    return {}\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "to_dict".to_string(),
            file_path: "src/bumpkin/planner.py".to_string(),
            source: "def to_dict():\n    return {}\n".to_string(),
            loc: 12,
            param_count: 0,
            start_line: 1,
            end_line: 12,
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
        evidence: "to_dict".to_string(),
        reason: "to_dict: copy-pasted method body (matches C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\impact.py::to_dict)".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
}

#[tokio::test]
async fn analysis_finding_signatures_still_flag_large_methods() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"extract_python_signatures\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/finding_python_signatures.py".to_string(),
        source: "def extract_python_signatures(source: str) -> list[str]:\n    return []\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "extract_python_signatures".to_string(),
            file_path: "src/bumpkin/analysis/finding_python_signatures.py".to_string(),
            source: "def extract_python_signatures(source: str) -> list[str]:\n    return []\n"
                .to_string(),
            loc: 102,
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
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "extract_python_signatures".to_string(),
        reason: "file does too much".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.smelly);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn analysis_finding_surface_base_helpers_stay_clean() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"module has sprawling helper surface\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module has sprawling helper surface (14 exported methods, 4-31 LOC spread)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
            source: "import ast\nimport re\n".to_string(),
            language: "python".to_string(),
            methods: vec![
                MethodRecord {
                    name: "collect_python_signature_source".to_string(),
                    file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
                    source: "def collect_python_signature_source(lines: list[str], start_index: int) -> tuple[str, int]:\n    return \"\", 0\n".to_string(),
                    loc: 26,
                    param_count: 2,
                    start_line: 1,
                    end_line: 26,
                    is_exported: true,
                    language: "python".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "split_top_level_params".to_string(),
                    file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
                    source: "def split_top_level_params(params: str) -> list[str]:\n    return []\n".to_string(),
                    loc: 31,
                    param_count: 1,
                    start_line: 27,
                    end_line: 57,
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
        reason: "module has sprawling helper surface (14 exported methods, 4-31 LOC spread)"
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
async fn analysis_findings_facade_stays_clean() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"findings.extend(detect_js_ts_export_findings(diff_text))\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"file does too much: re-exports from multiple submodules, defines helper functions, and orchestrates two different detection pipelines, making it a vague facade rather than a focused module\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/analysis/findings.py".to_string(),
            source: "from bumpkin.analysis import finding_js_ts\n\ndef detect_semver_findings(diff_text: str) -> list[str]:\n    return []\n".to_string(),
            language: "python".to_string(),
            methods: vec![MethodRecord {
                name: "_normalize_type".to_string(),
                file_path: "src/bumpkin/analysis/findings.py".to_string(),
                source: "def _normalize_type(raw_type: str | None) -> str | None:\n    return None\n".to_string(),
                loc: 4,
                param_count: 1,
                start_line: 1,
                end_line: 4,
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
            evidence: "findings.extend(detect_js_ts_export_findings(diff_text))".to_string(),
            reason: "file does too much: re-exports from multiple submodules, defines helper functions, and orchestrates two different detection pipelines, making it a vague facade rather than a focused module".to_string(),
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
async fn analysis_explanation_support_can_be_flagged_as_slop() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"derive_operation_hint(snippet)\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"module mixes public surface and orchestration (15 exported methods, 20 external references); module has sprawling helper surface (15 exported methods, 4-79 LOC spread)\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/explanation_facts.py".to_string(),
        source: "import re\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "derive_operation_hint".to_string(),
            file_path: "src/bumpkin/analysis/explanation_facts.py".to_string(),
            source: "def derive_operation_hint(snippet: str) -> str | None:\n    return None\n"
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
            evidence: "derive_operation_hint(snippet)".to_string(),
            reason: "module mixes public surface and orchestration (15 exported methods, 20 external references); module has sprawling helper surface (15 exported methods, 4-79 LOC spread)".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(verdict.smelly);
    assert!(!verdict.reason.is_empty());
    assert!(!verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn support_plumbing_modules_are_reviewed() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/orchestrator/explanation_facts.py".to_string(),
        source: "def build_explanation_facts(result):\n    return result\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };
    let parser_facade = FileRecord {
        file_path: "src/parser_impl.rs".to_string(),
        source: "use crate::language_adapter::LanguageAdapter;\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let rules_analysis = FileRecord {
        file_path: "src/analyzer_verdicts_rules_analysis.rs".to_string(),
        source: "fn should_clear_analysis_verdict() -> bool { true }\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let similarity_roles = FileRecord {
        file_path: "src/signal_layers_similarity_roles.rs".to_string(),
        source: "pub(crate) fn normalize_path(path: &str) -> String {\n    path.replace('\\\\', \"/\").to_lowercase()\n}\n".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let analysis_surface_base = FileRecord {
        file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
        source: "import ast\nimport re\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "collect_python_signature_source".to_string(),
            file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
            source: "def collect_python_signature_source(lines: list[str], start_index: int) -> tuple[str, int]:\n    return \"\", 0\n".to_string(),
            loc: 26,
            param_count: 2,
            start_line: 1,
            end_line: 26,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };
    let analysis_surface_base_method = MethodRecord {
        name: "collect_python_signature_source".to_string(),
        file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
        source: "def collect_python_signature_source(lines: list[str], start_index: int) -> tuple[str, int]:\n    return \"\", 0\n".to_string(),
        loc: 26,
        param_count: 2,
        start_line: 1,
        end_line: 26,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&file, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&parser_facade, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&rules_analysis, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&similarity_roles, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);

    let (verdict, in_tok, out_tok) = analyzer
        .analyze_file(&analysis_surface_base, &[])
        .await
        .unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);

    let (verdict, in_tok, out_tok) = analyzer
        .analyze_method_review(&analysis_surface_base_method, &[])
        .await
        .unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert!(hits.load(Ordering::SeqCst) >= 6);

    let static_flags = crate::scorer::score(&[analysis_surface_base], &ResolvedConfig::default());
    assert!(
        static_flags.is_empty(),
        "analysis support modules should be skipped from static scoring"
    );
}

#[tokio::test]
async fn parser_impl_state_bag_noise_is_cleared() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"kinda_slop\",\"evidence\":\"pub(crate) struct PyExtractor<'a> {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"struct holds too many unrelated fields and reads like a state bag\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/parser_impl/python_extractor_state.rs".to_string(),
        source: "pub(crate) struct PyExtractor<'a> {\n    pub source: &'a str,\n    pub line_index: LineIndex,\n    pub file_path: String,\n    pub methods: Vec<MethodRecord>,\n    pub definitions: Vec<SymbolDefinition>,\n    pub imports: Vec<ImportRecord>,\n    pub exports: Vec<ExportRecord>,\n    pub references: Vec<SymbolReference>,\n    pub scopes: Vec<HashSet<String>>,\n    pub next_id: usize,\n    pub parent_is_class: bool,\n    pub in_function_body: bool,\n    pub scanned: bool,\n}\n".to_string(),
        language: "rust".to_string(),
        methods: vec![MethodRecord {
            name: "visit_stmt".to_string(),
            file_path: "src/parser_impl/python_extractor_state.rs".to_string(),
            source: "pub(crate) fn visit_stmt<T>(&mut self, _stmt: T) {}".to_string(),
            loc: 3,
            param_count: 1,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            language: "rust".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&file, &[]).await.unwrap();
    assert!(verdict.is_some());
    let verdict = verdict.unwrap();
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(!verdict.reason.is_empty());
    assert!(!verdict.evidence.is_empty());
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn provider_facade_modules_are_reviewed() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/bumpkin/providers/llm.py".to_string(),
        source: "from bumpkin.providers.chunking import split_diff_into_chunks as _split_diff_into_chunks_impl\n\
                 from bumpkin.providers.llm_payloads import validate_recommendation as _validate_recommendation_impl\n\
                 from bumpkin.providers.llm_transport import request_headers as _request_headers_impl\n\
                 from bumpkin.providers.semantic import manual_review_result as _manual_review_result_impl\n\
                 def _provider_mode_for_endpoint(endpoint): return _provider_mode_for_endpoint_impl(endpoint)\n\
                 def _normalize_request_endpoint(endpoint): return _normalize_request_endpoint_impl(endpoint)\n\
                 def _request_headers(token, endpoint): return _request_headers_impl(token, endpoint)\n\
                 def _manual_review_result(reasoning): return _manual_review_result_impl(reasoning=reasoning)\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_provider_mode_for_endpoint".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _provider_mode_for_endpoint(endpoint: str) -> str:\n    return 'openai-compatible'\n".to_string(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_normalize_request_endpoint".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _normalize_request_endpoint(endpoint: str) -> str:\n    return endpoint\n".to_string(),
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
                name: "_request_headers".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _request_headers(token: str, endpoint: str) -> dict[str, str]:\n    return {}\n".to_string(),
                loc: 2,
                param_count: 2,
                start_line: 5,
                end_line: 6,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_manual_review_result".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _manual_review_result(reasoning: str) -> dict[str, str]:\n    return {}\n".to_string(),
                loc: 2,
                param_count: 1,
                start_line: 7,
                end_line: 8,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "get_recommendation".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def get_recommendation(mode: str, diff_text: str) -> dict[str, str]:\n    return {}\n".to_string(),
                loc: 52,
                param_count: 12,
                start_line: 9,
                end_line: 60,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_split_diff_into_chunks".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _split_diff_into_chunks(diff_text: str) -> tuple[list[str], int]:\n    return [], 0\n".to_string(),
                loc: 2,
                param_count: 3,
                start_line: 61,
                end_line: 62,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_aggregate_chunk_recommendations".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _aggregate_chunk_recommendations(recommendations: list[dict[str, str]]) -> dict[str, str]:\n    return {}\n".to_string(),
                loc: 2,
                param_count: 2,
                start_line: 63,
                end_line: 64,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_build_messages".to_string(),
                file_path: "src/bumpkin/providers/llm.py".to_string(),
                source: "def _build_messages(diff_text: str) -> list[dict[str, str]]:\n    return []\n".to_string(),
                loc: 2,
                param_count: 4,
                start_line: 65,
                end_line: 66,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let method = MethodRecord {
        name: "get_recommendation".to_string(),
        file_path: "src/bumpkin/providers/llm.py".to_string(),
        source:
            "def get_recommendation(mode: str, diff_text: str) -> dict[str, str]:\n    return {}\n"
                .to_string(),
        loc: 52,
        param_count: 12,
        start_line: 9,
        end_line: 60,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let (verdict, in_tok, out_tok) = analyzer.analyze_file(&file, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);

    let (verdict, in_tok, out_tok) = analyzer.analyze_method_review(&method, &[]).await.unwrap();
    assert!(verdict.is_some());
    assert!(in_tok > 0);
    assert!(out_tok > 0);
    assert!(hits.load(Ordering::SeqCst) >= 2);
}

#[test]
fn provider_facade_file_verdict_is_cleared_but_methods_remain_reviewable() {
    let file_path = "src/bumpkin/providers/llm.py".to_string();
    let source = "from bumpkin.providers.chunking import split_diff_into_chunks\n\
from bumpkin.providers.llm_payloads import validate_recommendation\n\
from bumpkin.providers.llm_transport import request_headers\n\
from bumpkin.providers.semantic import manual_review_result\n\
def one(value): return value\n\
def two(value): return value\n\
def three(value): return value\n\
def four(value): return value\n"
        .to_string();
    let methods = (0..8)
        .map(|index| MethodRecord {
            name: format!("_helper_{index}"),
            file_path: file_path.clone(),
            source: "def helper(value): return value\n".to_string(),
            loc: 1,
            param_count: 1,
            start_line: index + 5,
            end_line: index + 5,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        })
        .collect();
    let file = FileRecord {
        file_path: file_path.clone(),
        source,
        language: "python".to_string(),
        methods,
    };
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path,
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "from bumpkin.providers.chunking import".to_string(),
        reason: "file is a pure delegation layer that re-exports every function from multiple submodules with no added logic, making it a redundant facade that hides intent".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(
        &file,
        &LLMClient::new(cfg("http://127.0.0.1:9"), None),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}
