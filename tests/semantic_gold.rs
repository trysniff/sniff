use serde::Deserialize;
use sniff::analyzer::{
    AnalysisRun, analyze_with_client_and_graph_and_journal_with_context_and_records,
};
use sniff::benchmark::{BenchmarkCase, BenchmarkPrediction, evaluate};
use sniff::callgraph::build_references;
use sniff::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use sniff::llm::LLMClient;
use sniff::parser::{parse_file, parse_file_checked, parse_file_symbols_checked};
use sniff::symbol_graph::SymbolGraph;
use sniff::types::{FileRecord, FindingTier};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "case")]
    cases: Vec<GoldCase>,
}

#[derive(Debug, Deserialize, Clone)]
struct GoldCase {
    language: String,
    path: String,
    method: String,
    tier: String,
    pattern: String,
    evidence: String,
    explanation: String,
    #[serde(default)]
    change_scope: Option<String>,
    #[serde(default)]
    intentional_boundary: bool,
}

fn read_http_request(stream: TcpStream) -> (TcpStream, String) {
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        headers.push_str(&line);
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    let _ = reader.read_exact(&mut body);
    (
        reader.into_inner(),
        format!("{}{}", headers, String::from_utf8_lossy(&body)),
    )
}

fn prompt_source(request: &str) -> String {
    if let Some((_, rest)) = request.split_once("Method source:\n---\n") {
        return rest
            .split_once("\n---")
            .map(|(source, _)| source.to_string())
            .unwrap_or_default();
    }
    request
        .split_once("Method source:\\n---\\n")
        .and_then(|(_, rest)| rest.split_once("\\n---"))
        .map(|(source, _)| source.replace("\\n", "\n").replace("\\\"", "\""))
        .unwrap_or_default()
}

fn prompt_line_range(request: &str) -> (usize, usize) {
    request
        .split_once("absolute file line numbers from ")
        .and_then(|(_, rest)| rest.split_once(" through "))
        .and_then(|(start, rest)| {
            let start = start.trim().parse::<usize>().ok()?;
            let end = rest
                .split(|ch: char| !ch.is_ascii_digit())
                .next()
                .and_then(|value| value.parse::<usize>().ok())?;
            Some((start, end))
        })
        .unwrap_or((1, 1))
}

fn request_prompt(request: &str) -> String {
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(request);
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return request.to_string();
    };
    let Some(content) = payload
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("content"))
    else {
        return request.to_string();
    };
    if let Some(content) = content.as_str() {
        return content.to_string();
    }
    content
        .as_array()
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(request)
        .to_string()
}

fn staged_relative_path(source_path: &str) -> PathBuf {
    let normalized = source_path.replace('\\', "/");
    let relative = normalized
        .strip_prefix("tests/semantic_gold_fixtures/")
        .unwrap_or(&normalized);
    if relative == "python/intent_tests.py" {
        PathBuf::from("tests/gold/python/intent_tests.py")
    } else {
        PathBuf::from("src/gold").join(relative)
    }
}

fn normalized_request(request: &str) -> String {
    request.replace("\\\\", "/").replace('\\', "/")
}

fn request_targets_case(request: &str, case: &GoldCase) -> bool {
    let relative_path = staged_relative_path(&case.path)
        .to_string_lossy()
        .replace('\\', "/");
    let method_header = request.contains(&format!("Method: {} (", case.method))
        || request.contains(&format!("Method: {}/nLanguage:", case.method))
        || request.contains(&format!("Method: {}\nLanguage:", case.method))
        || request.contains(&format!("Method: {}/nEvidence line range:", case.method))
        || request.contains(&format!("Method: {}\nEvidence line range:", case.method));
    let file_header = request.contains(&relative_path);
    method_header && file_header
}

fn semantic_inner(request: &str, expected: &GoldCase) -> serde_json::Value {
    let (method_start, _) = prompt_line_range(request);
    let source = prompt_source(request);
    let evidence = if expected.evidence.is_empty() {
        serde_json::json!([])
    } else {
        let offset = source
            .lines()
            .position(|line| line.contains(&expected.evidence))
            .unwrap_or(0);
        serde_json::json!([{
            "start_line": method_start + offset,
            "end_line": method_start + offset + expected.evidence.lines().count().saturating_sub(1),
            "quote": expected.evidence
        }])
    };
    let change_scope = expected.change_scope.as_deref().unwrap_or({
        if matches!(expected.tier.as_str(), "clean" | "unresolved") {
            "none"
        } else {
            "local"
        }
    });
    serde_json::json!({
        "smelly": matches!(expected.tier.as_str(), "slop" | "kinda_slop"),
        "tier": expected.tier,
        "pattern": expected.pattern,
        "intent": "The method performs the operation described by its name.",
        "reason": match expected.tier.as_str() {
            "clean" => "",
            "unresolved" => "The repository dossier cannot establish the external boundary contract.",
            _ => "The implementation adds unnecessary conceptual machinery."
        },
        "necessity_check": expected.explanation,
        "contract_status": match expected.tier.as_str() {
            "clean" => "required",
            "unresolved" => "unknown",
            _ => "unnecessary"
        },
        "contract_impact": match expected.tier.as_str() {
            "clean" => "The repository contract requires the current method shape.",
            "unresolved" => "The contract impact cannot be established without the missing evidence.",
            _ => "The simplification preserves the method signature and public or protocol contract."
        },
        "dependency_impact": match expected.tier.as_str() {
            "clean" => "Callers or boundary consumers require the current behavior.",
            "unresolved" => "Dependency impact cannot be established without external consumers.",
            _ => "No caller, test, adapter, callback, re-export, or compatibility path depends on the unnecessary machinery."
        },
        "simplification": if matches!(expected.tier.as_str(), "clean" | "unresolved") {
            "none"
        } else if change_scope == "whole_method" {
            "delete the unused private method"
        } else {
            "replace the unnecessary machinery with the direct operation"
        },
        "change_scope": change_scope,
        "behavior_status": if expected.tier == "unresolved" { "unknown" } else { "preserved" },
        "missing_evidence": if expected.tier == "unresolved" { vec!["external consumers and boundary contract" ] } else { vec![] },
        "evidence": evidence
    })
}

fn response_envelope(inner: serde_json::Value) -> String {
    serde_json::json!({
        "choices": [{"message": {"content": serde_json::to_string(&inner).unwrap()}}]
    })
    .to_string()
}

fn semantic_response(request: &str, expected: &GoldCase) -> String {
    response_envelope(semantic_inner(request, expected))
}

fn batch_semantic_response(
    prompt: &str,
    cases: &[GoldCase],
    unmatched_requests: &Arc<Mutex<Vec<String>>>,
    intent_only: bool,
) -> String {
    let mut reviews = Vec::new();
    for section in prompt.split("METHOD KEY: ").skip(1) {
        let Some((method_key, block)) = section.split_once('\n') else {
            continue;
        };
        let method_key = method_key.trim().to_string();
        let method_name = block
            .split_once("Method: ")
            .and_then(|(_, rest)| rest.lines().next())
            .and_then(|header| header.split(" (").next())
            .map(str::trim);
        let normalized_block = normalized_request(block);
        let expected = method_name.and_then(|method_name| {
            cases.iter().find(|case| {
                case.method == method_name
                    && request_targets_case(&normalized_block, case)
                    && block.contains(&format!("Language: {}", case.language))
            })
        });
        let Some(expected) = expected else {
            unmatched_requests
                .lock()
                .expect("capture unmatched gold request")
                .push(normalized_request(block));
            continue;
        };
        let mut review = if intent_only {
            serde_json::json!({
                "intent": "The method performs the operation described by its name.",
                "contract_status": match expected.tier.as_str() {
                    "clean" => "required",
                    "unresolved" => "unknown",
                    _ => "unnecessary",
                },
                "necessity_check": expected.explanation,
                "missing_evidence": if expected.tier == "unresolved" {
                    vec!["external consumers and boundary contract"]
                } else {
                    vec![]
                },
            })
        } else {
            semantic_inner(block, expected)
        };
        review["method_key"] = serde_json::Value::String(method_key);
        reviews.push(review);
    }
    response_envelope(serde_json::json!({"reviews": reviews}))
}

struct GoldServer {
    endpoint: String,
    method_requests: Arc<AtomicUsize>,
    adjudication_requests: Arc<AtomicUsize>,
    scoped_requests: Arc<AtomicUsize>,
    captured_requests: Arc<Mutex<Vec<String>>>,
    unmatched_requests: Arc<Mutex<Vec<String>>>,
}

fn spawn_gold_server(cases: Vec<GoldCase>) -> GoldServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let method_requests = Arc::new(AtomicUsize::new(0));
    let adjudication_requests = Arc::new(AtomicUsize::new(0));
    let scoped_requests = Arc::new(AtomicUsize::new(0));
    let captured_requests = Arc::new(Mutex::new(Vec::new()));
    let unmatched_requests = Arc::new(Mutex::new(Vec::new()));
    let method_requests_for_server = Arc::clone(&method_requests);
    let adjudication_requests_for_server = Arc::clone(&adjudication_requests);
    let scoped_requests_for_server = Arc::clone(&scoped_requests);
    let captured_requests_for_server = Arc::clone(&captured_requests);
    let unmatched_requests_for_server = Arc::clone(&unmatched_requests);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let (mut stream, request) = read_http_request(stream);
            let prompt = request_prompt(&request);
            let batch_size = prompt.matches("METHOD KEY: ").count();
            let reviewed_methods = batch_size.max(usize::from(prompt.contains("Method source:")));
            if reviewed_methods > 0 {
                method_requests_for_server.fetch_add(reviewed_methods, Ordering::Relaxed);
                captured_requests_for_server
                    .lock()
                    .expect("capture gold request")
                    .push(request.clone());
            }
            if prompt.contains("FINAL ADJUDICATION PASS") || prompt.contains("final adjudicator") {
                adjudication_requests_for_server.fetch_add(reviewed_methods, Ordering::Relaxed);
            }
            if prompt.contains("focused dead-method adjudicator")
                || prompt.contains(
                    "final severity judge for a deterministically proven private-unused method",
                )
                || prompt.contains(
                    "judging the severity of a structurally proven behavior-neutral branch",
                )
                || prompt.contains(
                    "judging the cognitive friction of one structurally proven behavior-neutral Python parameter-discard block",
                )
            {
                scoped_requests_for_server.fetch_add(reviewed_methods, Ordering::Relaxed);
            }
            let body = if request.contains("Filename:") {
                serde_json::json!({
                    "choices": [{"message": {"content": "{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"clean\"}"}}]
                })
                .to_string()
            } else {
                let normalized_request = normalized_request(&request);
                if batch_size > 0 {
                    batch_semantic_response(
                        &prompt,
                        &cases,
                        &unmatched_requests_for_server,
                        prompt.contains("INTENT INVESTIGATION PASS"),
                    )
                } else {
                    let expected = cases.iter().find(|case| {
                        request_targets_case(&normalized_request, case)
                            && (request
                                .contains(&format!("The code is written in {}", case.language))
                                || request.contains(&format!("Language: {}", case.language))
                                || prompt.contains("focused dead-method adjudicator")
                                || prompt.contains(
                                    "final severity judge for a deterministically proven private-unused method",
                                ))
                    });
                    match expected {
                        Some(expected) => semantic_response(&request, expected),
                        None => {
                            unmatched_requests_for_server
                                .lock()
                                .expect("capture unmatched gold request")
                                .push(normalized_request);
                            let unmatched = GoldCase {
                                language: "unknown".to_string(),
                                path: "unknown".to_string(),
                                method: "unknown".to_string(),
                                tier: "unresolved".to_string(),
                                pattern: "none".to_string(),
                                evidence: String::new(),
                                explanation:
                                    "The deterministic gold server could not match the method target."
                                        .to_string(),
                                change_scope: None,
                                intentional_boundary: false,
                            };
                            semantic_response(&request, &unmatched)
                        }
                    }
                }
            };
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
    GoldServer {
        endpoint: format!("http://{}", address),
        method_requests,
        adjudication_requests,
        scoped_requests,
        captured_requests,
        unmatched_requests,
    }
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn stage_semantic_repository(root: &Path, manifest: &Manifest) -> (PathBuf, Vec<FileRecord>) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let staged_root = std::env::temp_dir().join(format!("sniff-semantic-gold-{nonce}"));
    let mut source_paths = manifest
        .cases
        .iter()
        .map(|case| case.path.clone())
        .collect::<BTreeSet<_>>();
    source_paths.insert("tests/semantic_gold_fixtures/python/intent_compat.py".to_string());

    let mut staged_paths = Vec::new();
    for source_path in source_paths {
        let destination = staged_root.join(staged_relative_path(&source_path));
        fs::create_dir_all(destination.parent().expect("staged file needs a parent"))
            .expect("create staged semantic fixture directory");
        fs::copy(root.join(&source_path), &destination)
            .unwrap_or_else(|error| panic!("stage {source_path}: {error}"));
        staged_paths.push(destination);
    }

    let mut files = staged_paths
        .iter()
        .map(|path| {
            parse_file_checked(&path.to_string_lossy())
                .unwrap_or_else(|error| panic!("parse staged {}: {error}", path.display()))
        })
        .collect::<Vec<_>>();
    let mut graph = SymbolGraph::new(&staged_root.to_string_lossy());
    for path in &staged_paths {
        graph.add_file(
            parse_file_symbols_checked(&path.to_string_lossy())
                .unwrap_or_else(|error| panic!("index staged {}: {error}", path.display())),
        );
    }
    graph.resolve_all();
    build_references(&mut files, &graph);

    (staged_root, files)
}

#[test]
fn semantic_gold_corpus_is_complete_and_parser_addressable() {
    let root = fixture_root();
    let manifest_text = fs::read_to_string(root.join("tests/semantic_gold_manifest.toml"))
        .expect("semantic gold manifest should exist");
    let manifest: Manifest = toml::from_str(&manifest_text).expect("semantic gold TOML is valid");
    let expected_languages = BTreeSet::from([
        "python".to_string(),
        "javascript".to_string(),
        "typescript".to_string(),
        "rust".to_string(),
        "go".to_string(),
        "kotlin".to_string(),
    ]);
    let mut languages = BTreeSet::new();
    let mut counts = BTreeMap::<String, usize>::new();

    for case in &manifest.cases {
        let path = root.join(&case.path);
        assert!(
            path.is_file(),
            "missing semantic gold fixture: {}",
            path.display()
        );
        let path_text = path.to_string_lossy().to_string();
        let record = parse_file(&path_text);
        let method = record
            .methods
            .iter()
            .find(|method| method.name == case.method)
            .unwrap_or_else(|| panic!("missing method {} in {}", case.method, case.path));

        assert!(["slop", "kinda_slop", "clean", "unresolved"].contains(&case.tier.as_str()));
        assert!(!case.explanation.trim().is_empty());
        if matches!(case.tier.as_str(), "clean" | "unresolved") {
            assert_eq!(case.pattern, "none");
            assert!(case.evidence.is_empty());
        } else {
            assert!(!case.evidence.is_empty());
            assert!(
                method.source.contains(&case.evidence),
                "evidence missing from {}: {}",
                case.path,
                case.evidence
            );
            assert!(case.pattern != "none");
        }
        assert!(method.loc > 0);
        languages.insert(case.language.clone());
        *counts.entry(case.language.clone()).or_default() += 1;
    }

    assert_eq!(languages, expected_languages);
    assert!(counts.values().all(|count| *count >= 2));
}

#[tokio::test]
async fn semantic_gold_corpus_runs_through_complete_method_pipeline() {
    let root = fixture_root();
    let manifest_text = fs::read_to_string(root.join("tests/semantic_gold_manifest.toml"))
        .expect("semantic gold manifest should exist");
    let manifest: Manifest = toml::from_str(&manifest_text).expect("semantic gold TOML is valid");
    let (staged_root, files) = stage_semantic_repository(&root, &manifest);
    let mut graph = SymbolGraph::new(&staged_root.to_string_lossy());
    for file in &files {
        graph.add_file(
            parse_file_symbols_checked(&file.file_path)
                .unwrap_or_else(|error| panic!("index staged {}: {error}", file.file_path)),
        );
    }
    graph.resolve_all();
    let compatibility_symbols = graph
        .files
        .iter()
        .find(|(path, _)| {
            path.replace('\\', "/")
                .ends_with("src/gold/python/intent_compat.py")
        })
        .map(|(_, symbols)| symbols)
        .expect("compatibility re-export should be indexed");
    assert!(
        compatibility_symbols
            .imports
            .iter()
            .any(|import| import.imported_name == "stable_load"),
        "compatibility import was not indexed: {:?}",
        compatibility_symbols.imports
    );

    let server = spawn_gold_server(manifest.cases.clone());
    let config = ResolvedConfig {
        thresholds: ThresholdsConfig::default(),
        ignore: vec![],
        generic_names: vec![],
        generic_file_names: vec![],
        model: "gold-test-model".to_string(),
        llm: LLMConfig {
            system_context: String::new(),
            endpoint: server.endpoint.clone(),
        },
    };
    let client = Arc::new(LLMClient::new(config, Some("gold-test-key".to_string())));
    let (analysis, _, _) = analyze_with_client_and_graph_and_journal_with_context_and_records(
        AnalysisRun {
            file_records: &files,
            context_file_records: &files,
            static_flags: &[],
            with_file_reviews: false,
            graph: Some(&graph),
            journal_path: None,
            scan_id: None,
            budget_usd: None,
            compiler_method_contexts: None,
        },
        client,
        None,
    )
    .await
    .expect("gold semantic review should complete");

    let method_verdicts = analysis
        .verdicts
        .iter()
        .filter(|verdict| verdict.check_type == "method")
        .collect::<Vec<_>>();
    let unmatched = server
        .unmatched_requests
        .lock()
        .expect("read unmatched gold prompts");
    assert!(
        unmatched.is_empty(),
        "gold server could not identify these exact method targets: {}",
        unmatched
            .iter()
            .map(|request| request
                .find("Method:")
                .map(|start| {
                    let end = (start + 300).min(request.len());
                    request[start..end].to_string()
                })
                .unwrap_or_else(|| request.chars().take(300).collect()))
            .collect::<Vec<_>>()
            .join("\n---\n")
    );
    assert_eq!(method_verdicts.len(), manifest.cases.len());
    assert_eq!(analysis.method_records.len(), manifest.cases.len());
    let benchmark_cases = manifest
        .cases
        .iter()
        .map(|case| BenchmarkCase {
            case_id: format!("{}:{}:{}", case.language, case.path, case.method),
            language: case.language.clone(),
            expected_tier: match case.tier.as_str() {
                "slop" => FindingTier::Slop,
                "kinda_slop" => FindingTier::KindaSlop,
                "clean" => FindingTier::Clean,
                "unresolved" => FindingTier::Unresolved,
                other => panic!("invalid expected tier {other}"),
            },
            expected_pattern: case.pattern.clone(),
            intentional_boundary: case.intentional_boundary,
        })
        .collect::<Vec<_>>();
    let benchmark_predictions = manifest
        .cases
        .iter()
        .map(|case| {
            let record = analysis
                .method_records
                .iter()
                .find(|record| {
                    record.method_name == case.method
                        && record.file_path.replace('\\', "/").ends_with(
                            &staged_relative_path(&case.path)
                                .to_string_lossy()
                                .replace('\\', "/"),
                        )
                })
                .unwrap_or_else(|| panic!("missing benchmark verdict for {}", case.method));
            BenchmarkPrediction {
                case_id: format!("{}:{}:{}", case.language, case.path, case.method),
                tier: record.verdict.tier,
                pattern: record.pattern.clone(),
                evidence_valid: !matches!(
                    record.verdict.tier,
                    FindingTier::Slop | FindingTier::KindaSlop
                ) || !record.evidence.is_empty(),
            }
        })
        .collect::<Vec<_>>();
    let benchmark_metrics = evaluate(&benchmark_cases, &benchmark_predictions)
        .expect("semantic gold benchmark ledger should be complete");
    assert!(benchmark_metrics.release_gate_errors().is_empty());
    assert!(benchmark_metrics.intentional_boundary_cases > 0);
    assert_eq!(
        benchmark_metrics.intentional_boundary_false_positive_rate,
        0.0
    );
    let mut slop_true_positive = 0usize;
    let mut slop_false_positive = 0usize;
    let mut slop_false_negative = 0usize;
    let mut kinda_true_positive = 0usize;
    let mut kinda_false_positive = 0usize;
    let mut unsupported_evidence = 0usize;
    for case in &manifest.cases {
        let verdict = method_verdicts
            .iter()
            .find(|verdict| {
                verdict.method_name.as_deref() == Some(case.method.as_str())
                    && verdict.file_path.replace('\\', "/").ends_with(
                        &staged_relative_path(&case.path)
                            .to_string_lossy()
                            .replace('\\', "/"),
                    )
            })
            .unwrap_or_else(|| panic!("missing gold verdict for {}", case.method));
        let expected_tier = match case.tier.as_str() {
            "slop" => FindingTier::Slop,
            "kinda_slop" => FindingTier::KindaSlop,
            "clean" => FindingTier::Clean,
            "unresolved" => FindingTier::Unresolved,
            other => panic!("invalid expected tier {other}"),
        };
        assert_eq!(
            verdict.tier, expected_tier,
            "wrong tier for {}",
            case.method
        );
        if !case.evidence.is_empty() {
            assert!(
                verdict.evidence.contains(&case.evidence),
                "missing evidence for {}: {}",
                case.path,
                verdict.evidence
            );
        }
        match (case.tier.as_str(), verdict.tier) {
            ("slop", FindingTier::Slop) => slop_true_positive += 1,
            ("slop", _) => slop_false_negative += 1,
            (_, FindingTier::Slop) => slop_false_positive += 1,
            _ => {}
        }
        match (case.tier.as_str(), verdict.tier) {
            ("kinda_slop", FindingTier::KindaSlop) => kinda_true_positive += 1,
            (_, FindingTier::KindaSlop) => kinda_false_positive += 1,
            _ => {}
        }
        if matches!(case.tier.as_str(), "slop" | "kinda_slop") && verdict.evidence.trim().is_empty()
        {
            unsupported_evidence += 1;
        }
    }

    let slop_precision =
        100 * slop_true_positive / (slop_true_positive + slop_false_positive).max(1);
    let slop_recall = 100 * slop_true_positive / (slop_true_positive + slop_false_negative).max(1);
    let kinda_precision =
        100 * kinda_true_positive / (kinda_true_positive + kinda_false_positive).max(1);
    eprintln!(
        "semantic gold metrics: Slop precision={slop_precision}%, recall={slop_recall}%, Kinda Slop precision={kinda_precision}%, unsupported evidence={unsupported_evidence}, method passes={}, adjudications={}, scoped={}",
        server.method_requests.load(Ordering::Relaxed),
        server.adjudication_requests.load(Ordering::Relaxed),
        server.scoped_requests.load(Ordering::Relaxed),
    );
    assert!(slop_precision >= 90, "Slop precision was {slop_precision}%");
    assert!(slop_recall >= 80, "Slop recall was {slop_recall}%");
    assert!(
        kinda_precision >= 80,
        "Kinda Slop precision was {kinda_precision}%"
    );
    assert_eq!(
        unsupported_evidence, 0,
        "non-clean gold findings need evidence"
    );
    assert_eq!(
        server.method_requests.load(Ordering::Relaxed),
        manifest.cases.len() * 2
            + server.adjudication_requests.load(Ordering::Relaxed)
            + server.scoped_requests.load(Ordering::Relaxed),
        "each gold method needs intent and adversarial passes, plus only applicable adjudication and scoped construct reviews"
    );
    assert!(
        server.adjudication_requests.load(Ordering::Relaxed) > 0,
        "the gold corpus must exercise disputed-method adjudication"
    );
    assert!(
        server.adjudication_requests.load(Ordering::Relaxed) < manifest.cases.len(),
        "agreed clean methods must not pay for a redundant adjudication pass"
    );
    assert!(
        server.scoped_requests.load(Ordering::Relaxed) > 0,
        "the gold corpus must exercise a focused structurally proven construct review"
    );
    let captured = server
        .captured_requests
        .lock()
        .expect("read captured gold prompts");
    assert_review_prompt_contains(
        &captured,
        "intent_contracts.py",
        "stable_load",
        &["intent_consumers.py", "intent_compat.py", "exports"],
    );
    assert_review_prompt_contains(
        &captured,
        "intent_contracts.py",
        "resolve_preview_rationale_lines",
        &[
            "callback-parameter dataflow evidence",
            "callback-parameter invocation provenance chains",
            "plan_release",
            "resolve_preview_rationale_lines_fn",
        ],
    );
    assert_review_prompt_contains(
        &captured,
        "intent_contracts.py",
        "run_with_clock",
        &["intent_consumers.py", "dependency-injection and callback"],
    );
    assert_review_prompt_contains(
        &captured,
        "intent_contracts.py",
        "emit_event",
        &["intent_tests.py", "monkeypatch.setattr"],
    );
    assert_review_prompt_contains(
        &captured,
        "intent_contracts.py",
        "metadata",
        &["interface/protocol/override evidence"],
    );
    assert_review_prompt_contains(
        &captured,
        "intent_memory_store.py",
        "metadata",
        &["same-name implementations/overrides", "intent_contracts.py"],
    );
    fs::remove_dir_all(staged_root).ok();
}

fn assert_review_prompt_contains(
    requests: &[String],
    path_suffix: &str,
    method_name: &str,
    expected_fragments: &[&str],
) {
    let request = requests
        .iter()
        .map(|request| normalized_request(request))
        .find(|request| {
            request.contains(path_suffix) && request.contains(&format!("/nMethod: {method_name} ("))
        })
        .unwrap_or_else(|| panic!("missing review prompt for {path_suffix}::{method_name}"));
    for fragment in expected_fragments {
        let evidence_excerpt = request
            .find("imports involving")
            .map(|start| {
                let end = (start + 2_000).min(request.len());
                &request[start..end]
            })
            .unwrap_or("<repository evidence section missing>");
        assert!(
            request.contains(fragment),
            "prompt for {path_suffix}::{method_name} omitted `{fragment}`; evidence excerpt: {evidence_excerpt}"
        );
    }
}
