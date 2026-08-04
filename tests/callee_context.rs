use sniff::callgraph::build_callee_context;
use sniff::config::{LLMConfig, ResolvedConfig, ThresholdsConfig};
use sniff::parser::{parse_file_checked, parse_file_symbols_checked};
use sniff::symbol_graph::SymbolGraph;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn resolved_callee_context_reaches_the_calling_method() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-callee-context-{nonce}"));
    let package = root.join("src");
    fs::create_dir_all(&package).expect("create fixture directory");
    let caller_path = package.join("caller.py");
    let callee_path = package.join("callee.py");
    fs::write(
        &caller_path,
        "from .callee import compute\n\ndef run(value):\n    return compute(value)\n",
    )
    .expect("write caller fixture");
    fs::write(&callee_path, "def compute(value):\n    return value + 1\n")
        .expect("write callee fixture");

    let caller_path = caller_path.to_string_lossy().to_string();
    let callee_path = callee_path.to_string_lossy().to_string();
    let files = vec![
        parse_file_checked(&caller_path).expect("parse caller fixture"),
        parse_file_checked(&callee_path).expect("parse callee fixture"),
    ];
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    graph.add_file(parse_file_symbols_checked(&caller_path).expect("index caller fixture"));
    graph.add_file(parse_file_symbols_checked(&callee_path).expect("index callee fixture"));
    graph.resolve_all();

    let contexts = build_callee_context(&files, &graph);
    let context = contexts
        .get(&(caller_path.clone(), "run".to_string(), 3))
        .expect("run should have a resolved callee");
    assert_eq!(context.len(), 1);
    assert_eq!(context[0].file_path, callee_path);
    assert_eq!(context[0].line, 1);
    assert!(context[0].snippet.contains("Callee Method: compute"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn module_qualified_python_reference_counts_as_a_real_use() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-qualified-reference-{nonce}"));
    let src = root.join("src");
    let analysis = src.join("bumpkin").join("analysis");
    fs::create_dir_all(&analysis).expect("create fixture directory");
    let callee_path = analysis.join("diff_git.py");
    let caller_path = src.join("diff.py");
    fs::write(
        &callee_path,
        "def run_command(args):\n    return args\n\ndef run_git(args):\n    return args\n",
    )
    .expect("write callee fixture");
    fs::write(
        &caller_path,
        "from bumpkin.analysis import diff_git\n\ndef run_command_adapter(args):\n    return diff_git.run_command(args)\n",
    )
    .expect("write caller fixture");

    let caller_path = caller_path.to_string_lossy().to_string();
    let callee_path = callee_path.to_string_lossy().to_string();
    let mut files = vec![
        parse_file_checked(&caller_path).expect("parse caller fixture"),
        parse_file_checked(&callee_path).expect("parse callee fixture"),
    ];
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    graph.add_file(parse_file_symbols_checked(&caller_path).expect("index caller fixture"));
    graph.add_file(parse_file_symbols_checked(&callee_path).expect("index callee fixture"));
    graph.resolve_all();
    sniff::callgraph::build_references(&mut files, &graph);
    sniff::callgraph::build_references(&mut files, &graph);

    let callee = files[1]
        .methods
        .iter()
        .find(|method| method.name == "run_command")
        .expect("run_command should be parsed");
    assert_eq!(callee.real_ref_count, 1);
    assert_eq!(callee.references[0].file_path, caller_path);

    fs::remove_dir_all(root).ok();
}

#[test]
fn context_only_rust_tests_count_as_real_callers_without_becoming_targets() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-rust-test-context-{nonce}"));
    let src = root.join("src");
    let tests = root.join("tests");
    fs::create_dir_all(&src).expect("create source directory");
    fs::create_dir_all(&tests).expect("create tests directory");
    let lib_path = src.join("lib.rs");
    let api_path = src.join("api.rs");
    let test_path = tests.join("api_contract.rs");
    fs::write(&lib_path, "pub mod api;\n").expect("write library root");
    fs::write(&api_path, "pub fn parse_file_symbols() -> bool { true }\n")
        .expect("write API fixture");
    fs::write(
        &test_path,
        "use crate::api::parse_file_symbols;\n\n#[test]\nfn public_api_contract() {\n    assert!(parse_file_symbols());\n}\n",
    )
    .expect("write integration test fixture");

    let lib_path = lib_path.to_string_lossy().to_string();
    let api_path = api_path.to_string_lossy().to_string();
    let test_path = test_path.to_string_lossy().to_string();
    let mut production = vec![
        parse_file_checked(&lib_path).expect("parse library root"),
        parse_file_checked(&api_path).expect("parse API fixture"),
    ];
    let test_record = parse_file_checked(&test_path).expect("parse test fixture");
    let mut context = production.clone();
    context.push(test_record);

    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    for path in [&lib_path, &api_path, &test_path] {
        graph.add_file(parse_file_symbols_checked(path).expect("index Rust fixture"));
    }
    graph.resolve_all();
    sniff::callgraph::build_references_with_context(&mut production, &context, &graph);

    let api = production[1]
        .methods
        .iter()
        .find(|method| method.name == "parse_file_symbols")
        .expect("public API must be parsed");
    assert_eq!(api.real_ref_count, 1);
    assert_eq!(api.references[0].file_path, test_path);

    fs::remove_dir_all(root).ok();
}

#[test]
fn same_file_javascript_calls_count_as_real_references() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-js-local-reference-{nonce}"));
    fs::create_dir_all(&root).expect("create fixture directory");
    let path = root.join("extractor.ts");
    fs::write(
        &path,
        "function push_method(methods: unknown[], method: unknown) {\n    methods.push(method);\n}\n\nfunction visit() {\n    push_method([], {});\n}\n",
    )
    .expect("write fixture");

    let path = path.to_string_lossy().to_string();
    let mut files = vec![parse_file_checked(&path).expect("parse fixture")];
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    graph.add_file(parse_file_symbols_checked(&path).expect("index fixture"));
    graph.resolve_all();
    sniff::callgraph::build_references(&mut files, &graph);

    let helper = files[0]
        .methods
        .iter()
        .find(|method| method.name == "push_method")
        .expect("push_method should be parsed");
    assert_eq!(helper.real_ref_count, 1);
    assert!(!helper.references[0].snippet.is_empty());

    fs::remove_dir_all(root).ok();
}

#[test]
fn imported_typescript_functions_count_as_real_references() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-import-reference-{nonce}"));
    let src = root.join("src");
    fs::create_dir_all(&src).expect("create fixture directory");
    let callee_path = src.join("guard.ts");
    let caller_path = src.join("controller.ts");
    fs::write(
        &callee_path,
        "export function clearSessionGuardNoticeState() {\n    return null;\n}\n",
    )
    .expect("write callee fixture");
    fs::write(
        &caller_path,
        "import { clearSessionGuardNoticeState } from './guard';\n\nexport function clearGuardNotice() {\n    return clearSessionGuardNoticeState();\n}\n",
    )
    .expect("write caller fixture");

    let caller_path = caller_path.to_string_lossy().to_string();
    let callee_path = callee_path.to_string_lossy().to_string();
    let mut files = vec![
        parse_file_checked(&caller_path).expect("parse caller fixture"),
        parse_file_checked(&callee_path).expect("parse callee fixture"),
    ];
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    graph.add_file(parse_file_symbols_checked(&caller_path).expect("index caller fixture"));
    graph.add_file(parse_file_symbols_checked(&callee_path).expect("index callee fixture"));
    graph.resolve_all();
    sniff::callgraph::build_references(&mut files, &graph);
    sniff::callgraph::build_references(&mut files, &graph);

    let callee = files[1]
        .methods
        .iter()
        .find(|method| method.name == "clearSessionGuardNoticeState")
        .expect("callee should be parsed");
    assert_eq!(callee.real_ref_count, 1);
    assert_eq!(callee.references.len(), 1);
    assert_eq!(callee.references[0].file_path, caller_path);
    assert!(
        callee.references[0]
            .snippet
            .contains("Caller Method: clearGuardNotice")
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn multiline_and_aliased_typescript_imports_resolve_real_references() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-multiline-import-{nonce}"));
    let src = root.join("src");
    fs::create_dir_all(&src).expect("create fixture directory");
    let callee_path = src.join("accepted-session-state.ts");
    let caller_path = src.join("session-state-coordinator.ts");
    let bridge_path = src.join("service-worker-support.ts");
    fs::write(
        &callee_path,
        "export function buildAcceptedSessionReservedState() {\n    return { status: 'starting' };\n}\n\nexport function deriveFeedbackContextFromSender() {\n    return null;\n}\n",
    )
    .expect("write callee fixture");
    fs::write(
        &caller_path,
        "import {\n    buildAcceptedSessionReservedState,\n} from './accepted-session-state';\n\nexport function reserveSession() {\n    return buildAcceptedSessionReservedState();\n}\n",
    )
    .expect("write direct multiline caller fixture");
    fs::write(
        &bridge_path,
        "import {\n    deriveFeedbackContextFromSender as deriveFeedbackContextFromSenderImpl,\n} from './accepted-session-state';\n\nexport function deriveFeedbackContextFromSender() {\n    return deriveFeedbackContextFromSenderImpl();\n}\n",
    )
    .expect("write aliased multiline caller fixture");

    let callee_path = callee_path.to_string_lossy().to_string();
    let caller_path = caller_path.to_string_lossy().to_string();
    let bridge_path = bridge_path.to_string_lossy().to_string();
    let mut files = vec![
        parse_file_checked(&caller_path).expect("parse direct caller fixture"),
        parse_file_checked(&bridge_path).expect("parse aliased caller fixture"),
        parse_file_checked(&callee_path).expect("parse callee fixture"),
    ];
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    for path in [&caller_path, &bridge_path, &callee_path] {
        graph.add_file(parse_file_symbols_checked(path).expect("index TypeScript fixture"));
    }
    graph.resolve_all();
    sniff::callgraph::build_references(&mut files, &graph);

    let reserved = files[2]
        .methods
        .iter()
        .find(|method| method.name == "buildAcceptedSessionReservedState")
        .expect("reserved-state builder should be parsed");
    assert_eq!(reserved.real_ref_count, 1);
    assert_eq!(reserved.references[0].file_path, caller_path);

    let feedback = files[2]
        .methods
        .iter()
        .find(|method| method.name == "deriveFeedbackContextFromSender")
        .expect("feedback helper should be parsed");
    assert_eq!(feedback.real_ref_count, 1);
    assert_eq!(feedback.references[0].file_path, bridge_path);

    fs::remove_dir_all(root).ok();
}

#[test]
#[ignore = "set SNIFF_LIVE_TS_REPO to run against a real TypeScript repository"]
fn live_typescript_repository_resolves_nested_methods_and_imported_callers() {
    let root = std::env::var("SNIFF_LIVE_TS_REPO")
        .expect("SNIFF_LIVE_TS_REPO must name a TypeScript repository");
    let config = ResolvedConfig {
        thresholds: ThresholdsConfig::default(),
        ignore: vec![],
        generic_names: vec![],
        generic_file_names: vec![],
        model: "live-graph-only".to_string(),
        llm: LLMConfig {
            system_context: String::new(),
            endpoint: "http://127.0.0.1:0".to_string(),
        },
    };
    let paths = sniff::walker::walk(&root, &config).expect("walk live TypeScript repository");
    let paths = paths
        .into_iter()
        .filter(|path| {
            [".ts", ".tsx", ".js", ".jsx"]
                .iter()
                .any(|extension| path.ends_with(extension))
        })
        .collect::<Vec<_>>();

    let mut files = paths
        .iter()
        .map(|path| parse_file_checked(path).expect("parse live TypeScript source"))
        .collect::<Vec<_>>();
    let mut graph = SymbolGraph::new(&root);
    for path in &paths {
        graph.add_file(parse_file_symbols_checked(path).expect("index live TypeScript source"));
    }
    graph.resolve_all();
    sniff::callgraph::build_references(&mut files, &graph);

    let method = |suffix: &str, name: &str| {
        files
            .iter()
            .find(|file| file.file_path.replace('\\', "/").ends_with(suffix))
            .and_then(|file| file.methods.iter().find(|method| method.name == name))
            .unwrap_or_else(|| panic!("missing live method {suffix}::{name}"))
    };

    for expected in [
        "createCheckoutRpc",
        "invokeCheckoutFunction",
        "createCheckoutSessionInBackground",
    ] {
        method("ui/background/core/checkout-rpc.ts", expected);
    }
    assert!(
        method(
            "ui/background/core/crypto-feedback.ts",
            "deriveFeedbackContextFromSender"
        )
        .real_ref_count
            > 0
    );
    for expected in [
        "buildAcceptedSessionAttachedState",
        "buildAcceptedSessionReservedState",
    ] {
        assert!(
            method("ui/background/core/accepted-session-state.ts", expected).real_ref_count > 0,
            "expected a resolved caller for {expected}"
        );
    }

    let method_count = files.iter().map(|file| file.methods.len()).sum::<usize>();
    eprintln!(
        "live TypeScript graph: {} files, {} methods",
        files.len(),
        method_count
    );
}

#[test]
fn sniff_javascript_extractor_helper_has_resolved_local_callers() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/parser_impl/js_ts_extractor.rs");
    let path = path.to_string_lossy().to_string();
    let mut files = vec![parse_file_checked(&path).expect("parse Sniff extractor")];
    let mut graph = SymbolGraph::new(env!("CARGO_MANIFEST_DIR"));
    graph.add_file(parse_file_symbols_checked(&path).expect("index Sniff extractor"));
    graph.resolve_all();
    sniff::callgraph::build_references(&mut files, &graph);

    let helper = files[0]
        .methods
        .iter()
        .find(|method| method.name == "push_method")
        .expect("push_method should be parsed in Sniff itself");
    assert!(
        helper.real_ref_count >= 2,
        "expected both local calls to resolve, got {}",
        helper.real_ref_count
    );
}
