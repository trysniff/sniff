use sniff::parser::{parse_file_checked, parse_file_symbols_checked};
use sniff::symbol_graph::SymbolGraph;
use sniff::types::{FileRecord, MethodRecord};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read repository directory") {
            let path = entry.expect("read repository entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files
}

fn method<'a>(
    records: &'a [FileRecord],
    file_suffix: &str,
    name: &str,
    source_fragment: &str,
) -> &'a MethodRecord {
    records
        .iter()
        .filter(|file| file.file_path.replace('\\', "/").ends_with(file_suffix))
        .flat_map(|file| &file.methods)
        .find(|method| method.name == name && method.source.contains(source_fragment))
        .unwrap_or_else(|| panic!("missing {file_suffix}::{name} containing {source_fragment}"))
}

fn has_caller(method: &MethodRecord, suffix: &str) -> bool {
    method
        .references
        .iter()
        .any(|reference| reference.file_path.replace('\\', "/").ends_with(suffix))
}

#[test]
fn javascript_this_member_calls_resolve_to_the_owning_class_method() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-js-this-member-{nanos}"));
    fs::create_dir_all(&root).expect("create JavaScript fixture root");
    let path = root.join("scanner.js");
    fs::write(
        &path,
        "class Scanner {\n  start() { this.scheduleScan(); }\n  scheduleScan() { return true; }\n}\nnew Scanner().start();\n",
    )
    .expect("write JavaScript fixture");
    let path_text = path.to_string_lossy().to_string();
    let mut records = vec![parse_file_checked(&path_text).expect("parse JavaScript methods")];
    let context = records.clone();
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    graph.add_file(parse_file_symbols_checked(&path_text).expect("index JavaScript symbols"));
    graph.resolve_all();
    sniff::callgraph::build_references_with_context(&mut records, &context, &graph);

    let scheduled = records[0]
        .methods
        .iter()
        .find(|method| method.name == "scheduleScan")
        .expect("scheduleScan method");
    assert_eq!(scheduled.real_ref_count, 1);
    assert_eq!(scheduled.references[0].line, 2);

    fs::remove_dir_all(root).ok();
}

#[test]
fn typescript_jsx_and_imported_object_members_resolve_to_their_definitions() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-tsx-boundaries-{nanos}"));
    fs::create_dir_all(&root).expect("create TypeScript fixture root");
    let components = root.join("components.shared.tsx");
    let deps = root.join("deps.ts");
    let consumer = root.join("consumer.tsx");
    fs::write(
        root.join("tsconfig.app.json"),
        "{\n  // Sniff must parse normal JSONC compiler configs.\n  \"compilerOptions\": {\n    \"baseUrl\": \".\",\n    \"paths\": { \"@/*\": [\"./*\"], },\n  },\n}\n",
    )
    .expect("write TypeScript config fixture");
    fs::write(
        &components,
        "function Badge() { return <span />; }\nexport { Badge };\n",
    )
    .expect("write component fixture");
    fs::write(
        &deps,
        "export const ROUTE_DEPS = {\n  get ALERT_WINDOW_SUFFIX() { return 'today'; },\n};\n",
    )
    .expect("write dependency fixture");
    fs::write(
        &consumer,
        "import { Badge } from '@/components.shared';\nimport { ROUTE_DEPS } from '@/deps';\nexport function Page() {\n  const suffix = ROUTE_DEPS.ALERT_WINDOW_SUFFIX;\n  return <Badge data-suffix={suffix} />;\n}\n",
    )
    .expect("write consumer fixture");

    let paths = [&components, &deps, &consumer];
    let mut records = paths
        .iter()
        .map(|path| {
            parse_file_checked(&path.to_string_lossy()).expect("parse TypeScript fixture methods")
        })
        .collect::<Vec<_>>();
    let context = records.clone();
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    for path in paths {
        graph.add_file(
            parse_file_symbols_checked(&path.to_string_lossy())
                .expect("index TypeScript fixture symbols"),
        );
    }
    graph.resolve_all();
    sniff::callgraph::build_references_with_context(&mut records, &context, &graph);

    let badge = method(&records, "components.shared.tsx", "Badge", "function Badge");
    assert!(badge.is_exported);
    assert_eq!(
        badge.real_ref_count, 1,
        "JSX opening tag must count as usage"
    );
    assert!(has_caller(badge, "consumer.tsx"));

    let suffix = method(&records, "deps.ts", "ALERT_WINDOW_SUFFIX", "return 'today'");
    assert_eq!(
        suffix.real_ref_count, 1,
        "imported object-member read must resolve to the getter"
    );
    assert!(has_caller(suffix, "consumer.tsx"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn typescript_parent_relative_imports_resolve_in_production_and_test_context() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-parent-import-{nanos}"));
    let core = root.join("src").join("core");
    let routes = root.join("src").join("routes");
    let tests = root.join("tests");
    fs::create_dir_all(&core).expect("create core fixture directory");
    fs::create_dir_all(&routes).expect("create routes fixture directory");
    fs::create_dir_all(&tests).expect("create test fixture directory");
    let target = core.join("state-gateway-client.ts");
    let caller = routes.join("registry.ts");
    let test = tests.join("state-gateway-client.test.ts");
    fs::write(
        &target,
        "export async function applyRegistryUpdateViaStateGateway() { return true; }\n",
    )
    .expect("write target fixture");
    fs::write(
        &caller,
        "import { applyRegistryUpdateViaStateGateway } from '../core/state-gateway-client';\nexport async function updateRegistry() { return applyRegistryUpdateViaStateGateway(); }\n",
    )
    .expect("write production caller fixture");
    fs::write(
        &test,
        "import { applyRegistryUpdateViaStateGateway } from '../src/core/state-gateway-client';\nexport async function verifiesGateway() { return applyRegistryUpdateViaStateGateway(); }\n",
    )
    .expect("write test caller fixture");

    let mut production = vec![
        parse_file_checked(&target.to_string_lossy()).expect("parse target methods"),
        parse_file_checked(&caller.to_string_lossy()).expect("parse production caller methods"),
    ];
    let mut context = production.clone();
    context.push(parse_file_checked(&test.to_string_lossy()).expect("parse test methods"));
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    for path in [&target, &caller, &test] {
        graph.add_file(
            parse_file_symbols_checked(&path.to_string_lossy())
                .expect("index TypeScript fixture symbols"),
        );
    }
    graph.resolve_all();
    sniff::callgraph::build_references_with_context(&mut production, &context, &graph);

    let gateway = method(
        &production,
        "state-gateway-client.ts",
        "applyRegistryUpdateViaStateGateway",
        "return true",
    );
    assert_eq!(gateway.real_ref_count, 2);
    assert!(has_caller(gateway, "src/routes/registry.ts"));
    assert!(has_caller(gateway, "tests/state-gateway-client.test.ts"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn jest_module_name_mapper_resolves_test_aliases_to_production_methods() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-jest-alias-{nanos}"));
    let source = root.join("ui").join("src").join("lib");
    let tests = root.join("tests");
    let runtime = root.join("ui").join("src").join("runtime");
    fs::create_dir_all(&source).expect("create source fixture directory");
    fs::create_dir_all(&tests).expect("create test fixture directory");
    fs::create_dir_all(&runtime).expect("create runtime fixture directory");
    fs::write(
        root.join("jest.config.json"),
        r#"{"moduleNameMapper":{"^@/(.*)$":"<rootDir>/ui/src/$1"}}"#,
    )
    .expect("write Jest config fixture");
    let target = source.join("profile-url.helpers.ts");
    let test = tests.join("profile-url.test.ts");
    let dynamic_caller = runtime.join("download.ts");
    fs::write(
        &target,
        "export function filterPlatformIds(ids: string[]) { return ids; }\nexport async function downloadPdfReport() { return true; }\n",
    )
    .expect("write target fixture");
    fs::write(
        &test,
        "import { filterPlatformIds } from '@/lib/profile-url.helpers';\nexport function verifiesFilter() { return filterPlatformIds([]); }\n",
    )
    .expect("write test fixture");
    fs::write(
        &dynamic_caller,
        "export async function download() {\n  const { downloadPdfReport } = await import('@/lib/profile-url.helpers');\n  return downloadPdfReport();\n}\n",
    )
    .expect("write dynamic caller fixture");

    let mut production = vec![
        parse_file_checked(&target.to_string_lossy()).expect("parse production methods"),
        parse_file_checked(&dynamic_caller.to_string_lossy()).expect("parse runtime methods"),
    ];
    let mut context = production.clone();
    context.push(parse_file_checked(&test.to_string_lossy()).expect("parse test methods"));
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    for path in [&target, &test, &dynamic_caller] {
        graph.add_file(
            parse_file_symbols_checked(&path.to_string_lossy())
                .expect("index TypeScript fixture symbols"),
        );
    }
    graph.resolve_all();
    sniff::callgraph::build_references_with_context(&mut production, &context, &graph);

    let filter = method(
        &production,
        "profile-url.helpers.ts",
        "filterPlatformIds",
        "return ids",
    );
    assert_eq!(filter.real_ref_count, 1);
    assert!(has_caller(filter, "tests/profile-url.test.ts"));

    let download = method(
        &production,
        "profile-url.helpers.ts",
        "downloadPdfReport",
        "return true",
    );
    assert_eq!(download.real_ref_count, 1);
    assert!(has_caller(download, "ui/src/runtime/download.ts"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn real_sniff_graph_preserves_rust_call_identity_and_test_evidence() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_paths = rust_files(&root.join("src"));
    let mut context_paths = source_paths.clone();
    context_paths.extend(rust_files(&root.join("tests")));

    let mut production = source_paths
        .iter()
        .map(|path| parse_file_checked(&path.to_string_lossy()).expect("parse source file"))
        .collect::<Vec<_>>();
    let context = context_paths
        .iter()
        .map(|path| parse_file_checked(&path.to_string_lossy()).expect("parse context file"))
        .collect::<Vec<_>>();
    let mut graph = SymbolGraph::new(&root.to_string_lossy());
    for path in &context_paths {
        graph.add_file(
            parse_file_symbols_checked(&path.to_string_lossy()).expect("index Rust symbols"),
        );
    }
    graph.resolve_all();
    sniff::callgraph::build_references_with_context(&mut production, &context, &graph);

    let client_raw = method(&production, "src/llm_impl.rs", "try_call_raw", "&self");
    assert!(has_caller(client_raw, "src/llm_call_policy.rs"));

    let transport_raw = method(
        &production,
        "src/llm_response.rs",
        "try_call_raw",
        "client: &reqwest::Client",
    );
    assert!(has_caller(transport_raw, "src/llm_impl.rs"));

    let getter = method(&production, "src/llm_impl.rs", "max_concurrency", "&self");
    assert!(has_caller(getter, "src/analyzer_engine_jobs.rs"));

    let configured = method(
        &production,
        "src/llm_impl.rs",
        "max_concurrency",
        "env::var",
    );
    assert!(has_caller(configured, "src/llm_impl.rs"));

    let test_path = method(
        &production,
        "src/roles_paths.rs",
        "is_test_path",
        "normalized: &str",
    );
    assert!(has_caller(test_path, "src/roles.rs"));
    assert!(has_caller(test_path, "src/roles_heuristics.rs"));

    let public_parser = method(
        &production,
        "src/parser.rs",
        "parse_file_symbols",
        "parser_impl::parse_file_symbols",
    );
    assert!(
        public_parser
            .references
            .iter()
            .any(|reference| reference.file_path.replace('\\', "/").contains("/tests/")),
        "integration tests must remain visible as evidence for the public parser API"
    );

    let contextual_review = method(
        &production,
        "src/analyzer_engine.rs",
        "analyze_method_record_with_context",
        "&self",
    );
    assert!(has_caller(contextual_review, "src/analyzer_engine_jobs.rs"));

    let batch_review = method(
        &production,
        "src/analyzer_engine.rs",
        "analyze_method_review_batch",
        "&self",
    );
    assert!(has_caller(batch_review, "src/analyzer_engine_jobs.rs"));

    let review_artifacts = method(
        &production,
        "src/cli_pipeline_llm.rs",
        "prepare_review_artifacts",
        "path: &str",
    );
    assert!(has_caller(review_artifacts, "src/cli_pipeline_run.rs"));

    let line_index = method(
        &production,
        "src/parser_impl_line_index.rs",
        "new",
        "source.char_indices()",
    );
    assert_eq!(
        line_index.references.len(),
        4,
        "LineIndex::new calls through nested `use super::*` imports must resolve exactly"
    );
    assert!(has_caller(line_index, "src/parser_impl_file_methods.rs"));
    assert!(has_caller(line_index, "src/parser_impl_file_symbols.rs"));
}
