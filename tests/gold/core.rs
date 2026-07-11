use super::*;

#[test]
fn gold_corpus_static_signals_cover_python_ts_js() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_gold"));
    copy_dir_all(&fixture_root(), &temp_root).unwrap();

    let temp_root_str = temp_root.to_string_lossy().to_string();
    let paths = walk(&temp_root_str, &ResolvedConfig::default()).unwrap();
    assert_eq!(
        paths.len(),
        12,
        "expected one helper and one consumer per language across six languages"
    );
    for suffix in [
        "go/main.go",
        "go/math.go",
        "rust/main.rs",
        "rust/math.rs",
        "kotlin/main.kt",
        "kotlin/math.kt",
    ] {
        assert!(
            paths.iter().any(|path| has_suffix(path, suffix)),
            "expected mixed corpus file {suffix} to be walked"
        );
    }

    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root_str);
    build_references(&mut file_records, &graph);

    let python_main_path = paths
        .iter()
        .find(|path| has_suffix(path, "python_main.py"))
        .unwrap();
    let python_main = graph.files.get(python_main_path).unwrap();
    let python_ref = python_main
        .references
        .iter()
        .find(|reference| reference.name == "process_data" && reference.resolved_symbol.is_some())
        .expect("python reference should resolve");
    match python_ref.resolved_symbol.as_ref().unwrap() {
        ResolvedSymbol::External { file_path, .. } => {
            assert!(has_suffix(file_path, "helpers.py"));
        }
        _ => panic!("python reference should resolve externally"),
    }

    let ts_main_path = paths
        .iter()
        .find(|path| has_suffix(path, "ts_main.ts"))
        .unwrap();
    let ts_main = graph.files.get(ts_main_path).unwrap();
    let ts_ref = ts_main
        .references
        .iter()
        .find(|reference| reference.name == "processData" && reference.resolved_symbol.is_some())
        .expect("typescript reference should resolve");
    match ts_ref.resolved_symbol.as_ref().unwrap() {
        ResolvedSymbol::External { file_path, .. } => {
            assert!(has_suffix(file_path, "helpers.ts"));
        }
        _ => panic!("typescript reference should resolve externally"),
    }

    let js_main_path = paths
        .iter()
        .find(|path| has_suffix(path, "javascript/main.js"))
        .unwrap();
    let js_main = graph.files.get(js_main_path).unwrap();
    let js_ref = js_main
        .references
        .iter()
        .find(|reference| reference.name == "processThing" && reference.resolved_symbol.is_some())
        .expect("javascript reference should resolve");
    match js_ref.resolved_symbol.as_ref().unwrap() {
        ResolvedSymbol::External { file_path, .. } => {
            assert!(has_suffix(file_path, "helpers.js"));
        }
        _ => panic!("javascript reference should resolve externally"),
    }

    let ref_flags = build_ref_count_flags(&file_records);
    assert!(
        ref_flags.iter().all(|flag| flag.tier != FindingTier::Slop),
        "expected only supporting ref-count signals: {:?}",
        ref_flags
    );
    assert!(
        ref_flags
            .iter()
            .any(|flag| flag.tier == FindingTier::KindaSlop),
        "expected at least one supporting ref-count signal: {:?}",
        ref_flags
    );

    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    assert!(
        scorer_flags
            .iter()
            .all(|flag| flag.tier != FindingTier::Slop),
        "expected the mixed corpus to stay below full slop: {:?}",
        scorer_flags
    );
    assert!(
        !scorer_flags.is_empty(),
        "expected some mixed-corpus signals to remain visible: {:?}",
        scorer_flags
    );

    let file_flags: Vec<_> = scorer_flags
        .iter()
        .filter(|flag| flag.flag_type == "file")
        .collect();
    let method_flags: Vec<_> = scorer_flags
        .iter()
        .filter(|flag| flag.flag_type == "method")
        .collect();
    assert!(file_flags.len() >= 3);
    assert_eq!(method_flags.len(), 0);

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn gold_corpus_mixed_repo_surfaces_end_to_end_without_full_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_gold_mixed_end_to_end"));
    copy_dir_all(&fixture_root(), &temp_root).unwrap();

    let temp_root_str = temp_root.to_string_lossy().to_string();
    let paths = walk(&temp_root_str, &ResolvedConfig::default()).unwrap();
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root_str);
    build_references(&mut file_records, &graph);

    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &scorer_flags, &[]);

    assert!(
        file_verdicts.len() >= 6,
        "expected the mixed corpus to yield multiple file verdicts"
    );
    assert!(
        file_verdicts
            .iter()
            .all(|verdict| verdict.verdict != FindingTier::Slop),
        "expected the mixed corpus to stay below full slop: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| !verdict.top_reasons.is_empty()),
        "expected the mixed corpus to preserve some mild friction evidence: {:?}",
        file_verdicts
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn gold_corpus_go_and_rust_routes_surface_slop_while_helpers_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_gold_go_rust"));
    fs::create_dir_all(&temp_root).unwrap();

    let go_helpers_path = write_temp_file(
        &temp_root,
        "src/go/math.go",
        "package goapp\n\nfunc processData(values []string) []string {\n    cleaned := make([]string, 0, len(values))\n    for _, value := range values {\n        cleaned = append(cleaned, value)\n    }\n    return cleaned\n}\n",
    );
    let go_routes_path = write_temp_file(
        &temp_root,
        "src/go/routes.go",
        &format!(
            "package goapp\n\n\
func triageStatusRank(status string) int {{\n    if status == \"blocked\" {{\n        return 3\n    }}\n    if status == \"warning\" {{\n        return 2\n    }}\n    if status == \"ok\" {{\n        return 1\n    }}\n    return 0\n}}\n\n\
func choosePrimaryBacklogItem(items []int) int {{\n    winner := items[0]\n    for _, item := range items {{\n        if item > winner {{\n            winner = item\n        }} else if item == winner {{\n            winner = item\n        }}\n    }}\n    return winner\n}}\n{}\n",
            branchy_go_helpers("goRoute", 19),
        ),
    );

    let rust_helpers_path = write_temp_file(
        &temp_root,
        "src/rust/math.rs",
        "pub fn process_data(values: &[&str]) -> Vec<String> {\n    values.iter().map(|value| value.trim().to_string()).collect()\n}\n",
    );
    let rust_routes_path = write_temp_file(
        &temp_root,
        "src/rust/routes.rs",
        &format!(
            "pub fn triage_status_rank(status: &str) -> i32 {{\n    if status == \"blocked\" {{\n        return 3;\n    }}\n    if status == \"warning\" {{\n        return 2;\n    }}\n    if status == \"ok\" {{\n        return 1;\n    }}\n    0\n}}\n\n\
pub fn choose_primary_backlog_item(items: &[i32]) -> i32 {{\n    let mut winner = items[0];\n    for item in items {{\n        if *item > winner {{\n            winner = *item;\n        }} else if *item == winner {{\n            winner = *item;\n        }}\n    }}\n    winner\n}}\n{}\n",
            branchy_rust_helpers("rust_route", 19),
        ),
    );

    let paths = vec![
        go_helpers_path,
        go_routes_path,
        rust_helpers_path,
        rust_routes_path,
    ];
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &scorer_flags, &[]);

    assert!(
        scorer_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("go/routes.go") && flag.tier == FindingTier::Slop),
        "Go route surface should be detected as real slop: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().any(
            |flag| flag.file_path.ends_with("rust/routes.rs") && flag.tier == FindingTier::Slop
        ),
        "Rust route surface should be detected as real slop: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags
            .iter()
            .all(|flag| !flag.file_path.ends_with("go/helpers.go")
                && !flag.file_path.ends_with("go/math.go")
                && !flag.file_path.ends_with("rust/math.rs")),
        "Go/Rust helper surfaces should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("go/routes.go")
                && verdict.verdict == FindingTier::Slop),
        "Go route surface should remain a slop verdict: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("rust/routes.rs")
                && verdict.verdict == FindingTier::Slop),
        "Rust route surface should remain a slop verdict: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("go/math.go")
                && verdict.verdict == FindingTier::Clean),
        "Go helper surface should stay clean in final verdicts: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("rust/math.rs")
                && verdict.verdict == FindingTier::Clean),
        "Rust helper surface should stay clean in final verdicts: {:?}",
        file_verdicts
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn package_facades_stay_clean_while_implementation_modules_surface_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_gold_facades"));
    fs::create_dir_all(&temp_root).unwrap();

    let python_facade_path = write_temp_file(
        &temp_root,
        "src/python_pkg/__init__.py",
        "from .impl import build_payload, render_summary\n",
    );
    let python_impl_path = write_temp_file(
        &temp_root,
        "src/python_pkg/impl.py",
        &format!(
            "def build_payload(value):\n    data = {{\"value\": value}}\n{}\n    return data\n\n\
def render_summary(payload):\n    if payload.get(\"kind\") == \"alpha\":\n        return \"alpha\"\n    if payload.get(\"kind\") == \"beta\":\n        return \"beta\"\n    if payload.get(\"kind\") == \"gamma\":\n        return \"gamma\"\n    return \"unknown\"\n",
            branchy_python_helpers("python_impl", 18),
        ),
    );

    let ts_facade_path =
        write_temp_file(&temp_root, "src/web/index.ts", "export * from './impl';\n");
    let ts_impl_path = write_temp_file(
        &temp_root,
        "src/web/impl.ts",
        &format!(
            "export function buildPayload(value: number) {{\n  const payload = {{ value }};\n  return payload;\n}}\n\n\
export function renderSummary(payload: {{ kind?: string }}) {{\n  if (payload.kind === 'alpha') return 'alpha';\n  if (payload.kind === 'beta') return 'beta';\n  if (payload.kind === 'gamma') return 'gamma';\n  return 'unknown';\n}}\n{}\n",
            branchy_typescript_helpers("webImpl", 18),
        ),
    );

    let rust_facade_path = write_temp_file(
        &temp_root,
        "src/rust/lib.rs",
        "pub mod impls;\npub use impls::{build_payload, render_summary};\n",
    );
    let rust_impl_path = write_temp_file(
        &temp_root,
        "src/rust/impls.rs",
        &format!(
            "pub fn build_payload(value: i32) -> i32 {{ value }}\n\npub fn render_summary(kind: &str) -> &str {{\n    if kind == \"alpha\" {{ return \"alpha\"; }}\n    if kind == \"beta\" {{ return \"beta\"; }}\n    if kind == \"gamma\" {{ return \"gamma\"; }}\n    \"unknown\"\n}}\n{}\n",
            branchy_rust_helpers("rust_impl", 18),
        ),
    );

    let file_records = parse_records(&[
        python_facade_path.clone(),
        python_impl_path.clone(),
        ts_facade_path.clone(),
        ts_impl_path.clone(),
        rust_facade_path.clone(),
        rust_impl_path.clone(),
    ]);
    let mut file_records = file_records;
    let graph = build_graph(
        &[
            python_facade_path,
            python_impl_path,
            ts_facade_path,
            ts_impl_path,
            rust_facade_path,
            rust_impl_path,
        ],
        &temp_root.to_string_lossy(),
    );
    build_references(&mut file_records, &graph);

    let ref_flags = build_ref_count_flags(&file_records);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &scorer_flags, &[]);

    assert!(
        ref_flags.iter().all(|flag| {
            !flag.file_path.ends_with("__init__.py")
                && !flag.file_path.ends_with("index.ts")
                && !flag.file_path.ends_with("lib.rs")
        }),
        "package facades should not create orphaned-export noise: {:?}",
        ref_flags
    );
    assert!(
        ref_flags.iter().any(|flag| {
            flag.file_path.ends_with("impl.py")
                || flag.file_path.ends_with("impl.ts")
                || flag.file_path.ends_with("impls.rs")
        }),
        "implementation modules should surface ref-count noise: {:?}",
        ref_flags
    );
    assert!(
        scorer_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("impl.py") && flag.tier != FindingTier::Clean),
        "python implementation should surface as non-clean code: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("impl.ts") && flag.tier != FindingTier::Clean),
        "typescript implementation should surface as non-clean code: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("impls.rs") && flag.tier != FindingTier::Clean),
        "rust implementation should surface as non-clean code: {:?}",
        scorer_flags
    );
    assert!(
        scorer_flags.iter().all(|flag| {
            !flag.file_path.ends_with("__init__.py")
                && !flag.file_path.ends_with("index.ts")
                && !flag.file_path.ends_with("lib.rs")
        }),
        "package facades should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("impl.py")
                && verdict.verdict != FindingTier::Clean),
        "python implementation should remain a non-clean verdict: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("impl.ts")
                && verdict.verdict != FindingTier::Clean),
        "typescript implementation should remain a non-clean verdict: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts
            .iter()
            .any(|verdict| verdict.file_path.ends_with("impls.rs")
                && verdict.verdict != FindingTier::Clean),
        "rust implementation should remain a non-clean verdict: {:?}",
        file_verdicts
    );
    assert!(
        file_verdicts.iter().all(|verdict| {
            !verdict.file_path.ends_with("__init__.py")
                && !verdict.file_path.ends_with("index.ts")
                && !verdict.file_path.ends_with("lib.rs")
        }),
        "package facades should not appear in non-clean verdicts: {:?}",
        file_verdicts
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn intentional_entrypoints_and_examples_are_not_flagged_as_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_roles"));
    let scripts_dir = temp_root.join("scripts");
    let examples_dir = scripts_dir.join("examples");
    fs::create_dir_all(&examples_dir).unwrap();

    let script_path = scripts_dir.join("run_app_server.py");
    let example_path = examples_dir.join("webhook_framework_apps.py");
    fs::write(&script_path, "def main():\n    return 0\n").unwrap();
    fs::write(
        &example_path,
        "def create_fastapi_app():\n    return object()\n",
    )
    .unwrap();

    let script_path_str = script_path.to_string_lossy().to_string();
    let example_path_str = example_path.to_string_lossy().to_string();

    let mut file_records = vec![parse_file(&script_path_str), parse_file(&example_path_str)];
    let mut graph = SymbolGraph::new(&temp_root.to_string_lossy());
    graph.add_file(parse_file_symbols(&script_path_str));
    graph.add_file(parse_file_symbols(&example_path_str));
    graph.resolve_all();
    build_references(&mut file_records, &graph);

    let ref_flags = build_ref_count_flags(&file_records);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        ref_flags.is_empty(),
        "intentional surfaces should not be orphaned-export noise: {:?}",
        ref_flags
    );
    assert!(
        scorer_flags.is_empty(),
        "intentional surfaces should not be scored as slop: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn kotlin_design_and_compose_support_surfaces_stay_non_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_kotlin_support_surfaces"));
    fs::create_dir_all(&temp_root).unwrap();

    let design_path = write_temp_file(
        &temp_root,
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/design/PillitDesignTokens.kt",
        "package com.onpill.shared.uicontract.design\n\npublic object OnPillColors { public val primary: Long = 0xFFF27121L }\npublic object OnPillSpacing { public val m: Int = 16 }\npublic object OnPillStrings { public val appName: String = \"OnPill\" }\npublic object OnPillTypography { public val body: Int = 16 }\n",
    );
    let components_path = write_temp_file(
        &temp_root,
        "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt",
        "package com.onpill.shared.uicompose.components\n\n@Composable\npublic fun OnPillCard() {}\n@Composable\npublic fun OnPillButton() {}\n@Composable\npublic fun OnPillHeader() {}\npublic object OnPillSemanticColors { public val warning: Int = 0 }\n",
    );
    let details_path = write_temp_file(
        &temp_root,
        "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt",
        "package com.onpill.shared.uicompose.screens\n\n@Composable\npublic fun OnPillMedicationDetailsScreen() {}\nprivate fun com.onpill.shared.uicontract.MedicationScheduleTimeUiState.label(): String = \"\"\n",
    );

    let paths = vec![design_path, components_path, details_path];
    let file_records = parse_records(&paths);
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    for suffix in [
        "PillitDesignTokens.kt",
        "PillitComponents.kt",
        "PillitMedicationDetailsScreen.kt",
    ] {
        assert!(
            file_verdicts
                .iter()
                .any(|verdict| has_suffix(&verdict.file_path, suffix)
                    && verdict.verdict != FindingTier::Slop),
            "{suffix} should not be reported as slop: {:?}",
            file_verdicts
        );
        assert!(
            static_flags
                .iter()
                .all(|flag| !has_suffix(&flag.file_path, suffix) || flag.tier != FindingTier::Slop),
            "{suffix} should not trigger static slop: {:?}",
            static_flags
        );
    }

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn broad_library_files_do_not_auto_promote_file_sprawl_from_one_smelly_method() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_broad_library_sprawl"));
    fs::create_dir_all(&temp_root).unwrap();

    let file_path = write_temp_file(
        &temp_root,
        "src/service.py",
        &format!(
            "def simple_{:02}():\n    return 1\n\n{}\
def orchestrate(value):\n    if value == 0:\n        return 0\n    if value == 1:\n        return 1\n    if value == 2:\n        return 2\n    if value == 3:\n        return 3\n    if value == 4:\n        return 4\n    return value\n",
            0,
            (1..21)
                .map(|idx| format!("def simple_{idx:02}():\n    return {idx}\n\n", idx = idx))
                .collect::<String>(),
        ),
    );

    let file_records = parse_records(std::slice::from_ref(&file_path));
    let static_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = build_file_verdicts(&file_records, &static_flags, &[]);

    assert!(
        !static_flags
            .iter()
            .any(|flag| flag.file_path.ends_with("service.py") && flag.flag_type == "file"),
        "one smelly method should not auto-promote file sprawl: {:?}",
        static_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert!(
        file_verdicts[0]
            .flagged_methods
            .iter()
            .any(|method| method == "orchestrate"),
        "the smelly method should still be visible: {:?}",
        file_verdicts[0]
    );
    assert!(
        !file_verdicts[0]
            .top_reasons
            .iter()
            .any(|reason| reason.contains("file does too much")),
        "file sprawl should not be inferred from one smelly method: {:?}",
        file_verdicts[0]
    );

    fs::remove_dir_all(&temp_root).ok();
}
