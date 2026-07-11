use super::*;

#[test]
fn javascript_support_helpers_stay_clean_while_routes_stay_flagged() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_javascript_support"));
    let routes_dir = temp_root.join("src").join("routes");
    let utils_dir = temp_root.join("src").join("utils");
    fs::create_dir_all(&routes_dir).unwrap();
    fs::create_dir_all(&utils_dir).unwrap();

    write_temp_file(
        &routes_dir,
        "ops.js",
        r#"
export function triageStatusRank(status) {
  if (status === "blocked") return 3;
  if (status === "warning") return 2;
  if (status === "ok") return 1;
  return 0;
}

export function choosePrimaryBacklogItem(items) {
  let winner = items[0];
  for (const item of items) {
    if (item.score > winner.score) {
      winner = item;
    } else if (item.score === winner.score && item.rank > winner.rank) {
      winner = item;
    }
  }
  return winner;
}
"#,
    );

    write_temp_file(
        &utils_dir,
        "math.js",
        r#"
export function add(a, b) {
  return a + b;
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags
            .iter()
            .any(|flag| flag.file_path.ends_with("ops.js") && flag.tier != FindingTier::Clean),
        "the JavaScript route module should still be flagged as noisy: {:?}",
        flags
    );
    assert!(
        !flags
            .iter()
            .any(|flag| flag.file_path.ends_with("math.js") && flag.tier != FindingTier::Clean),
        "the small JavaScript helper should stay clean: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn nextjs_and_ui_surface_modules_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_ui_surfaces"));
    let src_dir = temp_root.join("src");
    let app_dir = src_dir.join("app");
    let components_dir = src_dir.join("components");
    let sections_dir = components_dir.join("sections");
    let modals_dir = components_dir.join("modals");
    let templates_dir = components_dir.join("templates");
    fs::create_dir_all(app_dir.join("privacy")).unwrap();
    fs::create_dir_all(app_dir.join("terms")).unwrap();
    fs::create_dir_all(&sections_dir).unwrap();
    fs::create_dir_all(&modals_dir).unwrap();
    fs::create_dir_all(&templates_dir).unwrap();

    write_temp_file(
        &app_dir.join("privacy"),
        "page.tsx",
        r#"
export default function PrivacyPage() {
    return <main><h1>Privacy</h1><p>Policy text</p></main>;
}
"#,
    );

    write_temp_file(
        &app_dir.join("terms"),
        "page.tsx",
        r#"
export default function TermsPage() {
    return <main><h1>Terms</h1><p>Policy text</p></main>;
}
"#,
    );

    write_temp_file(
        &sections_dir,
        "Hero.tsx",
        r#"
export function Hero() {
    return <section><h1>Hero</h1><p>Intro text</p></section>;
}
"#,
    );

    write_temp_file(
        &templates_dir,
        "PlatformTemplate.tsx",
        r#"
export function PlatformTemplate({ children }) {
    return <div className="platform">{children}</div>;
}
"#,
    );

    write_temp_file(
        &modals_dir,
        "ContactModal.tsx",
        r#"
export function ContactModal() {
    return <dialog open><form><button type="submit">Send</button></form></dialog>;
}
"#,
    );

    write_temp_file(
        &sections_dir,
        "BrandStore.tsx",
        r#"
export function BrandStore() {
    return <section><article><h2>Brand Store</h2></article></section>;
}
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    assert!(
        scorer_flags.is_empty(),
        "presentation surfaces should stay clean: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn cli_and_adapter_integration_surfaces_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_cli_adapter"));
    let src_dir = temp_root.join("src");
    let release_dir = src_dir.join("bumpkin").join("release");
    fs::create_dir_all(&release_dir).unwrap();

    write_temp_file(
        &src_dir,
        "corpus_cli.py",
        r#"
from __future__ import annotations

import argparse


def main():
    parser = argparse.ArgumentParser()
    return parser
"#,
    );

    write_temp_file(
        &release_dir,
        "repository_client.py",
        r#"
from __future__ import annotations


class GitHubRepositoryClient:
    def list_tags(self):
        return []

    def compare_commits(self, *, base_ref, head_ref):
        return []

    def list_pull_requests_for_commit(self, commit_sha):
        return []

    def get_pull_request(self, number):
        return number
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    assert!(
        scorer_flags.is_empty(),
        "CLI and adapter integration surfaces should stay clean: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn hydration_hooks_stay_clean() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_hydration_hook"));
    let src_dir = temp_root.join("src").join("hooks");
    fs::create_dir_all(&src_dir).unwrap();

    write_temp_file(
        &src_dir,
        "useHasMounted.ts",
        r#"
import { useState, useEffect } from 'react';

export const useHasMounted = () => {
    const [hasMounted, setHasMounted] = useState(false);

    useEffect(() => {
        const timer = setTimeout(() => setHasMounted(true), 0);
        return () => clearTimeout(timer);
    }, []);

    return hasMounted;
};
"#,
    );

    let paths = walk(&temp_root.to_string_lossy(), &ResolvedConfig::default()).unwrap();
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    assert!(
        scorer_flags.is_empty(),
        "hydration hooks should stay clean: {:?}",
        scorer_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn rust_qualified_and_method_calls_resolve_cleanly() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_rust_refs"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let reporter_file = write_temp_file(
        &src_dir,
        "reporter.rs",
        r#"
#[path = "reporter_helpers.rs"]
pub mod helpers;
"#,
    );
    let reporter_helpers_file = write_temp_file(
        &src_dir,
        "reporter_helpers.rs",
        r#"
pub fn render_report() {
}
"#,
    );
    let symbol_graph_file = write_temp_file(
        &src_dir,
        "symbol_graph_impl.rs",
        r#"
pub fn resolve_all() {
}
"#,
    );
    let cli_file = write_temp_file(
        &src_dir,
        "cli.rs",
        r#"
pub fn run() {
    crate::reporter::helpers::render_report();
    let graph = crate::symbol_graph_impl::resolve_all();
    graph.resolve_all();
}
"#,
    );

    let paths = vec![
        reporter_file,
        reporter_helpers_file,
        symbol_graph_file,
        cli_file,
    ];
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        scorer_flags.iter().all(|flag| {
            !flag.file_path.ends_with("reporter_helpers.rs")
                && !flag.file_path.ends_with("symbol_graph_impl.rs")
        }),
        "focused Rust helper modules should stay clean: {:?}",
        scorer_flags
    );

    let cli_symbols = graph.files.get(&paths[3]).unwrap();
    let render_refs: Vec<_> = cli_symbols
        .references
        .iter()
        .filter(|reference| reference.name.contains("render_report"))
        .collect();
    assert!(!render_refs.is_empty());
    assert!(
        render_refs
            .iter()
            .any(|reference| reference.resolved_symbol.is_some()),
        "qualified Rust references should resolve"
    );

    let resolve_refs: Vec<_> = cli_symbols
        .references
        .iter()
        .filter(|reference| reference.name.contains("resolve_all"))
        .collect();
    assert!(!resolve_refs.is_empty());
    assert!(
        resolve_refs
            .iter()
            .any(|reference| reference.resolved_symbol.is_some()),
        "dot-call Rust method references should resolve"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn supporting_layers_detect_duplication_architecture_test_coupling_and_provenance() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_supporting"));
    let tests_dir = temp_root.join("tests");
    fs::create_dir_all(&tests_dir).unwrap();

    let dup_a = temp_root.join("dup_a.py");
    let dup_b = temp_root.join("dup_b.py");
    let test_dup = tests_dir.join("test_dup.py");
    let generated = temp_root.join("generated.py");
    let marker = temp_root.join("marker.py");
    let generated_str = generated.to_string_lossy().to_string();
    let duplicate_body = "def compute(data):\n    cleaned = data.strip()\n    normalized = cleaned.lower()\n    return normalized\n";
    fs::write(&dup_a, duplicate_body).unwrap();
    fs::write(&dup_b, duplicate_body).unwrap();
    fs::write(&test_dup, duplicate_body).unwrap();
    fs::write(
        &generated,
        "# auto-generated\n\ndef make_value():\n    return 1\n",
    )
    .unwrap();
    fs::write(
        &marker,
        "# auto-generated\n\ndef make_value():\n    return 1\n",
    )
    .unwrap();

    for i in 0..5 {
        fs::write(
            temp_root.join(format!("helper{i}.py")),
            format!("def step{i}():\n    return {i}\n"),
        )
        .unwrap();
    }

    let mut orchestrator = String::new();
    for i in 0..5 {
        orchestrator.push_str(&format!("from helper{i} import step{i}\n"));
    }
    orchestrator.push('\n');
    orchestrator.push_str("def run():\n");
    for i in 0..5 {
        orchestrator.push_str(&format!("    step{i}()\n"));
    }
    for i in 0..9 {
        orchestrator.push_str(&format!("\ndef helper_{i}():\n    return {i}\n"));
    }
    fs::write(temp_root.join("orchestrator.py"), orchestrator).unwrap();

    let paths = vec![
        dup_a,
        dup_b,
        test_dup,
        generated,
        marker,
        temp_root.join("helper0.py"),
        temp_root.join("helper1.py"),
        temp_root.join("helper2.py"),
        temp_root.join("helper3.py"),
        temp_root.join("helper4.py"),
        temp_root.join("orchestrator.py"),
    ]
    .into_iter()
    .map(|path| path.to_string_lossy().to_string())
    .collect::<Vec<_>>();

    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let flags = sniff::signal_layers::collect_supporting_flags(
        &file_records,
        &ResolvedConfig::default(),
        &temp_root,
    );

    assert!(
        count_gate(&flags, "duplication") >= 1,
        "expected duplication flag: {:?}",
        flags
    );
    assert!(
        count_gate(&flags, "test_coupling") >= 1,
        "expected test coupling flag: {:?}",
        flags
    );
    assert!(
        count_gate(&flags, "architecture") >= 1,
        "expected architecture flag: {:?}",
        flags
    );
    assert!(
        count_gate(&flags, "provenance") >= 1,
        "expected provenance flag: {:?}",
        flags
    );
    assert!(
        !flags.iter().any(|flag| flag.file_path == generated_str),
        "generated surfaces should be skipped entirely: {:?}",
        flags
    );
    assert_eq!(
        flags
            .iter()
            .filter(|flag| flag.tier == FindingTier::Slop)
            .count(),
        0,
        "supporting layers should not emit final Slop verdicts: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_private_helpers_stay_private() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_private"));
    fs::create_dir_all(&temp_root).unwrap();

    let private_file = temp_root.join("python_main.py");
    fs::write(&private_file, "def _run():\n    return 0\n").unwrap();

    let private_file_str = private_file.to_string_lossy().to_string();
    let file_records = vec![parse_file(&private_file_str)];
    let graph = build_graph(
        std::slice::from_ref(&private_file_str),
        &temp_root.to_string_lossy(),
    );
    let mut file_records = file_records;
    build_references(&mut file_records, &graph);

    let ref_flags = build_ref_count_flags(&file_records);
    assert!(
        ref_flags.is_empty(),
        "underscore-prefixed Python helpers should stay private: {:?}",
        ref_flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn churn_signals_use_git_history_when_available() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_churn"));
    fs::create_dir_all(&temp_root).unwrap();
    git_cmd(&temp_root, &["init", "-q"]);
    git_cmd(&temp_root, &["config", "user.email", "sniff@example.com"]);
    git_cmd(&temp_root, &["config", "user.name", "Sniff"]);

    let churn_path = temp_root.join("churny.py");
    fs::write(&churn_path, "def churn():\n    return 1\n").unwrap();
    git_cmd(&temp_root, &["add", "."]);
    git_cmd(&temp_root, &["commit", "-q", "-m", "initial churn file"]);

    fs::write(&churn_path, "def churn():\n    return 2\n").unwrap();
    git_cmd(&temp_root, &["add", "."]);
    git_cmd(&temp_root, &["commit", "-q", "-m", "second churn change"]);

    fs::write(&churn_path, "def churn():\n    return 1\n").unwrap();
    git_cmd(&temp_root, &["add", "."]);
    git_cmd(&temp_root, &["commit", "-q", "-m", "Revert churn change"]);

    fs::write(&churn_path, "def churn():\n    return 3\n").unwrap();
    git_cmd(&temp_root, &["add", "."]);
    git_cmd(&temp_root, &["commit", "-q", "-m", "final churn change"]);

    let paths = vec![churn_path.to_string_lossy().to_string()];
    let mut file_records = parse_records(&paths);
    let graph = build_graph(&paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let flags = sniff::signal_layers::collect_supporting_flags(
        &file_records,
        &ResolvedConfig::default(),
        &temp_root,
    );
    assert!(
        count_gate(&flags, "churn") >= 1,
        "expected churn flag: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn branchy_small_helpers_get_flagged_by_control_flow_density() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_branchy"));
    fs::create_dir_all(&temp_root).unwrap();
    let path = temp_root.join("branchy.py");
    fs::write(
        &path,
        "def branchy(value):\n    if value > 0:\n        value -= 1\n    if value > 1:\n        value -= 1\n    for _ in range(2):\n        value += 1\n    while value > 0:\n        value -= 1\n    if value == 0:\n        return True\n    return False\n",
    )
    .unwrap();

    let path_str = path.to_string_lossy().to_string();
    let file_records = parse_records(&[path_str]);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());

    assert_eq!(scorer_flags.len(), 1);
    let flag = &scorer_flags[0];
    assert_eq!(flag.flag_type, "method");
    assert_eq!(flag.tier, FindingTier::Slop);
    assert!(
        flag.reasons
            .iter()
            .any(|reason| reason.contains("control flow is tangled")),
        "{:?}",
        flag.reasons
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn rust_similarity_modules_stay_small_and_separated() {
    let wrapper_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("signal_layers.rs");
    let flags_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("signal_layers_similarity_flags.rs");
    let duplicates_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("signal_layers_similarity_duplicates.rs");

    let wrapper_src = fs::read_to_string(&wrapper_path).unwrap();
    let flags_src = fs::read_to_string(&flags_path).unwrap();
    let duplicates_src = fs::read_to_string(&duplicates_path).unwrap();

    assert!(
        !wrapper_src.contains("fn supporting_similarity_flags")
            && !wrapper_src.contains("fn build_prepared_methods"),
        "wrapper should only re-export the split modules"
    );
    assert!(
        flags_src.contains("pub(crate) fn supporting_similarity_flags"),
        "flags module should own the emitted findings"
    );
    assert!(
        duplicates_src.contains("pub(crate) fn build_prepared_methods"),
        "duplicate-preparation module should own prepared methods"
    );
    assert!(
        wrapper_src.lines().count() < 200 && flags_src.lines().count() < 360,
        "the split modules should stay reasonably small"
    );
}

#[test]
fn python_protocol_surfaces_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_protocol_end_to_end"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let protocol_path = write_temp_file(
        &src_dir,
        "protocols.py",
        r#"
from typing import Protocol


class ApprovalStore(Protocol):
    def get(self, repository: str, pull_request_number: int) -> object | None: ...
    def close(self) -> None: ...
"#,
    );

    let protocol_paths = vec![protocol_path.clone()];
    let mut file_records = parse_records(&protocol_paths);
    let graph = build_graph(&protocol_paths, &temp_root.to_string_lossy());
    build_references(&mut file_records, &graph);

    let ref_flags = build_ref_count_flags(&file_records);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        ref_flags.is_empty(),
        "protocol methods should not be orphaned export noise"
    );
    assert!(
        scorer_flags.is_empty(),
        "protocol surfaces should not be scored as slop"
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);
    assert!(
        file_verdicts[0].top_reasons.is_empty(),
        "protocol surfaces should not ship any verdict reasons"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_star_import_reexports_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_star_reexport"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let shim_path = write_temp_file(
        &src_dir,
        "shim.py",
        "from bumpkin.analysis.explanation_facts import *  # noqa: F403\n",
    );

    let paths = vec![shim_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "star-import reexport shims should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "pure reexport shims should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_api_facades_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_api_facade"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let api_path = write_temp_file(
        &src_dir,
        "api.py",
        "from bumpkin.analysis import finding_python_all_contract as _all_contract\nfrom bumpkin.analysis import finding_python_public_names as _public_names\n\nextract_python_all_contract = _all_contract.extract_python_all_contract\nextract_python_public_names = _public_names.extract_python_public_names\n",
    );

    let paths = vec![api_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "api facade shims should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "api facade shims should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_parameter_compat_helpers_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_parameter_compat"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let compat_path = write_temp_file(
        &src_dir,
        "finding_python_parameter_compat.py",
        r#"
import ast


def is_optional_param(annotation):
    return annotation is None


def normalize_python_annotation(annotation):
    return annotation


def parse_python_parameter_specs(params):
    return []


def same_python_parameter_surface(left, right):
    return left == right


def has_compatible_python_parameter_surface(left, right):
    return left == right
"#,
    );

    let paths = vec![compat_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "parameter compatibility helpers should stay clean: {:?}",
        scorer_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);
    assert!(
        file_verdicts[0].top_reasons.is_empty(),
        "parameter compatibility helpers should not ship verdict reasons"
    );

    fs::remove_dir_all(&temp_root).ok();
}
