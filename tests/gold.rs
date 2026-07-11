use sniff::callgraph::{build_ref_count_flags, build_references};
use sniff::config::ResolvedConfig;
use sniff::file_verdicts::build_file_verdicts;
use sniff::parser::{parse_file, parse_file_symbols};
use sniff::report_types::StaticFlag;
use sniff::scorer::score;
use sniff::symbol_graph::SymbolGraph;
use sniff::types::{FileRecord, FindingTier, ResolvedSymbol};
use sniff::walker::walk;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_tag(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}_{}_{}", label, std::process::id(), nanos)
}

fn write_temp_file(root: &Path, relative: &str, contents: &str) -> String {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
    path.to_string_lossy().to_string()
}

fn branchy_python_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\ndef {prefix}_helper_{idx:02}(value):\n    if value == 0:\n        return 0\n    if value == 1:\n        return 1\n    if value == 2:\n        return 2\n    return value\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn branchy_typescript_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\nexport function {prefix}Helper{idx:02}(value: number) {{\n  if (value === 0) {{\n    return 0;\n  }}\n  if (value === 1) {{\n    return 1;\n  }}\n  if (value === 2) {{\n    return 2;\n  }}\n  return value;\n}}\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn branchy_go_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\nfunc {prefix}Helper{idx:02}(value int) int {{\n    if value == 0 {{\n        return 0\n    }}\n    if value == 1 {{\n        return 1\n    }}\n    if value == 2 {{\n        return 2\n    }}\n    return value\n}}\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn branchy_rust_helpers(prefix: &str, count: usize) -> String {
    let mut helpers = String::new();
    for idx in 0..count {
        helpers.push_str(&format!(
            "\npub fn {prefix}_helper_{idx:02}(value: i32) -> i32 {{\n    if value == 0 {{\n        return 0;\n    }}\n    if value == 1 {{\n        return 1;\n    }}\n    if value == 2 {{\n        return 2;\n    }}\n    value\n}}\n",
            prefix = prefix,
            idx = idx
        ));
    }
    helpers
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }

    Ok(())
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("gold_fixtures")
        .join("repo")
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn has_suffix(path: &str, suffix: &str) -> bool {
    normalize_path(path).ends_with(suffix)
}

fn parse_records(paths: &[String]) -> Vec<FileRecord> {
    paths.iter().map(|path| parse_file(path)).collect()
}

fn build_graph(paths: &[String], root: &str) -> SymbolGraph {
    let mut graph = SymbolGraph::new(root);
    for path in paths {
        graph.add_file(parse_file_symbols(path));
    }
    graph.resolve_all();
    graph
}

fn count_gate(flags: &[StaticFlag], gate: &str) -> usize {
    flags.iter().filter(|flag| flag.gate == gate).count()
}

fn git_cmd(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {:?}", args);
}

#[path = "gold/analysis.rs"]
mod analysis;
#[path = "gold/bumpkin.rs"]
mod bumpkin;
#[path = "gold/contracts.rs"]
mod contracts;
#[path = "gold/core.rs"]
mod core;
#[path = "gold/graph.rs"]
mod graph;
#[path = "gold/language_runtime.rs"]
mod language_runtime;
#[path = "gold/language_surfaces.rs"]
mod language_surfaces;
#[path = "gold/policy.rs"]
mod policy;
