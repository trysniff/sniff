use super::*;

#[test]
fn test_rust_qualified_call_resolves_through_reexport() {
    let dir = unique_tag("temp_rust_qualified_reexport");
    let src_dir = format!("{dir}/src");
    fs::create_dir_all(&src_dir).unwrap();

    let lib_file = write_temp_file(
        &src_dir,
        "lib.rs",
        r#"mod reporter;
mod consumer;
mod unrelated;
"#,
    );
    let reporter_file = write_temp_file(
        &src_dir,
        "reporter.rs",
        r#"#[path = "reporter_render.rs"]
mod render;

pub use render::render_report;
"#,
    );
    let render_file = write_temp_file(
        &src_dir,
        "reporter_render.rs",
        r#"pub fn render_report() {}
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.rs",
        r#"pub fn run() {
    crate::reporter::render_report();
}
"#,
    );
    let unrelated_file = write_temp_file(
        &src_dir,
        "unrelated.rs",
        r#"pub fn render_report() {}
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    for file in [
        &lib_file,
        &reporter_file,
        &render_file,
        &consumer_file,
        &unrelated_file,
    ] {
        graph.add_file(parse_file_symbols(file));
    }
    graph.resolve_all();

    let reference = graph
        .files
        .get(&consumer_file)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "crate::reporter::render_report")
        .expect("qualified render_report call");
    match reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External {
            file_path,
            symbol_name,
            definition_id: Some(_),
        }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&render_file));
            assert_eq!(symbol_name, "render_report");
        }
        other => panic!("expected re-export target, got {other:?}"),
    }

    let reporter_symbols = graph.files.get(&reporter_file).unwrap();
    let export_index = reporter_symbols
        .exports
        .iter()
        .position(|export| export.exported_name == "render_report")
        .unwrap();
    let target_id = graph
        .files
        .get(&render_file)
        .unwrap()
        .definitions
        .iter()
        .find(|definition| definition.name == "render_report")
        .unwrap()
        .id;
    let unrelated_id = graph
        .files
        .get(&unrelated_file)
        .unwrap()
        .definitions
        .iter()
        .find(|definition| definition.name == "render_report")
        .unwrap()
        .id;
    assert!(graph.export_targets_definition(&reporter_file, export_index, &render_file, target_id));
    assert!(!graph.export_targets_definition(
        &reporter_file,
        export_index,
        &unrelated_file,
        unrelated_id
    ));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_python_alias_import_reexport_resolution() {
    let dir = unique_tag("temp_python_reexport");
    let pkg_dir = format!("{}/pkg", dir);
    fs::create_dir_all(&pkg_dir).unwrap();

    let helpers_file = write_temp_file(
        &pkg_dir,
        "helpers.py",
        r#"
def process_data():
    pass
"#,
    );
    let api_file = write_temp_file(
        &pkg_dir,
        "api.py",
        r#"
from .helpers import process_data as run_data
"#,
    );
    let consumer_file = write_temp_file(
        &dir,
        "consumer.py",
        r#"
from pkg.api import run_data

def main():
    run_data()
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&api_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let run_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "run_data")
        .collect();
    assert_eq!(run_refs.len(), 1);

    let resolved = run_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "process_data");
        }
        _ => panic!("Expected Python re-export resolution"),
    }
}

#[test]
fn test_ts_named_alias_reexport_resolution() {
    let dir = unique_tag("temp_ts_reexport");
    let src_dir = format!("{}/src", dir);
    fs::create_dir_all(&src_dir).unwrap();

    let helpers_file = write_temp_file(
        &src_dir,
        "helpers.ts",
        r#"
export function processData() {
}
"#,
    );
    let api_file = write_temp_file(
        &src_dir,
        "api.ts",
        r#"
export { processData as runData } from "./helpers";
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.ts",
        r#"
import { runData } from "./api";

export function main() {
    runData();
}
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&api_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let run_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "runData")
        .collect();
    assert_eq!(run_refs.len(), 1);

    let resolved = run_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "processData");
        }
        _ => panic!("Expected TS re-export resolution"),
    }
}

#[test]
fn test_js_named_alias_import_resolution() {
    let dir = unique_tag("temp_js_alias");
    let src_dir = format!("{}/src", dir);
    fs::create_dir_all(&src_dir).unwrap();

    let helpers_file = write_temp_file(
        &src_dir,
        "helpers.js",
        r#"
export function processThing() {
}
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.js",
        r#"
import { processThing as runThing } from "./helpers";

export function main() {
    runThing();
}
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let run_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "runThing")
        .collect();
    assert_eq!(run_refs.len(), 1);

    let resolved = run_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "processThing");
        }
        _ => panic!("Expected JS alias import resolution"),
    }
}

#[test]
fn test_python_star_import_reexport_resolution() {
    let dir = unique_tag("temp_python_star");
    let pkg_dir = format!("{}/pkg", dir);
    fs::create_dir_all(&pkg_dir).unwrap();

    let helpers_file = write_temp_file(
        &pkg_dir,
        "helpers.py",
        r#"
def process_data():
    pass
"#,
    );
    let init_file = write_temp_file(
        &pkg_dir,
        "__init__.py",
        r#"
from .helpers import *
"#,
    );
    let consumer_file = write_temp_file(
        &dir,
        "consumer.py",
        r#"
from pkg import *

def main():
    process_data()
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&init_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let process_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "process_data")
        .collect();
    assert_eq!(process_refs.len(), 1);

    let resolved = process_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "process_data");
        }
        _ => panic!("Expected Python star import resolution"),
    }
}

#[test]
fn test_ts_export_star_resolution() {
    let dir = unique_tag("temp_ts_export_star");
    let src_dir = format!("{}/src", dir);
    fs::create_dir_all(&src_dir).unwrap();

    let helpers_file = write_temp_file(
        &src_dir,
        "helpers.ts",
        r#"
export function processData() {
}
"#,
    );
    let api_file = write_temp_file(
        &src_dir,
        "api.ts",
        r#"
export * from "./helpers";
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.ts",
        r#"
import { processData } from "./api";

export function main() {
    processData();
}
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&api_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let process_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "processData")
        .collect();
    assert_eq!(process_refs.len(), 1);

    let resolved = process_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "processData");
        }
        _ => panic!("Expected TS export-star resolution"),
    }
}
