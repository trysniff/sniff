use super::*;

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
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "processData");
        }
        _ => panic!("Expected TS export-star resolution"),
    }
}
