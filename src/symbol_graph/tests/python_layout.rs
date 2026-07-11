use super::*;

#[test]
fn test_python_namespace_import_resolution() {
    let dir = unique_tag("temp_python_namespace");
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
    let consumer_file = write_temp_file(
        &dir,
        "consumer.py",
        r#"
import pkg.helpers as helpers

def main():
    helpers.process_data()
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let helper_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "helpers.process_data")
        .collect();
    assert_eq!(helper_refs.len(), 1);

    let resolved = helper_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "process_data");
        }
        _ => panic!("Expected Python namespace import resolution"),
    }
}

#[test]
fn test_python_src_layout_absolute_import_resolution() {
    let dir = unique_tag("temp_python_src_layout");
    let src_dir = format!("{}/src", dir);
    let pkg_dir = format!("{}/bumpkin/analysis", src_dir);
    fs::create_dir_all(&pkg_dir).unwrap();

    let helpers_file = write_temp_file(
        &pkg_dir,
        "finding_python_signatures.py",
        r#"
def extract_python_signatures():
    pass
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.py",
        r#"
import bumpkin.analysis.finding_python_signatures as sigs

def main():
    sigs.extract_python_signatures()
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "sigs.extract_python_signatures")
        .collect();
    assert_eq!(refs.len(), 1);

    let resolved = refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "extract_python_signatures");
        }
        _ => panic!("Expected Python src-layout absolute import resolution"),
    }
}

#[test]
fn test_python_src_subdir_absolute_import_resolution() {
    let dir = unique_tag("temp_python_src_subdir");
    let analysis_dir = format!("{}/src/bumpkin/analysis", dir);
    fs::create_dir_all(&analysis_dir).unwrap();

    let helpers_file = write_temp_file(
        &analysis_dir,
        "finding_python_signatures.py",
        r#"
def extract_python_signatures():
    pass
"#,
    );
    let consumer_file = write_temp_file(
        &analysis_dir,
        "finding_python_detection_context.py",
        r#"
from bumpkin.analysis import (
    finding_python_signatures,
    finding_python_surface,
)

_extract_python_signatures = finding_python_signatures.extract_python_signatures
"#,
    );

    let mut graph = SymbolGraph::new(&analysis_dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "finding_python_signatures.extract_python_signatures")
        .collect();
    assert_eq!(refs.len(), 1);

    let resolved = refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "extract_python_signatures");
        }
        _ => panic!("Expected Python src-subdir absolute import resolution"),
    }
}

#[test]
fn test_python_top_level_alias_reference_resolution() {
    let dir = unique_tag("temp_python_top_level_alias");
    let src_dir = format!("{}/src", dir);
    let pkg_dir = format!("{}/bumpkin/analysis", src_dir);
    fs::create_dir_all(&pkg_dir).unwrap();

    let helpers_file = write_temp_file(
        &pkg_dir,
        "finding_python_signatures.py",
        r#"
def extract_python_signatures():
    pass
"#,
    );
    let consumer_file = write_temp_file(
        &pkg_dir,
        "finding_python_detection_context.py",
        r#"
import bumpkin.analysis.finding_python_signatures as finding_python_signatures

_extract_python_signatures = finding_python_signatures.extract_python_signatures
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "finding_python_signatures.extract_python_signatures")
        .collect();
    assert_eq!(refs.len(), 1);

    let resolved = refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "extract_python_signatures");
        }
        _ => panic!("Expected Python top-level alias resolution"),
    }
}

#[test]
fn test_python_multiline_from_import_top_level_alias_resolution() {
    let dir = unique_tag("temp_python_multiline_alias");
    let src_dir = format!("{}/src", dir);
    let pkg_dir = format!("{}/bumpkin/analysis", src_dir);
    fs::create_dir_all(&pkg_dir).unwrap();

    let helpers_file = write_temp_file(
        &pkg_dir,
        "finding_python_signatures.py",
        r#"
def extract_python_signatures():
    pass
"#,
    );
    let consumer_file = write_temp_file(
        &pkg_dir,
        "finding_python_detection_context.py",
        r#"
from bumpkin.analysis import (
    finding_python_signatures,
    finding_python_surface,
)

_extract_python_signatures = finding_python_signatures.extract_python_signatures
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&helpers_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "finding_python_signatures.extract_python_signatures")
        .collect();
    assert_eq!(refs.len(), 1);

    let resolved = refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "extract_python_signatures");
        }
        _ => panic!("Expected Python multiline import alias resolution"),
    }
}
