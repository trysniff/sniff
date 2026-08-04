use super::*;

#[test]
fn test_python_function_local_import_resolves_only_inside_its_scope() {
    let dir = unique_tag("temp_python_local_import");
    fs::create_dir_all(&dir).unwrap();
    let pipeline = write_temp_file(&dir, "pipeline.py", "def run():\n    return 0\n");
    let entrypoint = write_temp_file(
        &dir,
        "entrypoint.py",
        "def main():\n    from pipeline import run\n    return run()\n\ndef unrelated():\n    return run()\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&pipeline));
    graph.add_file(parse_file_symbols(&entrypoint));
    graph.resolve_all();

    let symbols = graph.files.get(&entrypoint).unwrap();
    let scoped = symbols
        .references
        .iter()
        .find(|reference| reference.line == 3)
        .expect("scoped run call");
    match scoped.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External { file_path, .. }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&pipeline));
        }
        other => panic!("expected function-local import to resolve, got {other:?}"),
    }
    let unrelated = symbols
        .references
        .iter()
        .find(|reference| reference.line == 6)
        .expect("unrelated run call");
    assert!(
        unrelated.resolved_symbol.is_none(),
        "function-local imports must not leak into sibling functions"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_python_inherited_method_resolves_through_imported_base_class() {
    let dir = unique_tag("temp_python_inherited_method");
    let pkg = format!("{dir}/pkg");
    fs::create_dir_all(&pkg).unwrap();
    let support = write_temp_file(
        &pkg,
        "support.py",
        "class StoreSupport:\n    def _record_audit(self, *, action):\n        return action\n",
    );
    let operations = write_temp_file(
        &pkg,
        "operations.py",
        "from .support import StoreSupport\n\nclass EventOpsMixin(StoreSupport):\n    def record_event(self):\n        return self._record_audit(action='recorded')\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&support));
    graph.add_file(parse_file_symbols(&operations));
    graph.resolve_all();

    let operation_symbols = graph.files.get(&operations).unwrap();
    assert!(
        operation_symbols
            .types
            .iter()
            .any(|record| record.name == "EventOpsMixin" && record.bases == ["StoreSupport"])
    );
    let reference = operation_symbols
        .references
        .iter()
        .find(|reference| reference.name == "self._record_audit")
        .unwrap();
    match reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External { file_path, .. }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&support));
        }
        other => panic!("expected inherited support method, got {other:?}"),
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_python_imported_function_is_not_shadowed_by_same_named_class_method() {
    let dir = unique_tag("temp_python_method_shadow");
    let pkg = format!("{dir}/pkg");
    fs::create_dir_all(&pkg).unwrap();
    let service = write_temp_file(&pkg, "service.py", "def replay_once():\n    return True\n");
    let effects = write_temp_file(
        &pkg,
        "effects.py",
        "from .service import replay_once\n\nclass Effects:\n    def replay_once(self):\n        return replay_once()\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&service));
    graph.add_file(parse_file_symbols(&effects));
    graph.resolve_all();

    let effects_symbols = graph.files.get(&effects).unwrap();
    assert!(effects_symbols.definitions.iter().any(|definition| {
        definition.name == "replay_once" && definition.owner_type.as_deref() == Some("Effects")
    }));
    let reference = effects_symbols
        .references
        .iter()
        .find(|reference| reference.name == "replay_once")
        .unwrap();
    match reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External { file_path, .. }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&service));
        }
        other => panic!("expected imported service function, got {other:?}"),
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_python_imported_callable_used_as_staticmethod_is_a_real_reference() {
    let dir = unique_tag("temp_python_staticmethod");
    let pkg = format!("{dir}/pkg");
    fs::create_dir_all(&pkg).unwrap();
    let http = write_temp_file(&pkg, "http.py", "def collect_paginated():\n    return []\n");
    let client = write_temp_file(
        &pkg,
        "client.py",
        "from .http import collect_paginated\n\nclass Client:\n    collect = staticmethod(collect_paginated)\n",
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&http));
    graph.add_file(parse_file_symbols(&client));
    graph.resolve_all();

    let reference = graph
        .files
        .get(&client)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "collect_paginated")
        .unwrap();
    match reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External { file_path, .. }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&http));
        }
        other => panic!("expected imported callable reference, got {other:?}"),
    }
    fs::remove_dir_all(&dir).ok();
}

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
            ..
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
            ..
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
            ..
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

_extract_python_signatures_indirect = (
    finding_python_signatures.extract_python_signatures
)

def use_indirect_alias():
    return _extract_python_signatures_indirect()
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
    assert_eq!(refs.len(), 2);

    let resolved = refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
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

_extract_python_signatures_indirect = (
    finding_python_signatures.extract_python_signatures
)

def use_indirect_alias():
    return _extract_python_signatures_indirect()
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
    assert_eq!(refs.len(), 2);

    let resolved = refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "extract_python_signatures");
        }
        _ => panic!("Expected Python multiline import alias resolution"),
    }

    let alias_call = consumer_symbols
        .references
        .iter()
        .find(|reference| reference.name == "_extract_python_signatures_indirect")
        .expect("indirect callable alias call");
    match alias_call.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        }) => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "extract_python_signatures");
        }
        other => panic!("Expected indirect Python callable alias resolution, got {other:?}"),
    }
}
