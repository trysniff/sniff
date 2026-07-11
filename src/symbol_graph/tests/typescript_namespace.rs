use super::*;

#[test]
fn test_ts_namespace_import_resolution() {
    let dir = unique_tag("temp_ts_namespace");
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
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.ts",
        r#"
import * as helpers from "./helpers";

export function main() {
    helpers.processData();
}
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
        .filter(|r| r.name == "helpers.processData")
        .collect();
    assert_eq!(helper_refs.len(), 1);

    let resolved = helper_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "processData");
        }
        _ => panic!("Expected TS namespace import resolution"),
    }
}

#[test]
fn test_ts_namespace_export_resolution() {
    let dir = unique_tag("temp_ts_namespace_export");
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
export * as helpers from "./helpers";
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.ts",
        r#"
import { helpers } from "./api";

export function main() {
    helpers.processData();
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
    let helper_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "helpers.processData")
        .collect();
    assert_eq!(helper_refs.len(), 1);

    let resolved = helper_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&helpers_file));
            assert_eq!(symbol_name, "processData");
        }
        _ => panic!("Expected TS namespace export resolution"),
    }
}
