use super::*;

fn external_definition_id(
    reference: &crate::types::SymbolReference,
    expected_file: &str,
) -> Option<usize> {
    match reference.resolved_symbol.as_ref() {
        Some(ResolvedSymbol::External {
            file_path,
            definition_id,
            ..
        }) => {
            assert_eq!(normalize_path(file_path), normalize_path(expected_file));
            *definition_id
        }
        other => panic!("expected external target {expected_file}, got {other:?}"),
    }
}

#[test]
fn test_rust_path_modules_and_grouped_imports_resolve() {
    let root = unique_tag("temp_rust_modules");
    let src = format!("{root}/src");
    fs::create_dir_all(&src).unwrap();

    let lib = write_temp_file(
        &src,
        "lib.rs",
        r#"#[path = "roles.rs"]
mod roles;
"#,
    );
    let roles = write_temp_file(
        &src,
        "roles.rs",
        r#"#[path = "roles_paths.rs"]
pub(super) mod paths;
#[path = "roles_heuristics.rs"]
mod heuristics;

pub(super) use paths::{is_source_path, is_test_path};
"#,
    );
    let paths = write_temp_file(
        &src,
        "roles_paths.rs",
        r#"pub(super) fn is_test_path(path: &str) -> bool {
    path.contains("test")
}

pub(super) fn is_source_path(path: &str) -> bool {
    path.contains("src")
}
"#,
    );
    let heuristics = write_temp_file(
        &src,
        "roles_heuristics.rs",
        r#"use super::paths::{is_source_path, is_test_path};

pub(super) fn classify(path: &str) -> bool {
    is_source_path(path) && !is_test_path(path)
}
"#,
    );

    let mut graph = SymbolGraph::new(&root);
    for file in [&lib, &roles, &paths, &heuristics] {
        graph.add_file(parse_file_symbols(file));
    }
    graph.resolve_all();

    let references = &graph.files.get(&heuristics).unwrap().references;
    let source_call = references
        .iter()
        .find(|reference| reference.name == "is_source_path")
        .expect("is_source_path call");
    let test_call = references
        .iter()
        .find(|reference| reference.name == "is_test_path")
        .expect("is_test_path call");
    assert!(external_definition_id(source_call, &paths).is_some());
    assert!(external_definition_id(test_call, &paths).is_some());

    fs::remove_dir_all(&root).ok();
}

#[test]
fn test_rust_sibling_module_import_follows_parent_path_module() {
    let root = unique_tag("temp_rust_sibling_path_module");
    let src = format!("{root}/src");
    fs::create_dir_all(&src).unwrap();

    let lib = write_temp_file(
        &src,
        "lib.rs",
        r#"#[path = "pipeline.rs"]
mod pipeline;
"#,
    );
    let pipeline = write_temp_file(
        &src,
        "pipeline.rs",
        r#"#[path = "pipeline_llm.rs"]
mod llm;
#[path = "pipeline_run.rs"]
mod run;
"#,
    );
    let llm = write_temp_file(
        &src,
        "pipeline_llm.rs",
        "pub(super) fn prepare_review_artifacts() {}\n",
    );
    let run = write_temp_file(
        &src,
        "pipeline_run.rs",
        r#"use super::{llm};

pub(super) fn run() {
    llm::prepare_review_artifacts();
}
"#,
    );

    let mut graph = SymbolGraph::new(&root);
    for file in [&lib, &pipeline, &llm, &run] {
        graph.add_file(parse_file_symbols(file));
    }
    graph.resolve_all();

    let call = graph
        .files
        .get(&run)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "llm::prepare_review_artifacts")
        .expect("qualified sibling module call");
    assert!(external_definition_id(call, &llm).is_some());

    fs::remove_dir_all(&root).ok();
}

#[test]
fn test_rust_type_method_resolves_through_nested_super_globs() {
    let root = unique_tag("temp_rust_nested_glob_type_method");
    let src = format!("{root}/src");
    fs::create_dir_all(&src).unwrap();

    let lib = write_temp_file(
        &src,
        "lib.rs",
        r#"#[path = "parser.rs"]
mod parser;
"#,
    );
    let parser = write_temp_file(
        &src,
        "parser.rs",
        r#"#[path = "line_index.rs"]
mod line_index;
#[path = "parser_file.rs"]
mod file;

pub(super) use line_index::LineIndex;
"#,
    );
    let line_index = write_temp_file(
        &src,
        "line_index.rs",
        r#"pub struct LineIndex;

impl LineIndex {
    pub fn new() -> Self {
        Self
    }
}
"#,
    );
    let parser_file = write_temp_file(
        &src,
        "parser_file.rs",
        r#"use super::*;

#[path = "parser_file_methods.rs"]
mod methods;
"#,
    );
    let methods = write_temp_file(
        &src,
        "parser_file_methods.rs",
        r#"use super::*;

pub fn parse() {
    let _ = LineIndex::new();
}
"#,
    );

    let mut graph = SymbolGraph::new(&root);
    for file in [&lib, &parser, &line_index, &parser_file, &methods] {
        graph.add_file(parse_file_symbols(file));
    }
    graph.resolve_all();

    let call = graph
        .files
        .get(&methods)
        .unwrap()
        .references
        .iter()
        .find(|reference| reference.name == "LineIndex::new")
        .expect("LineIndex::new call");
    assert!(external_definition_id(call, &line_index).is_some());

    fs::remove_dir_all(&root).ok();
}

#[test]
fn test_rust_free_and_receiver_calls_with_the_same_name_resolve_separately() {
    let root = unique_tag("temp_rust_call_shape");
    let src = format!("{root}/src");
    fs::create_dir_all(&src).unwrap();

    let lib = write_temp_file(&src, "lib.rs", "mod client;\nmod consumer;\n");
    let client = write_temp_file(
        &src,
        "client.rs",
        r#"pub struct Client;

impl Client {
    pub fn max_concurrency(&self) -> usize {
        8
    }
}

pub fn max_concurrency() -> usize {
    4
}
"#,
    );
    let consumer = write_temp_file(
        &src,
        "consumer.rs",
        r#"use crate::client::{max_concurrency, Client};

pub fn run(client: &Client) -> usize {
    max_concurrency() + client.max_concurrency()
}
"#,
    );

    let mut graph = SymbolGraph::new(&root);
    for file in [&lib, &client, &consumer] {
        graph.add_file(parse_file_symbols(file));
    }
    graph.resolve_all();

    let symbols = graph.files.get(&consumer).unwrap();
    let calls = symbols
        .references
        .iter()
        .filter(|reference| reference.name == "max_concurrency")
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    let definitions = &graph.files.get(&client).unwrap().definitions;
    let free_id = definitions
        .iter()
        .find(|definition| definition.name == "max_concurrency" && definition.owner_type.is_none())
        .unwrap()
        .id;
    let method_id = definitions
        .iter()
        .find(|definition| {
            definition.name == "max_concurrency"
                && definition.owner_type.as_deref() == Some("Client")
        })
        .unwrap()
        .id;
    let free_call = calls.iter().find(|call| !call.is_member_call).unwrap();
    let member_call = calls.iter().find(|call| call.is_member_call).unwrap();
    assert_eq!(external_definition_id(free_call, &client), Some(free_id));
    assert_eq!(
        external_definition_id(member_call, &client),
        Some(method_id)
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn test_rust_callable_values_resolve_without_treating_shadowed_values_as_calls() {
    let root = unique_tag("temp_rust_callable_values");
    let src = format!("{root}/src");
    fs::create_dir_all(&src).unwrap();

    let lib = write_temp_file(
        &src,
        "lib.rs",
        r#"fn render_definition(value: &str) -> String {
    value.to_string()
}

fn shadowed_callback() -> String {
    String::new()
}

pub fn render_all(values: &[&str]) -> Vec<String> {
    values.iter().map(render_definition).collect()
}

pub fn use_supplied_callback(shadowed_callback: fn() -> String) -> String {
    consume(shadowed_callback)
}
"#,
    );

    let mut graph = SymbolGraph::new(&root);
    graph.add_file(parse_file_symbols(&lib));
    graph.resolve_all();

    let symbols = graph.files.get(&lib).unwrap();
    let definition = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "render_definition")
        .unwrap();
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "render_definition" && reference.is_callable_value)
        .expect("function passed to map should be retained as a callable-value reference");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == definition.id
    ));
    assert!(
        !symbols
            .references
            .iter()
            .any(|reference| reference.name == "shadowed_callback"),
        "a shadowing parameter must not be mistaken for the same-named function"
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn test_rust_receiver_call_resolves_to_same_owner_method() {
    let root = unique_tag("temp_rust_receiver_call");
    let source = write_temp_file(
        &root,
        "src/cli.rs",
        r#"struct Opts;

impl Opts {
    fn search_paths(&self) {
        let _ = Ok::<_, ()>(vec![self.normalize_path(".")]);
    }

    fn normalize_path(&self, path: &str) -> String {
        path.to_string()
    }
}
"#,
    );
    let mut graph = SymbolGraph::new(&root);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let definition = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "normalize_path")
        .unwrap();
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "normalize_path")
        .expect("receiver call");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == definition.id
    ));

    fs::remove_dir_all(&root).ok();
}

#[test]
fn test_rust_proc_macro_attribute_records_callable_reference() {
    let root = unique_tag("temp_rust_attribute_callback");
    let source = write_temp_file(
        &root,
        "src/cli.rs",
        r#"struct Opts {
    #[arg(long, value_parser = parse_millis)]
    timeout: u64,
}

fn parse_millis(value: &str) -> Result<u64, ()> {
    value.parse().map_err(|_| ())
}
"#,
    );
    let mut graph = SymbolGraph::new(&root);
    graph.add_file(parse_file_symbols(&source));
    graph.resolve_all();

    let symbols = graph.files.get(&source).unwrap();
    let definition = symbols
        .definitions
        .iter()
        .find(|definition| definition.name == "parse_millis")
        .unwrap();
    let reference = symbols
        .references
        .iter()
        .find(|reference| reference.name == "parse_millis" && reference.is_callable_value)
        .expect("proc-macro callable reference");
    assert!(matches!(
        reference.resolved_symbol,
        Some(ResolvedSymbol::Local(id)) if id == definition.id
    ));

    fs::remove_dir_all(&root).ok();
}
