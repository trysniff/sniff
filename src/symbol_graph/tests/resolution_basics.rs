use super::*;

#[test]
fn test_local_resolution_and_shadowing() {
    let file_path = "temp_test_file.py";
    let code = r#"
def foo():
    pass

def bar():
    foo()

def baz(foo):
    foo()
"#;
    fs::write(file_path, code).unwrap();
    let symbols = parse_file_symbols(file_path);
    fs::remove_file(file_path).ok();

    // 1. Verify definitions
    println!("Definitions: {:?}", symbols.definitions);
    println!("References: {:?}", symbols.references);
    assert_eq!(symbols.definitions.len(), 3);
    assert_eq!(symbols.definitions[0].name, "foo");
    assert_eq!(symbols.definitions[1].name, "bar");
    assert_eq!(symbols.definitions[2].name, "baz");

    // 2. Verify references
    let foo_refs: Vec<_> = symbols
        .references
        .iter()
        .filter(|r| r.name == "foo")
        .collect();
    println!("Foo references: {:?}", foo_refs);
    assert_eq!(
        foo_refs.len(),
        1,
        "Should only have 1 reference to foo (in bar)"
    );
    assert_eq!(foo_refs[0].line, 6);
}

#[test]
fn test_cross_file_import_resolution() {
    let file_a = "temp_file_a.py";
    let file_b = "temp_file_b.py";

    let code_a = r#"
def foo():
    pass
"#;
    let code_b = r#"
from temp_file_a import foo

def test():
    foo()
"#;

    fs::write(file_a, code_a).unwrap();
    fs::write(file_b, code_b).unwrap();

    let mut graph = SymbolGraph::new(".");
    graph.add_file(parse_file_symbols(file_a));
    graph.add_file(parse_file_symbols(file_b));
    graph.resolve_all();

    fs::remove_file(file_a).ok();
    fs::remove_file(file_b).ok();

    // Verify that B's reference to "foo" is resolved to A's definition
    let symbols_b = graph.files.get(file_b).unwrap();
    let foo_refs: Vec<_> = symbols_b
        .references
        .iter()
        .filter(|r| r.name == "foo")
        .collect();
    assert_eq!(foo_refs.len(), 1);

    let resolved = foo_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert!(file_path.contains("temp_file_a.py"));
            assert_eq!(symbol_name, "foo");
        }
        _ => panic!("Expected external resolution"),
    }
}

#[test]
fn test_go_package_resolution() {
    let dir = "temp_go_pkg";
    fs::create_dir_all(dir).unwrap();
    let file_a = format!("{}/a.go", dir);
    let file_b = format!("{}/b.go", dir);

    let code_a = r#"
package main

func Foo() {
}
"#;
    let code_b = r#"
package main

func Bar() {
    Foo()
}
"#;

    fs::write(&file_a, code_a).unwrap();
    fs::write(&file_b, code_b).unwrap();

    let mut graph = SymbolGraph::new(dir);
    let symbols_a = parse_file_symbols(&file_a);
    let symbols_b = parse_file_symbols(&file_b);

    graph.add_file(symbols_a);
    graph.add_file(symbols_b);
    graph.resolve_all();

    fs::remove_file(&file_a).ok();
    fs::remove_file(&file_b).ok();
    fs::remove_dir(dir).ok();

    let b_ref = graph.files.get(&file_b).unwrap();
    let foo_refs: Vec<_> = b_ref
        .references
        .iter()
        .filter(|r| r.name == "Foo")
        .collect();
    assert_eq!(foo_refs.len(), 1);

    let resolved = foo_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert!(file_path.contains("a.go"));
            assert_eq!(symbol_name, "Foo");
        }
        _ => panic!("Expected external resolution for Foo"),
    }
}

#[test]
fn test_ts_oxc_parsing() {
    let file_path = "temp_ts_file.ts";
    let code = r#"
import { Helper } from "./helper";

interface User {
    id: number;
    name: string;
}

export function processUser(user: User): string {
    const message: string = "hello";
    return Helper.format(message, user.name);
}

const getUserId = (user: User): number => {
    return user.id;
};
"#;
    fs::write(file_path, code).unwrap();
    let symbols = parse_file_symbols(file_path);
    fs::remove_file(file_path).ok();

    println!("TS Definitions: {:?}", symbols.definitions);
    println!("TS References: {:?}", symbols.references);
    println!("TS Imports: {:?}", symbols.imports);
    println!("TS Exports: {:?}", symbols.exports);

    assert_eq!(symbols.definitions.len(), 2);
    assert!(
        symbols
            .definitions
            .iter()
            .any(|d| d.name == "processUser" && d.is_exported)
    );
    assert!(
        symbols
            .definitions
            .iter()
            .any(|d| d.name == "getUserId" && !d.is_exported)
    );

    assert_eq!(symbols.imports.len(), 1);
    assert_eq!(symbols.imports[0].local_name, "Helper");
    assert_eq!(symbols.imports[0].source_module, "./helper");

    assert_eq!(symbols.exports.len(), 1);
    assert_eq!(symbols.exports[0].local_symbol_name, "processUser");

    let helper_refs: Vec<_> = symbols
        .references
        .iter()
        .filter(|r| r.name == "Helper.format")
        .collect();
    assert_eq!(helper_refs.len(), 1);
}

#[test]
fn test_js_default_import_resolution() {
    let dir = unique_tag("temp_js_default");
    fs::create_dir_all(&dir).unwrap();
    let file_a = format!("{}/a.js", dir);
    let file_b = format!("{}/b.js", dir);

    let code_a = r#"
export default function greet() {
}
"#;
    let code_b = r#"
import greetAlias from "./a";

export function run() {
    greetAlias();
}
"#;

    fs::write(&file_a, code_a).unwrap();
    fs::write(&file_b, code_b).unwrap();

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&file_a));
    graph.add_file(parse_file_symbols(&file_b));
    graph.resolve_all();

    fs::remove_file(&file_a).ok();
    fs::remove_file(&file_b).ok();
    fs::remove_dir_all(&dir).ok();

    let symbols_b = graph.files.get(&file_b).unwrap();
    let greet_refs: Vec<_> = symbols_b
        .references
        .iter()
        .filter(|r| r.name == "greetAlias")
        .collect();
    assert_eq!(greet_refs.len(), 1);

    let resolved = greet_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert!(file_path.contains("a.js"));
            assert_eq!(symbol_name, "greet");
        }
        _ => panic!("Expected default export resolution"),
    }
}

#[test]
fn test_go_selector_resolution() {
    let dir = unique_tag("temp_go_selector");
    fs::create_dir_all(&dir).unwrap();
    let file_a = format!("{}/a.go", dir);
    let file_b = format!("{}/b.go", dir);

    let code_a = r#"
package pkg

func Foo() {
}
"#;
    let code_b = format!(
        r#"
package main

import p "{}"

func Bar() {{
    p.Foo()
}}
"#,
        dir
    );

    fs::write(&file_a, code_a).unwrap();
    fs::write(&file_b, code_b).unwrap();

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&file_a));
    graph.add_file(parse_file_symbols(&file_b));
    graph.resolve_all();

    fs::remove_file(&file_a).ok();
    fs::remove_file(&file_b).ok();
    fs::remove_dir_all(&dir).ok();

    let symbols_b = graph.files.get(&file_b).unwrap();
    let foo_refs: Vec<_> = symbols_b
        .references
        .iter()
        .filter(|r| r.name == "p.Foo")
        .collect();
    assert_eq!(foo_refs.len(), 1);

    let resolved = foo_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert!(file_path.contains("a.go"));
            assert_eq!(symbol_name, "Foo");
        }
        _ => panic!("Expected Go selector resolution"),
    }
}

#[test]
fn test_go_receiver_calls_and_function_arguments_resolve() {
    let dir = unique_tag("temp_go_receiver_and_callback");
    fs::create_dir_all(&dir).unwrap();
    let file = format!("{}/main.go", dir);
    let lifecycle_file = format!("{}/lifecycle.go", dir);
    let code = r#"
package pkg

type limiter struct{}

func (r *limiter) permit() {}
func handler() {}
func register(fn func()) {}

func wire(r *limiter) {
    r.permit()
    register(handler)
    go r.maintain()
}
"#;
    fs::write(&file, code).unwrap();
    fs::write(
        &lifecycle_file,
        "package pkg\n\nfunc (r *limiter) maintain() {}\n",
    )
    .unwrap();

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&file));
    graph.add_file(parse_file_symbols(&lifecycle_file));
    graph.resolve_all();

    let symbols = graph.files.get(&file).unwrap();
    let permit = symbols
        .references
        .iter()
        .find(|reference| reference.name == "r.permit")
        .expect("receiver call reference");
    assert!(permit.is_member_call);
    assert!(matches!(
        permit.resolved_symbol,
        Some(ResolvedSymbol::Local(_))
    ));

    let handler = symbols
        .references
        .iter()
        .find(|reference| reference.name == "handler")
        .expect("function argument reference");
    assert!(handler.is_callable_value);
    assert!(matches!(
        handler.resolved_symbol,
        Some(ResolvedSymbol::Local(_))
    ));

    let maintain = symbols
        .references
        .iter()
        .find(|reference| reference.name == "r.maintain")
        .expect("cross-file goroutine receiver call reference");
    assert!(matches!(
        maintain.resolved_symbol,
        Some(ResolvedSymbol::External { .. })
    ));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_rust_resolution_and_dogfood_path() {
    let dir = unique_tag("temp_rust_mod");
    let src_dir = format!("{}/src", dir);
    fs::create_dir_all(&src_dir).unwrap();
    let file_a = format!("{}/utils.rs", src_dir);
    let file_b = format!("{}/lib.rs", src_dir);

    let code_a = r#"
pub fn helper() {
}
"#;
    let code_b = r#"
mod utils;

use crate::utils::helper;

pub fn run() {
    helper();
}
"#;

    fs::write(&file_a, code_a).unwrap();
    fs::write(&file_b, code_b).unwrap();

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&file_a));
    graph.add_file(parse_file_symbols(&file_b));
    graph.resolve_all();

    fs::remove_file(&file_a).ok();
    fs::remove_file(&file_b).ok();
    fs::remove_dir_all(&dir).ok();

    let symbols_b = graph.files.get(&file_b).unwrap();
    let helper_refs: Vec<_> = symbols_b
        .references
        .iter()
        .filter(|r| r.name == "helper")
        .collect();
    assert_eq!(helper_refs.len(), 1);

    let resolved = helper_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert!(file_path.contains("utils.rs"));
            assert_eq!(symbol_name, "helper");
        }
        _ => panic!("Expected Rust cross-file resolution"),
    }
}

#[test]
fn test_rust_pub_use_reexport_resolution() {
    let dir = unique_tag("temp_rust_reexport");
    let src_dir = format!("{}/src", dir);
    fs::create_dir_all(&src_dir).unwrap();

    let foo_file = write_temp_file(
        &src_dir,
        "foo.rs",
        r#"
pub fn make_thing() {
}
"#,
    );
    let public_file = write_temp_file(
        &src_dir,
        "public.rs",
        r#"
pub use crate::foo::make_thing;
"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.rs",
        r#"
use crate::public::make_thing;

pub fn run() {
    make_thing();
}
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&foo_file));
    graph.add_file(parse_file_symbols(&public_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let make_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "make_thing")
        .collect();
    assert_eq!(make_refs.len(), 1);

    let resolved = make_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&foo_file));
            assert_eq!(symbol_name, "make_thing");
        }
        _ => panic!("Expected Rust re-export resolution"),
    }
}

#[test]
fn test_rust_associated_method_resolution() {
    let dir = unique_tag("temp_rust_assoc");
    let src_dir = format!("{}/src", dir);
    fs::create_dir_all(&src_dir).unwrap();

    let foo_file = write_temp_file(
        &src_dir,
        "foo.rs",
        r#"
pub struct Thing;

impl Thing {
    pub fn new() -> Self {
        Thing
    }
}

"#,
    );
    let consumer_file = write_temp_file(
        &src_dir,
        "consumer.rs",
        r#"
use crate::foo::Thing;

pub fn run() {
    Thing::new();
}
"#,
    );

    let mut graph = SymbolGraph::new(&dir);
    graph.add_file(parse_file_symbols(&foo_file));
    graph.add_file(parse_file_symbols(&consumer_file));
    graph.resolve_all();

    fs::remove_dir_all(&dir).ok();

    let consumer_symbols = graph.files.get(&consumer_file).unwrap();
    let assoc_refs: Vec<_> = consumer_symbols
        .references
        .iter()
        .filter(|r| r.name == "Thing::new")
        .collect();
    assert_eq!(assoc_refs.len(), 1);

    let resolved = assoc_refs[0].resolved_symbol.as_ref().unwrap();
    match resolved {
        ResolvedSymbol::External {
            file_path,
            symbol_name,
            ..
        } => {
            assert_eq!(normalize_path(file_path), normalize_path(&foo_file));
            assert_eq!(symbol_name, "new");
        }
        _ => panic!("Expected Rust associated method resolution"),
    }
}
