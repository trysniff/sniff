use super::{parse_file, parse_file_checked, parse_file_symbols, parse_file_symbols_checked};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_kotlin_fixture() -> (std::path::PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-kotlin-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("Main.kt");
    fs::write(
        &file_path,
        r#"
package demo

class Greeter {
    fun greet(name: String): String {
        return "Hello, $name"
    }
}

fun topLevel(value: Int): Int {
    return value + 1
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    (root, file_path_str)
}

fn write_kotlin_composable_fixture() -> (std::path::PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-kotlin-composable-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("DashboardHero.kt");
    fs::write(
        &file_path,
        r#"
package demo

import androidx.compose.runtime.Composable

@Composable
fun DashboardHero(nextDose: String?): String {
    return nextDose ?: "none"
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    (root, file_path_str)
}

#[test]
fn kotlin_file_methods_are_parsed() {
    let (root, file_path_str) = write_kotlin_fixture();
    let record = parse_file(&file_path_str);
    assert_eq!(record.language, "kotlin");
    assert!(
        record.methods.iter().any(|method| method.name == "greet"),
        "expected Kotlin member functions to be extracted: {:?}",
        record.methods
    );
    assert!(
        record
            .methods
            .iter()
            .any(|method| method.name == "topLevel"),
        "expected Kotlin top-level functions to be extracted: {:?}",
        record.methods
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn kotlin_file_symbols_are_parsed() {
    let (root, file_path_str) = write_kotlin_fixture();
    let symbols = parse_file_symbols(&file_path_str);
    assert!(
        symbols
            .definitions
            .iter()
            .any(|definition| definition.name == "Greeter"),
        "expected Kotlin classes to be captured as definitions: {:?}",
        symbols.definitions
    );
    assert!(
        symbols
            .definitions
            .iter()
            .any(|definition| definition.name == "topLevel"),
        "expected Kotlin top-level functions to be captured as definitions: {:?}",
        symbols.definitions
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn kotlin_composable_function_keeps_its_real_name() {
    let (root, file_path_str) = write_kotlin_composable_fixture();
    let record = parse_file(&file_path_str);
    assert!(
        record
            .methods
            .iter()
            .any(|method| method.name == "DashboardHero"),
        "expected annotated Kotlin composables to keep the real function name: {:?}",
        record.methods
    );
    assert!(
        !record
            .methods
            .iter()
            .any(|method| method.name == "Composable"),
        "expected the annotation name not to be used as the method name: {:?}",
        record.methods
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn typescript_type_annotations_do_not_become_fake_methods() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-arrow-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("toast.ts");
    fs::write(
        &file_path,
        r#"
type State = {
  value: string
}

const listeners: Array<() => void> = []

const realHandler = () => {
  return listeners.length
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    let record = parse_file(&file_path_str);
    assert_eq!(
        record.methods.len(),
        1,
        "expected only the real arrow function to be extracted: {:?}",
        record.methods
    );
    assert_eq!(record.methods[0].name, "realHandler");
    fs::remove_dir_all(&root).ok();
}

#[test]
fn typescript_generic_arrow_functions_are_parsed() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-generic-arrow-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("generic.ts");
    fs::write(
        &file_path,
        r#"
const wrap = <T>(value: T) => {
  return value
}

const plain = (value: string) => value.trim()
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    let record = parse_file(&file_path_str);
    let method_names: Vec<_> = record
        .methods
        .iter()
        .map(|method| method.name.as_str())
        .collect();
    assert!(
        method_names.contains(&"wrap"),
        "expected the generic arrow function to be extracted: {:?}",
        record.methods
    );
    assert!(
        method_names.contains(&"plain"),
        "expected the normal arrow function to be extracted: {:?}",
        record.methods
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn unsupported_extensions_fail_closed() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-unsupported-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("notes.txt");
    fs::write(
        &file_path,
        "fn maybe_not_real() {\n  this should not be parsed\n}\n",
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    let record = parse_file(&file_path_str);
    let symbols = parse_file_symbols(&file_path_str);

    assert!(
        record.methods.is_empty(),
        "unsupported files should not invent methods"
    );
    assert!(
        record.language.is_empty(),
        "unsupported files should not claim a language"
    );
    assert!(
        symbols.definitions.is_empty()
            && symbols.imports.is_empty()
            && symbols.exports.is_empty()
            && symbols.references.is_empty(),
        "unsupported files should not invent symbols: {:?}",
        symbols
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn checked_parser_reports_missing_source_files() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir()
        .join(format!("sniff-missing-{nanos}.py"))
        .to_string_lossy()
        .to_string();

    let err = parse_file_checked(&path).expect_err("missing source should fail explicitly");
    assert!(err.contains("failed to read source file"), "{err}");
}

#[test]
fn uppercase_extensions_are_supported() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-uppercase-ext-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("Widget.TS");
    fs::write(
        &file_path,
        "export function renderWidget() {\n  return 42;\n}\n",
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    let record = parse_file(&file_path_str);
    let symbols = parse_file_symbols(&file_path_str);

    assert_eq!(record.language, "typescript");
    assert!(
        record
            .methods
            .iter()
            .any(|method| method.name == "renderWidget"),
        "expected uppercase extensions to parse as TypeScript: {:?}",
        record.methods
    );
    assert!(
        symbols
            .definitions
            .iter()
            .any(|definition| definition.name == "renderWidget"),
        "expected uppercase extensions to contribute symbols: {:?}",
        symbols.definitions
    );

    fs::remove_dir_all(&root).ok();
}

fn write_rust_fixture() -> (std::path::PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-rust-fn-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("summary.rs");
    fs::write(
        &file_path,
        r#"
fn verdict_counts() -> (usize, usize) {
    (0, 0)
}

pub(super) fn append_footer() {}

pub(crate) async fn print_summary<'a>(value: &'a str) -> &'a str {
    value
}

pub(in crate::parser) fn bridge(value: usize) -> usize {
    value
}

#[cfg(test)]
mod tests {
    fn verdict() {}
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    (root, file_path_str)
}

#[test]
fn rust_file_methods_include_visibility_and_async_signatures() {
    let (root, file_path_str) = write_rust_fixture();
    let record = parse_file(&file_path_str);
    let method_names: Vec<_> = record
        .methods
        .iter()
        .map(|method| method.name.as_str())
        .collect();
    assert!(
        method_names.contains(&"append_footer"),
        "expected pub(super) functions to be extracted: {:?}",
        record.methods
    );
    assert!(
        method_names.contains(&"print_summary"),
        "expected async pub(crate) functions to be extracted: {:?}",
        record.methods
    );
    assert!(
        method_names.contains(&"bridge"),
        "expected pub(in ...) functions to be extracted: {:?}",
        record.methods
    );
    assert!(
        method_names.contains(&"verdict_counts"),
        "expected plain functions to still be extracted: {:?}",
        record.methods
    );
    fs::remove_dir_all(&root).ok();
}

fn write_rust_impl_fixture() -> (std::path::PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-rust-impl-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("pipeline.rs");
    fs::write(
        &file_path,
        r#"
pub(super) struct Pipeline<T> {
    value: T,
}

impl<T> Pipeline<T> {
    pub(super) fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Clone> Clone for Pipeline<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    (root, file_path_str)
}

#[test]
fn rust_file_methods_cover_generic_impls_and_pub_super_structs() {
    let (root, file_path_str) = write_rust_impl_fixture();
    let record = parse_file(&file_path_str);
    let method_names: Vec<_> = record
        .methods
        .iter()
        .map(|method| method.name.as_str())
        .collect();
    assert!(
        method_names.contains(&"new"),
        "expected generic inherent impl methods to be extracted: {:?}",
        record.methods
    );
    assert!(
        method_names.contains(&"clone"),
        "expected trait impl methods to be extracted: {:?}",
        record.methods
    );
    let symbols = parse_file_symbols(&file_path_str);
    assert!(
        symbols
            .definitions
            .iter()
            .any(|definition| definition.name == "Pipeline" && definition.is_exported),
        "expected pub(super) structs to be captured as definitions: {:?}",
        symbols.definitions
    );
    fs::remove_dir_all(&root).ok();
}

fn write_invalid_fixture(extension: &str, source: &[u8]) -> (std::path::PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-invalid-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join(format!("broken.{extension}"));
    fs::write(&file_path, source).unwrap();
    let file_path_str = file_path.to_string_lossy().to_string();
    (root, file_path_str)
}

#[test]
fn checked_parse_rejects_malformed_python_instead_of_returning_zero_methods() {
    let (root, path) = write_invalid_fixture("py", b"def broken():\nreturn 1\n");
    let error = parse_file_checked(&path).expect_err("malformed Python must fail closed");
    assert!(error.contains("failed to parse"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn checked_parse_rejects_malformed_javascript_instead_of_returning_zero_methods() {
    let (root, path) = write_invalid_fixture("ts", b"export function broken( { return 1; }\n");
    let error = parse_file_checked(&path).expect_err("malformed TypeScript must fail closed");
    assert!(error.contains("failed to parse"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn checked_parse_rejects_malformed_rust_instead_of_returning_zero_methods() {
    let (root, path) = write_invalid_fixture("rs", b"fn broken( {\n");
    let error = parse_file_checked(&path).expect_err("malformed Rust must fail closed");
    assert!(error.contains("failed to parse"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn checked_parse_rejects_malformed_go_instead_of_returning_zero_methods() {
    let (root, path) = write_invalid_fixture("go", b"package broken\n\nfunc broken( {\n");
    let error = parse_file_checked(&path).expect_err("malformed Go must fail closed");
    assert!(error.contains("failed to parse"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn checked_parse_rejects_malformed_kotlin_instead_of_returning_zero_methods() {
    let (root, path) = write_invalid_fixture("kt", b"fun broken( {\n");
    let error = parse_file_checked(&path).expect_err("malformed Kotlin must fail closed");
    assert!(error.contains("failed to parse"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn checked_symbol_parse_rejects_invalid_utf8_before_graph_construction() {
    let (root, path) = write_invalid_fixture("py", b"def ok():\n    return 1\n\xff");
    let error = parse_file_symbols_checked(&path)
        .expect_err("invalid UTF-8 must fail closed before symbol extraction");
    assert!(error.contains("not valid UTF-8"), "{error}");
    fs::remove_dir_all(root).ok();
}
