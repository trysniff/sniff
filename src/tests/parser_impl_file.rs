use super::{
    parse_file, parse_file_checked, parse_file_symbols, parse_file_symbols_checked,
    parse_source_symbols_checked,
};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn python_string_fixtures_do_not_become_methods() {
    let root = std::env::temp_dir().join(format!(
        "sniff-python-string-methods-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("fixture.py");
    std::fs::write(
        &path,
        "def real_method():\n    return 1\n\nfixture = \"\"\"\ndef fake_method():\n    return 2\n\"\"\"\n# def fake_comment():\n",
    )
    .unwrap();

    let record = parse_file_checked(&path.to_string_lossy()).unwrap();
    assert_eq!(
        record
            .methods
            .iter()
            .map(|method| method.name.as_str())
            .collect::<Vec<_>>(),
        vec!["real_method"]
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn checked_python_parse_censuses_async_functions() {
    let root =
        std::env::temp_dir().join(format!("sniff-python-async-methods-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("fixture.py");
    std::fs::write(
        &path,
        "async def process(value: Input) -> Output:\n    return await target(value)\n",
    )
    .unwrap();

    let record = parse_file_checked(&path.to_string_lossy()).unwrap();

    assert_eq!(record.methods.len(), 1);
    assert_eq!(record.methods[0].name, "process");
    assert_eq!(record.methods[0].param_count, 1);
    assert_eq!(
        (record.methods[0].start_line, record.methods[0].end_line),
        (1, 2)
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn python_all_controls_top_level_export_visibility() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-python-all-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("candidate.py");
    fs::write(
        &file_path,
        r#"from .types import ReleasePlan

def public_but_internal() -> None:
    pass

def _release_candidate_to_plan(candidate: object) -> ReleasePlan:
    return ReleasePlan(candidate)

__all__ = [
    "_release_candidate_to_plan",
]
"#,
    )
    .unwrap();
    let path = file_path.to_string_lossy();

    let record = parse_file_checked(&path).expect("parse Python methods");
    assert!(
        record
            .methods
            .iter()
            .any(|method| { method.name == "_release_candidate_to_plan" && method.is_exported }),
        "a private-looking name listed in __all__ must be exported: {:?}",
        record.methods
    );
    assert!(
        record
            .methods
            .iter()
            .any(|method| method.name == "public_but_internal" && !method.is_exported),
        "an explicit __all__ excludes otherwise public top-level names: {:?}",
        record.methods
    );

    let symbols = parse_file_symbols_checked(&path).expect("parse Python symbols");
    assert!(symbols.definitions.iter().any(|definition| {
        definition.name == "_release_candidate_to_plan" && definition.is_exported
    }));
    assert!(symbols.exports.iter().any(|export| {
        export.exported_name == "_release_candidate_to_plan"
            && export.local_symbol_name == "_release_candidate_to_plan"
    }));
    assert!(
        !symbols
            .exports
            .iter()
            .any(|export| export.exported_name == "ReleasePlan")
    );

    fs::remove_dir_all(&root).ok();
}

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

fn write_kotlin_suspend_function_type_fixture() -> (std::path::PathBuf, String) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-kotlin-suspend-type-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("Coordinator.kt");
    fs::write(
        &file_path,
        r#"
object Coordinator {
    suspend fun reload(
        transform: suspend (String, String) -> String = { first, second -> first + second },
    ): String = transform("first", "second")
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
fn kotlin_suspend_function_types_are_parsed() {
    let (root, file_path_str) = write_kotlin_suspend_function_type_fixture();
    let record = parse_file_checked(&file_path_str).expect("valid Kotlin should parse");
    assert!(
        record.methods.iter().any(|method| method.name == "reload"),
        "expected suspend function type fixture to yield reload: {:?}",
        record.methods
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn kotlin_internal_visibility_propagates_through_owners() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-kotlin-visibility-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("Runtime.kt");
    fs::write(
        &file_path,
        r#"package demo

internal fun internalTopLevel(): String = "internal"
public fun publicTopLevel(): String = "public"

internal object InternalRuntime {
    fun inheritedInternalVisibility(): String = "internal owner"
}

object PublicRuntime {
    internal fun internalMember(): String = "internal member"
    fun publicMember(): String = "public member"
}
"#,
    )
    .unwrap();
    let path = file_path.to_string_lossy();

    let record = parse_file_checked(&path).expect("parse Kotlin methods");
    for private_name in [
        "internalTopLevel",
        "inheritedInternalVisibility",
        "internalMember",
    ] {
        assert!(
            record
                .methods
                .iter()
                .any(|method| { method.name == private_name && !method.is_exported }),
            "{private_name} must remain repository-private: {:?}",
            record.methods
        );
    }
    for external_name in ["publicTopLevel", "publicMember"] {
        assert!(
            record
                .methods
                .iter()
                .any(|method| { method.name == external_name && method.is_exported }),
            "{external_name} must remain externally visible: {:?}",
            record.methods
        );
    }

    let symbols = parse_file_symbols_checked(&path).expect("parse Kotlin symbols");
    for private_name in [
        "internalTopLevel",
        "InternalRuntime",
        "inheritedInternalVisibility",
        "internalMember",
    ] {
        assert!(
            symbols
                .definitions
                .iter()
                .any(|definition| { definition.name == private_name && !definition.is_exported }),
            "{private_name} symbol must remain repository-private: {:?}",
            symbols.definitions
        );
    }
    for external_name in ["publicTopLevel", "PublicRuntime", "publicMember"] {
        assert!(
            symbols
                .definitions
                .iter()
                .any(|definition| { definition.name == external_name && definition.is_exported }),
            "{external_name} symbol must remain externally visible: {:?}",
            symbols.definitions
        );
    }

    fs::remove_dir_all(root).ok();
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
fn javascript_nested_callbacks_do_not_inherit_container_variable_names() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-js-nested-callback-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("callbacks.js");
    fs::write(
        &file_path,
        r#"
const directHandler = (value) => value.trim()

function stableStringify(value) {
  const keys = Object.keys(value).sort()
  const entries = keys.map(
    (key) => `${key}:${value[key]}`,
  )
  return entries.join(",")
}

export function exportedOuter(values) {
  return values.map((value) => value)
}

export class ExportedBox {
  run(values) {
    return values.map((value) => value)
  }
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    let record = parse_file_checked(&file_path_str).expect("valid JavaScript should parse");
    let method_names = record
        .methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<Vec<_>>();

    assert!(method_names.contains(&"directHandler"));
    assert!(method_names.contains(&"stableStringify"));
    assert!(method_names.contains(&"exportedOuter"));
    assert!(method_names.contains(&"run"));
    assert!(
        method_names
            .iter()
            .filter(|name| name.starts_with("<anonymous@"))
            .count()
            >= 3
    );
    assert!(!method_names.contains(&"entries"));

    let symbols = parse_file_symbols(&file_path_str);
    let anonymous_definitions = symbols
        .definitions
        .iter()
        .filter(|definition| definition.name.starts_with("<anonymous@"))
        .collect::<Vec<_>>();
    assert!(anonymous_definitions.len() >= 3);
    assert!(
        anonymous_definitions
            .iter()
            .all(|definition| !definition.is_exported && definition.owner_type.is_none())
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn typescript_object_members_and_local_export_lists_keep_their_real_boundaries() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-object-members-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("boundaries.tsx");
    fs::write(
        &file_path,
        r#"
export const affiliateLinks = {
  teamChat: () => "https://example.test/chat",
}

const telemetry = {
  beforeSend(event: unknown) {
    return event
  },
}

export const ROUTE_DEPS = {
  get ALERT_WINDOW_SUFFIX() {
    return "today"
  },
}

function Badge() {
  return <span />
}

export { Badge }
"#,
    )
    .unwrap();

    let path = file_path.to_string_lossy().to_string();
    let record = parse_file_checked(&path).expect("valid TypeScript should parse");
    let badge = record
        .methods
        .iter()
        .find(|method| method.name == "Badge")
        .expect("Badge method");
    assert!(
        badge.is_exported,
        "local export list must mark Badge public"
    );
    for member in ["teamChat", "beforeSend", "ALERT_WINDOW_SUFFIX"] {
        assert!(
            record.methods.iter().any(|method| method.name == member),
            "expected object member {member}: {:?}",
            record.methods
        );
    }

    let symbols = parse_file_symbols_checked(&path).expect("index TypeScript symbols");
    let definition = |name: &str| {
        symbols
            .definitions
            .iter()
            .find(|definition| definition.name == name)
            .unwrap_or_else(|| panic!("missing definition {name}"))
    };
    assert!(definition("affiliateLinks").is_exported);
    assert_eq!(
        definition("teamChat").owner_type.as_deref(),
        Some("affiliateLinks")
    );
    assert!(!definition("teamChat").is_exported);
    assert_eq!(
        definition("beforeSend").owner_type.as_deref(),
        Some("telemetry")
    );
    assert_eq!(
        definition("ALERT_WINDOW_SUFFIX").owner_type.as_deref(),
        Some("ROUTE_DEPS")
    );
    assert!(definition("Badge").is_exported);
    assert!(symbols.exports.iter().any(|export| {
        export.exported_name == "affiliateLinks" && export.local_symbol_name == "affiliateLinks"
    }));
    assert!(
        symbols
            .exports
            .iter()
            .any(|export| export.exported_name == "Badge" && export.local_symbol_name == "Badge")
    );
    assert!(
        !symbols
            .exports
            .iter()
            .any(|export| export.exported_name == "teamChat")
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn typescript_nested_functions_and_class_methods_are_parsed() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-ts-nested-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("checkout-rpc.ts");
    fs::write(
        &file_path,
        r#"
export function createCheckoutRpc() {
  async function invokeCheckoutFunction() {
    return true
  }
  const createCheckoutSession = async () => invokeCheckoutFunction()
  return { createCheckoutSession }
}

export class CheckoutController {
  async start() {
    return createCheckoutRpc()
  }
}
"#,
    )
    .unwrap();

    let file_path_str = file_path.to_string_lossy().to_string();
    let record = parse_file_checked(&file_path_str).expect("valid TypeScript should parse");
    let method_names = record
        .methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "createCheckoutRpc",
        "invokeCheckoutFunction",
        "createCheckoutSession",
        "start",
    ] {
        assert!(
            method_names.contains(&expected),
            "expected {expected} to be discovered: {:?}",
            record.methods
        );
    }

    fs::remove_dir_all(root).ok();
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
            .all(|method| method.language == "typescript"),
        "method prompts must retain the TypeScript language: {:?}",
        record.methods
    );
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

#[test]
fn rust_method_boundaries_come_from_ast_spans() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-rust-spans-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("boundaries.rs");
    fs::write(
        &file_path,
        r#"fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

pub trait Contract {
    fn required(&self, value: char);

    fn defaulted(&self) -> bool {
        true
    }
}

fn after_contract() -> bool {
    true
}
"#,
    )
    .unwrap();

    let record = parse_file(&file_path.to_string_lossy());
    let identifier = record
        .methods
        .iter()
        .find(|method| method.name == "is_identifier_char")
        .expect("character literals must not break the method boundary");
    assert_eq!((identifier.start_line, identifier.end_line), (1, 3));
    assert!(!identifier.source.contains("Contract"));

    let required = record
        .methods
        .iter()
        .find(|method| method.name == "required")
        .expect("trait declarations must be discovered");
    assert_eq!(required.start_line, required.end_line);
    assert!(required.source.trim_end().ends_with(';'));

    let after = record
        .methods
        .iter()
        .find(|method| method.name == "after_contract")
        .expect("methods after a trait declaration must remain discoverable");
    assert_eq!((after.start_line, after.end_line), (13, 15));

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
fn checked_parse_accepts_valid_go_const_declarations_without_a_trailing_newline() {
    let source = b"package ecc\n\ntype CurveType uint8\n\nconst (\n    NISTCurve CurveType = 1\n\tCurve25519 CurveType = 2\n\tBitCurve CurveType = 3\n\tBrainpoolCurve CurveType = 4\n)";
    let (root, path) = write_invalid_fixture("go", source);

    let record =
        parse_file_checked(&path).expect("valid Go source must not be excluded from the census");
    assert_eq!(record.source.as_bytes(), source);
    super::super::parse_tree_sitter_source_checked(&path, source)
        .expect("valid Go source must produce AST evidence");
    parse_file_symbols_checked(&path).expect("valid Go source must produce symbol facts");

    fs::remove_dir_all(root).ok();
}

#[test]
fn go_symbol_scan_records_top_level_calls_without_string_or_comment_noise() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-go-top-level-call-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\nfunc normalizeValue(value string) string {\n    return value\n}\n\nvar _ = normalizeValue(\"\")\nvar text = \"fakeCall()\"\n// commentCall()\n",
    )
    .unwrap();

    let symbols = parse_file_symbols_checked(&file_path.to_string_lossy()).expect("parse Go");
    assert!(symbols.references.iter().any(|reference| {
        reference.name == "normalizeValue"
            && reference.line == 7
            && reference.snippet.contains("var _ = normalizeValue")
    }));
    assert!(
        !symbols
            .references
            .iter()
            .any(|reference| reference.name == "fakeCall" || reference.name == "commentCall")
    );

    fs::remove_dir_all(root).ok();
}

#[test]
fn go_symbol_scan_records_grouped_imports_with_package_qualifiers() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sniff-go-grouped-import-{nanos}"));
    fs::create_dir_all(&root).unwrap();
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        r#"package main

import (
    "example.test/project/internal/filedescriptor"
    alias "example.test/project/internal/other"
)

func useImports() {
    filedescriptor.Dup(1)
    alias.Call()
}
"#,
    )
    .unwrap();

    let symbols = parse_file_symbols_checked(&file_path.to_string_lossy()).expect("parse Go");
    assert!(symbols.imports.iter().any(|import| {
        import.local_name == "filedescriptor"
            && import.source_module == "example.test/project/internal/filedescriptor"
    }));
    assert!(symbols.imports.iter().any(|import| {
        import.local_name == "alias"
            && import.source_module == "example.test/project/internal/other"
    }));

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

#[test]
fn checked_symbol_parse_uses_supplied_snapshot_bytes() {
    let symbols =
        parse_source_symbols_checked("snapshot.py", b"def committed_symbol():\n    return 1\n")
            .expect("parse supplied snapshot bytes");

    assert!(
        symbols
            .definitions
            .iter()
            .any(|definition| definition.name == "committed_symbol")
    );
}
