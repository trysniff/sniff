use super::*;

fn facts(path: &str, source: &str) -> (crate::types::FileRecord, AstMethodSyntaxFacts) {
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let facts = js_ts_syntax_facts(path, &record).unwrap();
    (record, facts)
}

#[test]
fn records_returned_javascript_call() {
    let source = "export function process(value) { return target(value); }";
    let (record, facts) = facts("src/example.js", source);

    assert_eq!(record.methods.len(), 1);
    let method = &record.methods[0];
    let fact = facts
        .get(&(method.name.clone(), method.start_line))
        .expect("function AST fact");
    let call = fact.thin_delegation.as_ref().expect("thin delegation");
    assert_eq!(call.repository_path, "src/example.js");
    assert_eq!(
        &source[call.start_character_zero_based as usize..call.end_character_zero_based as usize],
        "target(value)"
    );
}

#[test]
fn records_awaited_typescript_arrow_call() {
    let source =
        "export const process = async (value: Input): Promise<Output> => await target(value);";
    let (record, facts) = facts("src/example.ts", source);

    assert_eq!(record.methods.len(), 1);
    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .thin_delegation
            .is_some()
    );
}

#[test]
fn records_class_method_without_duplicate_function_candidate() {
    let source = "export class Adapter { process(value: Input) { return target(value); } }";
    let (record, facts) = facts("src/example.ts", source);

    assert_eq!(record.methods.len(), 1);
    assert_eq!(facts.len(), 1);
    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .thin_delegation
            .is_some()
    );
}

#[test]
fn aligns_two_same_line_arrows_by_ast_span_order() {
    let source = "export const first = (value) => target(value); export const second = (value) => other(value);";
    let (record, facts) = facts("src/example.js", source);

    assert_eq!(record.methods.len(), 2);
    assert_eq!(facts.len(), 2);
    assert!(facts.contains_key(&("first".to_string(), 1)));
    assert!(facts.contains_key(&("second".to_string(), 1)));
}

#[test]
fn rejects_directive_and_extra_statement_bodies() {
    let source =
        "export function process(value) { 'use strict'; const next = value; return target(next); }";
    let (record, facts) = facts("src/example.js", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .thin_delegation
            .is_none()
    );
}

#[test]
fn unwraps_typescript_assertion_around_call() {
    let source =
        "export function process(value: Input): Output { return target(value) as Output; }";
    let (record, facts) = facts("src/example.ts", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .thin_delegation
            .is_some()
    );
}
