use super::*;

fn facts(path: &str, source: &str) -> (crate::types::FileRecord, AstMethodSyntaxFacts) {
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let facts = js_ts_syntax_facts(path, &record).unwrap();
    (record, facts)
}

fn fact_for<'a>(
    record: &crate::types::FileRecord,
    facts: &'a AstMethodSyntaxFacts,
    name: &str,
) -> &'a super::super::intentional_boundary_ast::AstMethodSyntaxFact {
    let method = record
        .methods
        .iter()
        .find(|method| method.name == name)
        .expect("parser method");
    facts
        .get(&(method.name.clone(), method.start_line))
        .expect("AST fact")
}

fn range_text<'a>(source: &'a str, range: &IntentionalBoundarySemanticRange) -> &'a str {
    let starts = line_starts(source);
    let start =
        starts[range.start_line_zero_based as usize] + range.start_character_zero_based as usize;
    let end = starts[range.end_line_zero_based as usize] + range.end_character_zero_based as usize;
    &source[start..end]
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
fn records_versioned_typescript_function_jsdoc_contract() {
    let source = concat!(
        "/** @deprecated remove after v3.1 */\n",
        "export function process(value: Input): Output { return value; }",
    );
    let (record, facts) = facts("src/example.ts", source);

    let contract = fact_for(&record, &facts, "process")
        .versioned_compatibility_source_contract
        .as_ref()
        .expect("versioned compatibility contract");
    assert_eq!(
        range_text(source, contract),
        "/** @deprecated remove after v3.1 */"
    );
}

#[test]
fn records_versioned_javascript_arrow_and_method_contracts() {
    let source = concat!(
        "/** @deprecated retained until version 3. */\n",
        "export const process = (value) => value;\n",
        "export class Adapter {\n",
        "/** @deprecated remove in v4 */\n",
        "convert(value) { return value; }\n",
        "}",
    );
    let (record, facts) = facts("src/example.js", source);

    assert!(
        fact_for(&record, &facts, "process")
            .versioned_compatibility_source_contract
            .is_some()
    );
    assert!(
        fact_for(&record, &facts, "convert")
            .versioned_compatibility_source_contract
            .is_some()
    );
}

#[test]
fn records_versioned_object_property_contract() {
    let source = concat!(
        "export const api = {\n",
        "/** @deprecated remove in v2 */\n",
        "process(value) { return value; }\n",
        "};",
    );
    let (record, facts) = facts("src/example.js", source);

    assert!(
        fact_for(&record, &facts, "process")
            .versioned_compatibility_source_contract
            .is_some()
    );
}

#[test]
fn records_versioned_function_expression_and_default_export_contracts() {
    let source = concat!(
        "/** @deprecated remove in v2 */\n",
        "export const process = function (value) { return value; };\n",
        "/** @deprecated remove in v3 */\n",
        "export default function convert(value) { return value; }",
    );
    let (record, facts) = facts("src/example.js", source);

    assert!(
        fact_for(&record, &facts, "process")
            .versioned_compatibility_source_contract
            .is_some()
    );
    assert!(
        fact_for(&record, &facts, "convert")
            .versioned_compatibility_source_contract
            .is_some()
    );
}

#[test]
fn rejects_unversioned_detached_and_non_jsdoc_deprecations() {
    for source in [
        "/** @deprecated use current */\nexport function process() {}",
        "/** @deprecated remove in v3 */\n\nexport function process() {}",
        "/* @deprecated remove in v3 */\nexport function process() {}",
    ] {
        let (record, facts) = facts("src/example.ts", source);
        assert!(
            fact_for(&record, &facts, "process")
                .versioned_compatibility_source_contract
                .is_none(),
            "{source}"
        );
    }
}

#[test]
fn rejects_version_outside_the_deprecated_jsdoc_tag() {
    let source = concat!(
        "/**\n",
        " * Preserved since v1.\n",
        " * @deprecated use current.\n",
        " * @since 1.0\n",
        " */\n",
        "export function process() {}",
    );
    let (record, facts) = facts("src/example.ts", source);

    assert!(
        fact_for(&record, &facts, "process")
            .versioned_compatibility_source_contract
            .is_none()
    );
}

#[test]
fn rejects_duplicate_or_inline_since_laundered_deprecated_tags() {
    for source in [
        concat!(
            "/**\n",
            " * @deprecated remove in v2\n",
            " * @deprecated remove in v3\n",
            " */\n",
            "export function process() {}",
        ),
        concat!(
            "/** @deprecated use current @since v2 */\n",
            "export function process() {}",
        ),
    ] {
        let (record, facts) = facts("src/example.ts", source);
        assert!(
            fact_for(&record, &facts, "process")
                .versioned_compatibility_source_contract
                .is_none(),
            "{source}"
        );
    }
}

#[test]
fn rejects_ambiguous_multi_callable_variable_contract() {
    let source = concat!(
        "/** @deprecated remove in v3 */\n",
        "export const first = () => 1, second = () => 2;",
    );
    let (record, facts) = facts("src/example.ts", source);

    assert_eq!(record.methods.len(), 2);
    assert!(
        facts
            .values()
            .all(|fact| { fact.versioned_compatibility_source_contract.is_none() })
    );
}

#[test]
fn rejects_deprecated_jsdoc_inside_a_function_body() {
    let source = concat!(
        "export function process() {\n",
        "/** @deprecated remove in v3 */\n",
        "return 1;\n",
        "}",
    );
    let (record, facts) = facts("src/example.ts", source);

    assert!(
        fact_for(&record, &facts, "process")
            .versioned_compatibility_source_contract
            .is_none()
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

#[test]
fn records_distinct_switch_retry_and_terminal_outcomes() {
    let source = concat!(
        "export function process() { while (true) { switch (target()) { ",
        "case 'retry': continue; default: return 1; } } }",
    );
    let (record, facts) = facts("src/example.js", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .distinct_retry_outcomes
            .is_some()
    );
}

#[test]
fn records_typescript_if_retry_and_throw_outcomes() {
    let source = concat!(
        "export async function process(): Promise<void> { for (;;) { ",
        "if (await retryable()) { continue; } else { throw new Error('terminal'); } } }",
    );
    let (record, facts) = facts("src/example.ts", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .distinct_retry_outcomes
            .is_some()
    );
}

#[test]
fn retry_and_terminal_in_one_if_branch_are_not_distinct() {
    let source = concat!(
        "export function process() { while (true) { if (retryable()) { ",
        "continue; return 1; } else { work(); } } }",
    );
    let (record, facts) = facts("src/example.js", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .distinct_retry_outcomes
            .is_none()
    );
}

#[test]
fn nested_loop_continue_does_not_count_for_outer_branches() {
    let source = concat!(
        "export function process() { while (true) { if (retryable()) { ",
        "while (nested()) { continue; } } else { return 1; } } }",
    );
    let (record, facts) = facts("src/example.js", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .distinct_retry_outcomes
            .is_none()
    );
}

#[test]
fn switch_break_does_not_count_as_loop_terminal() {
    let source = concat!(
        "export function process() { while (true) { switch (target()) { ",
        "case 'retry': continue; default: break; } } }",
    );
    let (record, facts) = facts("src/example.js", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .distinct_retry_outcomes
            .is_none()
    );
}

#[test]
fn labeled_break_can_be_a_terminal_loop_outcome() {
    let source = concat!(
        "export function process() { attempts: while (true) { switch (target()) { ",
        "case 'retry': continue attempts; default: break attempts; } } }",
    );
    let (record, facts) = facts("src/example.js", source);

    let method = &record.methods[0];
    assert!(
        facts[&(method.name.clone(), method.start_line)]
            .distinct_retry_outcomes
            .is_some()
    );
}
