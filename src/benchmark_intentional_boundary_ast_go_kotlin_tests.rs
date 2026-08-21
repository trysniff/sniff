use super::*;

fn go_facts(source: &str) -> (crate::types::FileRecord, AstMethodSyntaxFacts) {
    let path = "src/example.go";
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let facts = go_syntax_facts(path, &record).unwrap();
    (record, facts)
}

fn kotlin_facts(source: &str) -> (crate::types::FileRecord, AstMethodSyntaxFacts) {
    let path = "src/Example.kt";
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let facts = kotlin_syntax_facts(path, &record).unwrap();
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
    let starts = std::iter::once(0)
        .chain(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        )
        .collect::<Vec<_>>();
    let start =
        starts[range.start_line_zero_based as usize] + range.start_character_zero_based as usize;
    let end = starts[range.end_line_zero_based as usize] + range.end_character_zero_based as usize;
    &source[start..end]
}

#[test]
fn records_returned_go_call() {
    let source = "package sample\nfunc Process(value int) int { return target(value) }";
    let (record, facts) = go_facts(source);

    assert_eq!(record.methods.len(), 1);
    let call = fact_for(&record, &facts, "Process")
        .thin_delegation
        .as_ref()
        .expect("thin delegation");
    assert_eq!(range_text(source, call), "target(value)");
}

#[test]
fn records_go_receiver_method_and_ignores_comment() {
    let source = "package sample\ntype Adapter struct{}\nfunc (a Adapter) Process(value int) int {\n// contract\nreturn target(value)\n}";
    let (record, facts) = go_facts(source);

    assert_eq!(record.methods.len(), 1);
    assert!(
        fact_for(&record, &facts, "Process")
            .thin_delegation
            .is_some()
    );
}

#[test]
fn records_direct_go_call_statement() {
    let source = "package sample\nfunc Notify(value int) { target(value) }";
    let (record, facts) = go_facts(source);

    assert!(
        fact_for(&record, &facts, "Notify")
            .thin_delegation
            .is_some()
    );
}

#[test]
fn rejects_go_body_with_extra_statement() {
    let source =
        "package sample\nfunc Process(value int) int { next := value; return target(next) }";
    let (record, facts) = go_facts(source);

    assert!(
        fact_for(&record, &facts, "Process")
            .thin_delegation
            .is_none()
    );
}

#[test]
fn records_versioned_kotlin_deprecation_contract_and_type_reference() {
    let source = concat!(
        "package sample\n",
        "@kotlin.Deprecated(message = \"removed in v2.0; use current\")\n",
        "fun process(value: Int): Int = value\n",
    );
    let (record, facts) = kotlin_facts(source);
    let fact = fact_for(&record, &facts, "process");

    let contract = fact
        .versioned_compatibility_source_contract
        .as_ref()
        .expect("versioned Kotlin compatibility contract");
    assert_eq!(
        range_text(source, contract),
        "@kotlin.Deprecated(message = \"removed in v2.0; use current\")"
    );
    let [requirement] = fact.versioned_compatibility_compiler_references.as_slice() else {
        panic!("expected exact Kotlin compiler reference requirement");
    };
    assert_eq!(range_text(source, &requirement.range), "Deprecated");
}

#[test]
fn rejects_kotlin_annotations_without_an_unambiguous_versioned_literal() {
    for source in [
        "@Deprecated(\"use current\")\nfun process() = Unit\n",
        "@Deprecated(\"removed in $version\")\nfun process() = Unit\n",
        "@Deprecated(message = message)\nfun process() = Unit\n",
        "@Deprecated()\nfun process() = Unit\n",
        concat!(
            "@Deprecated(\"removed in v2\")\n",
            "@Legacy(\"removed in v3\")\n",
            "fun process() = Unit\n",
        ),
    ] {
        let (record, facts) = kotlin_facts(source);
        let fact = fact_for(&record, &facts, "process");
        assert!(
            fact.versioned_compatibility_source_contract.is_none(),
            "{source}"
        );
        assert!(fact.versioned_compatibility_compiler_references.is_empty());
    }
}

#[test]
fn records_attached_versioned_go_deprecation_contract() {
    let source = concat!(
        "package sample\n",
        "// Process preserves callers compiled against v1.\n",
        "//\n",
        "// Deprecated: use ProcessV2; remove in v3.\n",
        "func Process(value int) int { return value }",
    );
    let (record, facts) = go_facts(source);

    let contract = fact_for(&record, &facts, "Process")
        .versioned_compatibility_source_contract
        .as_ref()
        .expect("versioned compatibility contract");
    assert_eq!(
        range_text(source, contract),
        concat!(
            "// Process preserves callers compiled against v1.\n",
            "//\n",
            "// Deprecated: use ProcessV2; remove in v3."
        )
    );
}

#[test]
fn rejects_unversioned_or_detached_go_deprecation_comments() {
    for source in [
        concat!(
            "package sample\n",
            "// Deprecated: use ProcessV2.\n",
            "func Process(value int) int { return value }",
        ),
        concat!(
            "package sample\n",
            "// Deprecated: remove in v3.\n\n",
            "func Process(value int) int { return value }",
        ),
    ] {
        let (record, facts) = go_facts(source);
        assert!(
            fact_for(&record, &facts, "Process")
                .versioned_compatibility_source_contract
                .is_none()
        );
    }
}

#[test]
fn rejects_version_outside_the_go_deprecation_paragraph() {
    let source = concat!(
        "package sample\n",
        "// Process preserves v1 callers.\n",
        "//\n",
        "// Deprecated: use Current.\n",
        "func Process(value int) int { return value }",
    );
    let (record, facts) = go_facts(source);

    assert!(
        fact_for(&record, &facts, "Process")
            .versioned_compatibility_source_contract
            .is_none()
    );
}

#[test]
fn rejects_deprecation_text_inside_a_go_method_body() {
    let source = concat!(
        "package sample\n",
        "func Process(value int) int {\n",
        "// Deprecated: remove in v3.\n",
        "return value\n",
        "}",
    );
    let (record, facts) = go_facts(source);

    assert!(
        fact_for(&record, &facts, "Process")
            .versioned_compatibility_source_contract
            .is_none()
    );
}

#[test]
fn records_versioned_go_block_doc_contract() {
    let source = concat!(
        "package sample\n",
        "/*\n",
        " * Deprecated: retained until version 3.\n",
        " */\n",
        "func Process(value int) int { return value }",
    );
    let (record, facts) = go_facts(source);

    assert!(
        fact_for(&record, &facts, "Process")
            .versioned_compatibility_source_contract
            .is_some()
    );
}

#[test]
fn records_kotlin_expression_body_call() {
    let source = "fun process(value: Int): Int = target(value)";
    let (record, facts) = kotlin_facts(source);

    assert_eq!(record.methods.len(), 1);
    let call = fact_for(&record, &facts, "process")
        .thin_delegation
        .as_ref()
        .expect("thin delegation");
    assert_eq!(range_text(source, call), "target(value)");
}

#[test]
fn records_kotlin_class_method_and_ignores_comment() {
    let source =
        "class Adapter {\nfun process(value: Int): Int {\n// contract\nreturn target(value)\n}\n}";
    let (record, facts) = kotlin_facts(source);

    assert_eq!(record.methods.len(), 1);
    assert!(
        fact_for(&record, &facts, "process")
            .thin_delegation
            .is_some()
    );
}

#[test]
fn rejects_kotlin_body_with_extra_statement() {
    let source = "fun process(value: Int): Int { val next = value; return target(next) }";
    let (record, facts) = kotlin_facts(source);

    assert!(
        fact_for(&record, &facts, "process")
            .thin_delegation
            .is_none()
    );
}

#[test]
fn aligns_nested_kotlin_function_without_name_guessing() {
    let source = "fun outer(): Int {\nfun inner(): Int = target()\nreturn inner()\n}";
    let (record, facts) = kotlin_facts(source);

    assert_eq!(record.methods.len(), 2);
    assert!(fact_for(&record, &facts, "outer").thin_delegation.is_none());
    assert!(fact_for(&record, &facts, "inner").thin_delegation.is_some());
}
