use super::*;

fn retry_fact(
    source: &str,
) -> Option<(
    IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticRange,
)> {
    let path = "src/Retry.kt";
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let facts = kotlin_syntax_facts(path, &record).unwrap();
    assert_eq!(record.methods.len(), 1);
    facts
        .get(&(record.methods[0].name.clone(), record.methods[0].start_line))
        .expect("Kotlin AST fact")
        .distinct_retry_outcomes
        .clone()
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
fn records_distinct_kotlin_if_retry_outcomes() {
    let source = "fun retry(ok: Boolean) {\nwhile (true) if (ok) continue else return\n}";
    let (retryable, terminal) = retry_fact(source).expect("retry evidence");

    assert_eq!(range_text(source, &retryable), "continue");
    assert_eq!(range_text(source, &terminal), "return");
}

#[test]
fn requires_outcomes_from_distinct_kotlin_branches() {
    let source =
        "fun retry(ok: Boolean) {\nwhile (true) {\nif (ok) { continue; return } else work()\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn rejects_unbranched_kotlin_retry_and_terminal_expressions() {
    let source = "fun retry() {\nwhile (true) {\ncontinue\nreturn\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn records_labeled_kotlin_loop_outcomes() {
    let source = "fun retry(ok: Boolean) {\nouter@ while (true) {\nif (ok) continue@outer else break@outer\n}\n}";
    let (retryable, terminal) = retry_fact(source).expect("labeled retry evidence");

    assert_eq!(range_text(source, &retryable), "continue@outer");
    assert_eq!(range_text(source, &terminal), "break@outer");
}

#[test]
fn rejects_kotlin_outcomes_targeting_another_label() {
    let source = "fun retry(ok: Boolean) {\nouter@ while (true) {\nif (ok) continue@missing else break@missing\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn records_kotlin_when_retry_outcomes() {
    let source = "fun retry(value: Int) {\nfor (item in items) {\nwhen (value) {\n1 -> continue\nelse -> throw Error()\n}\n}\n}";
    let (retryable, terminal) = retry_fact(source).expect("when retry evidence");

    assert_eq!(range_text(source, &retryable), "continue");
    assert_eq!(range_text(source, &terminal), "throw Error()");
}

#[test]
fn records_kotlin_try_catch_retry_outcomes() {
    let source =
        "fun retry() {\ndo {\ntry { continue } catch (error: Error) { return }\n} while (true)\n}";

    assert!(retry_fact(source).is_some());
}

#[test]
fn finally_prevents_direct_kotlin_try_catch_proof() {
    let source = "fun retry() {\nwhile (true) {\ntry { continue } catch (error: Error) { return } finally { cleanup() }\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn local_kotlin_return_is_not_a_terminal_method_outcome() {
    let source =
        "fun retry(ok: Boolean) {\nwhile (true) {\nif (ok) continue else return@callback\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn isolates_nested_kotlin_loops_from_outer_branches() {
    let source = "fun retry(ok: Boolean) {\nwhile (true) {\nif (ok) continue else { while (true) { return } }\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn can_record_retry_outcomes_inside_a_nested_kotlin_loop() {
    let source =
        "fun retry(ok: Boolean) {\nwhile (true) {\nwhile (true) if (ok) continue else return\n}\n}";

    assert!(retry_fact(source).is_some());
}

#[test]
fn ignores_kotlin_lambda_control_flow() {
    let source = "fun retry(ok: Boolean) {\nwhile (true) {\nif (ok) continue else callback { return@callback }\n}\n}";

    assert!(retry_fact(source).is_none());
}
