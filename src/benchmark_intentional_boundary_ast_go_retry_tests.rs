use super::*;

fn retry_fact(
    source: &str,
) -> Option<(
    IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticRange,
)> {
    let path = "src/retry.go";
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let facts = go_syntax_facts(path, &record).unwrap();
    assert_eq!(record.methods.len(), 1);
    facts
        .get(&(record.methods[0].name.clone(), record.methods[0].start_line))
        .expect("Go AST fact")
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
fn records_distinct_go_if_retry_outcomes() {
    let source =
        "package sample\nfunc retry(ok bool) {\nfor {\nif ok { continue } else { return }\n}\n}";
    let (retryable, terminal) = retry_fact(source).expect("retry evidence");

    assert_eq!(range_text(source, &retryable), "continue");
    assert_eq!(range_text(source, &terminal), "return");
}

#[test]
fn requires_outcomes_from_distinct_go_branches() {
    let source = "package sample\nfunc retry(ok bool) {\nfor {\nif ok { continue; return } else { work() }\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn rejects_unbranched_go_retry_and_terminal_statements() {
    let source = "package sample\nfunc retry() {\nfor {\ncontinue\nreturn\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn records_labeled_go_loop_outcomes() {
    let source = "package sample\nfunc retry(ok bool) {\nouter: for {\nif ok { continue outer } else { break outer }\n}\n}";
    let (retryable, terminal) = retry_fact(source).expect("labeled retry evidence");

    assert_eq!(range_text(source, &retryable), "continue outer");
    assert_eq!(range_text(source, &terminal), "break outer");
}

#[test]
fn records_direct_go_loop_break_as_terminal() {
    let source =
        "package sample\nfunc retry(ok bool) {\nfor {\nif ok { continue } else { break }\n}\n}";
    let (_, terminal) = retry_fact(source).expect("direct break evidence");

    assert_eq!(range_text(source, &terminal), "break");
}

#[test]
fn rejects_go_outcomes_targeting_another_label() {
    let source = "package sample\nfunc retry(ok bool) {\nouter: for {\nif ok { continue missing } else { break missing }\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn does_not_treat_go_switch_break_as_loop_terminal() {
    let source = "package sample\nfunc retry(value int) {\nfor {\nswitch value {\ncase 1: continue\ndefault: break\n}\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn records_labeled_go_loop_break_from_inside_switch() {
    let source = "package sample\nfunc retry(value int) {\nouter: for {\nswitch value {\ncase 1: continue outer\ndefault: break outer\n}\n}\n}";
    let (_, terminal) = retry_fact(source).expect("labeled switch break evidence");

    assert_eq!(range_text(source, &terminal), "break outer");
}

#[test]
fn records_go_expression_switch_retry_outcomes() {
    let source = "package sample\nfunc retry(value int) {\nfor {\nswitch value {\ncase 1: continue\ndefault: return\n}\n}\n}";

    assert!(retry_fact(source).is_some());
}

#[test]
fn records_go_type_switch_retry_outcomes() {
    let source = "package sample\nfunc retry(value any) {\nfor {\nswitch value.(type) {\ncase int: continue\ndefault: return\n}\n}\n}";

    assert!(retry_fact(source).is_some());
}

#[test]
fn records_go_select_retry_outcomes() {
    let source = "package sample\nfunc retry(ch chan int) {\nfor {\nselect {\ncase <-ch: continue\ndefault: return\n}\n}\n}";

    assert!(retry_fact(source).is_some());
}

#[test]
fn isolates_nested_go_loops_from_outer_branches() {
    let source = "package sample\nfunc retry(ok bool) {\nfor {\nif ok { continue } else { for { return } }\n}\n}";

    assert!(retry_fact(source).is_none());
}

#[test]
fn can_record_retry_outcomes_inside_a_nested_go_loop() {
    let source = "package sample\nfunc retry(ok bool) {\nfor {\nfor {\nif ok { continue } else { return }\n}\n}\n}";

    assert!(retry_fact(source).is_some());
}

#[test]
fn ignores_go_function_literal_control_flow() {
    let source = "package sample\nfunc retry(ok bool) {\nfor {\nif ok { continue } else { callback := func() { return }; callback() }\n}\n}";

    assert!(retry_fact(source).is_none());
}
