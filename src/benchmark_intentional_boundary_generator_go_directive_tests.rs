use super::*;
use crate::benchmark::release::IntentionalBoundarySemanticRange;

fn directive(line: u32, source_text: &str) -> IntentionalBoundaryGoGenerateDirective {
    IntentionalBoundaryGoGenerateDirective {
        location: IntentionalBoundarySemanticRange {
            repository_path: "tools/gen.go".to_string(),
            start_line_zero_based: line,
            start_character_zero_based: 0,
            end_line_zero_based: line,
            end_character_zero_based: source_text.len() as u32,
        },
        source_text: source_text.to_string(),
    }
}

#[test]
fn go_quoted_executable_words_follow_interpreted_string_escapes() {
    for command in [
        "//go:generate \"go\" run ./cmd/gen",
        "//go:generate \"\\x67o\" run ./cmd/gen",
        "//go:generate \"\\u0067o\" run ./cmd/gen",
        "//go:generate \"\\147o\" run ./cmd/gen",
    ] {
        assert!(
            directives_use_only_go(&[directive(1, command)]),
            "{command}"
        );
    }
}

#[test]
fn quoted_aliases_use_the_same_go_word_decoder() {
    assert!(directives_use_only_go(&[
        directive(
            1,
            "//go:generate -command \"generate\" \"go\" run ./cmd/gen"
        ),
        directive(2, "//go:generate \"generate\""),
    ]));
}

#[test]
fn malformed_or_environment_dependent_executables_are_rejected() {
    for command in [
        "//go:generate \"go run ./cmd/gen",
        "//go:generate \"\\x6go\" run ./cmd/gen",
        "//go:generate \"go\"run ./cmd/gen",
        "//go:generate \"\\777\" run ./cmd/gen",
        "//go:generate \"$GENERATOR\" run ./cmd/gen",
        "//go:generate $GENERATOR run ./cmd/gen",
    ] {
        assert!(
            !directives_use_only_go(&[directive(1, command)]),
            "{command}"
        );
    }
}

#[test]
fn duplicate_file_local_aliases_are_rejected_like_go_generate() {
    assert!(!directives_use_only_go(&[
        directive(1, "//go:generate -command generate go run ./cmd/one"),
        directive(2, "//go:generate -command generate go run ./cmd/two"),
        directive(3, "//go:generate generate"),
    ]));
}

#[test]
fn aliases_still_reset_at_each_source_file() {
    let mut second = directive(1, "//go:generate generate");
    second.location.repository_path = "tools/other.go".to_string();
    assert!(!directives_use_only_go(&[
        directive(1, "//go:generate -command generate go run ./cmd/gen"),
        second,
    ]));
}
