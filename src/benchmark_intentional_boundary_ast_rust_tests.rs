use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryAstFact, IntentionalBoundaryAstMethodStatus, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundarySemanticCallFacts,
    IntentionalBoundarySemanticDispatch, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticSymbolFacts, IntentionalBoundarySemanticVisibility,
    IntentionalBoundarySourceFile,
};
use crate::types::FileRecord;

const SUBJECT: &str = "rust fixture process";
const CALLEE: &str = "rust fixture target";

fn range(start: usize, end: usize) -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: "src/lib.rs".to_string(),
        start_line_zero_based: 0,
        start_character_zero_based: start as u32,
        end_line_zero_based: 0,
        end_character_zero_based: end as u32,
    }
}

fn fixture(
    source: &str,
    calls: Vec<IntentionalBoundarySemanticCallFacts>,
    status: Option<IntentionalBoundarySemanticMethodStatus>,
) -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    Vec<FileRecord>,
) {
    let file = crate::parser::parse_source_checked("src/lib.rs", source.as_bytes()).unwrap();
    let parsed_method = file.methods.first().expect("fixture method");
    let parser_unit_id = "ibm-v1:rust-ast-fixture".to_string();
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture".to_string(),
        repository: "github.com/example/ast".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![IntentionalBoundarySourceFile {
            repository_path: "src/lib.rs".to_string(),
            object_id: "c".repeat(40),
            byte_length: source.len() as u64,
            source_sha256: "d".repeat(64),
            language: "rust".to_string(),
            methods: vec![IntentionalBoundaryMethodCensusEntry {
                parser_unit_id: parser_unit_id.clone(),
                symbol_name: parsed_method.name.clone(),
                start_line: parsed_method.start_line,
                end_line: parsed_method.end_line,
                source_sha256: "e".repeat(64),
                is_exported: parsed_method.is_exported,
            }],
        }],
        source_file_count: 1,
        method_count: 1,
        census_sha256: "f".repeat(64),
    };
    let semantic_status =
        status.unwrap_or_else(|| IntentionalBoundarySemanticMethodStatus::Resolved {
            symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                symbol_id: SUBJECT.to_string(),
                provider_identity: SUBJECT.to_string(),
                display_name: Some("process".to_string()),
                category: IntentionalBoundarySemanticSymbolCategory::Callable,
                provider_kind: "function".to_string(),
                documentation: Vec::new(),
                signature: Some("fn process(value: i32) -> i32".to_string()),
                signature_referenced_symbols: Vec::new(),
                owner: None,
                definitions: vec![range(7, 14)],
                visibility: IntentionalBoundarySemanticVisibility::Public,
                surfaces: Vec::new(),
                origin: IntentionalBoundarySemanticOrigin::Repository,
                ambiguity_notes: Vec::new(),
            }),
            joined_definition: Some(range(7, 14)),
        });
    let semantic_census = IntentionalBoundarySemanticCensus {
        schema_version: 1,
        semantic_contract: "fixture".to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers: Vec::new(),
        methods: vec![IntentionalBoundarySemanticMethod {
            parser_unit_id,
            repository_path: "src/lib.rs".to_string(),
            symbol_name: parsed_method.name.clone(),
            start_line: parsed_method.start_line,
            end_line: parsed_method.end_line,
            indexer: IntentionalBoundaryIndexerKind::Rust,
            status: semantic_status,
            occurrences: Vec::new(),
            calls,
            relationships: Vec::new(),
            imports: Vec::new(),
            test_relationships: Vec::new(),
        }],
        resolved_method_count: 1,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_census_sha256: "1".repeat(64),
    };
    (source_census, semantic_census, vec![file])
}

fn resolved_call(source: &str, target: &str) -> IntentionalBoundarySemanticCallFacts {
    let start = source.find(target).expect("call target");
    IntentionalBoundarySemanticCallFacts {
        caller: SUBJECT.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: if target == "target" {
                CALLEE.to_string()
            } else {
                format!("rust fixture {target}")
            },
        },
        callsite: range(start, start + target.len()),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    }
}

#[test]
fn records_one_ast_and_compiler_resolved_delegation() {
    let source = "pub fn process(value: i32) -> i32 { target(value) }";
    let call = resolved_call(source, "target");
    let (source_census, semantic_census, files) = fixture(source, vec![call.clone()], None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.languages, ["rust"]);
    assert_eq!(census.method_count, 1);
    assert_eq!(census.fact_count, 1);
    assert_eq!(census.methods[0].language, "rust");
    let IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } = &census.methods[0].status
    else {
        panic!("expected resolved AST method");
    };
    assert!(matches!(
        &facts[0],
        IntentionalBoundaryAstFact::ThinDelegation {
            compiler_callsite,
            resolved_callee_symbol_id,
            ..
        } if compiler_callsite == &call.callsite && resolved_callee_symbol_id == CALLEE
    ));
    assert_eq!(census.ast_census_sha256.len(), 64);
}

#[test]
fn records_exact_versioned_compatibility_annotation() {
    let source = "#[deprecated(since = \"1.2.0\", note = \"use current\")]\npub fn process(value: i32) -> i32 { value }";
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
    let IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } = &census.methods[0].status
    else {
        panic!("expected resolved AST method");
    };
    let [IntentionalBoundaryAstFact::VersionedCompatibilitySourceContract { contract }] =
        facts.as_slice()
    else {
        panic!("expected one versioned compatibility annotation");
    };
    assert_eq!(contract.repository_path, "src/lib.rs");
    assert_eq!(contract.start_line_zero_based, 0);
}

#[test]
fn unversioned_deprecation_is_not_compatibility_evidence() {
    let source =
        "#[deprecated(note = \"use current\")]\npub fn process(value: i32) -> i32 { value }";
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn records_retry_and_terminal_outcomes_in_the_same_loop_match() {
    let source = concat!(
        "pub fn process() -> Result<i32, ()> { loop { match target() { ",
        "Ok(value) => return Ok(value), Err(_) => continue } } }",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
    let IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } = &census.methods[0].status
    else {
        panic!("expected resolved AST method");
    };
    let [
        IntentionalBoundaryAstFact::DistinctRetryOutcomes {
            retryable_outcome,
            terminal_outcome,
        },
    ] = facts.as_slice()
    else {
        panic!("expected one distinct retry outcome fact");
    };
    assert!(
        retryable_outcome.start_character_zero_based > terminal_outcome.start_character_zero_based
    );
}

#[test]
fn terminal_match_without_retry_does_not_create_retry_evidence() {
    let source = concat!(
        "pub fn process() -> Result<i32, ()> { loop { match target() { ",
        "Ok(value) => return Ok(value), Err(_) => break Err(()) } } }",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn nested_loop_continue_does_not_count_for_the_outer_match() {
    let source = concat!(
        "pub fn process() -> Result<i32, ()> { loop { match target() { ",
        "Ok(value) => return Ok(value), Err(_) => loop { continue } } } }",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn retry_and_terminal_flow_in_one_match_arm_is_not_distinct() {
    let source = concat!(
        "pub fn process() -> Result<i32, ()> { loop { match target() { ",
        "Ok(_) => {}, Err(_) => { if should_retry() { continue; } return Err(()) } } } }",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn records_an_exact_header_generator_marker() {
    let source = "// @generated\npub fn process(value: i32) -> i32 { value }";
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
    let IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } = &census.methods[0].status
    else {
        panic!("expected resolved AST method");
    };
    let [IntentionalBoundaryAstFact::GeneratorMarker { marker }] = facts.as_slice() else {
        panic!("expected one generator marker");
    };
    assert_eq!(marker.start_line_zero_based, 0);
}

#[test]
fn generated_text_inside_code_is_not_a_generator_marker() {
    let source = "pub fn process() -> &'static str { \"// @generated\" }";
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn rejects_nested_calls_even_when_outer_body_is_one_expression() {
    let source = "pub fn process(value: i32) -> i32 { target(normalize(value)) }";
    let calls = vec![
        resolved_call(source, "target"),
        resolved_call(source, "normalize"),
    ];
    let (source_census, semantic_census, files) = fixture(source, calls, None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn rejects_extra_statements_and_unresolved_calls() {
    let source = "pub fn process(value: i32) -> i32 { let next = value + 1; target(next) }";
    let mut call = resolved_call(source, "target");
    call.callee = IntentionalBoundarySemanticResolution::Unresolved {
        reason: super::super::IntentionalBoundarySemanticUnresolvedReason::DynamicDispatch,
        raw_target: Some("target".to_string()),
        detail: "fixture".to_string(),
    };
    let (source_census, semantic_census, files) = fixture(source, vec![call], None);

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn preserves_compiler_unresolved_status_without_ast_facts() {
    let source = "pub fn process(value: i32) -> i32 { target(value) }";
    let status = IntentionalBoundarySemanticMethodStatus::Unresolved {
        reason: super::super::IntentionalBoundarySemanticUnresolvedReason::MissingIndexerFact,
        raw_target: Some("process".to_string()),
        detail: "fixture".to_string(),
    };
    let (source_census, semantic_census, files) = fixture(source, Vec::new(), Some(status));

    let census = derive_rust_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
    assert!(matches!(
        census.methods[0].status,
        IntentionalBoundaryAstMethodStatus::Unresolved { .. }
    ));
}
