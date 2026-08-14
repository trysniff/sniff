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

const SUBJECT: &str = "python fixture process";
const CALLEE: &str = "python fixture target";

fn source_range(source: &str, target: &str) -> IntentionalBoundarySemanticRange {
    let start = source.find(target).expect("fixture target");
    let end = start + target.len();
    let starts = line_starts(source);
    let start_line = line_for_offset(start, &starts);
    let end_line = line_for_offset(end, &starts);
    IntentionalBoundarySemanticRange {
        repository_path: "src/example.py".to_string(),
        start_line_zero_based: start_line as u32,
        start_character_zero_based: start.saturating_sub(starts[start_line]) as u32,
        end_line_zero_based: end_line as u32,
        end_character_zero_based: end.saturating_sub(starts[end_line]) as u32,
    }
}

fn fixture(
    source: &str,
    calls: Vec<IntentionalBoundarySemanticCallFacts>,
) -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    Vec<FileRecord>,
) {
    let file = crate::parser::parse_source_checked("src/example.py", source.as_bytes()).unwrap();
    let parsed_method = file.methods.first().expect("fixture method");
    let parser_unit_id = "ibm-v1:python-ast-fixture".to_string();
    let definition = source_range(source, "process");
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture".to_string(),
        repository: "github.com/example/python-ast".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![IntentionalBoundarySourceFile {
            repository_path: "src/example.py".to_string(),
            object_id: "c".repeat(40),
            byte_length: source.len() as u64,
            source_sha256: "d".repeat(64),
            language: "python".to_string(),
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
    let semantic_census = IntentionalBoundarySemanticCensus {
        schema_version: 1,
        semantic_contract: "fixture".to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers: Vec::new(),
        methods: vec![IntentionalBoundarySemanticMethod {
            parser_unit_id,
            repository_path: "src/example.py".to_string(),
            symbol_name: parsed_method.name.clone(),
            start_line: parsed_method.start_line,
            end_line: parsed_method.end_line,
            indexer: IntentionalBoundaryIndexerKind::Python,
            status: IntentionalBoundarySemanticMethodStatus::Resolved {
                symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                    symbol_id: SUBJECT.to_string(),
                    provider_identity: SUBJECT.to_string(),
                    display_name: Some("process".to_string()),
                    category: IntentionalBoundarySemanticSymbolCategory::Callable,
                    provider_kind: "function".to_string(),
                    documentation: Vec::new(),
                    signature: Some("def process(value)".to_string()),
                    signature_referenced_symbols: Vec::new(),
                    owner: None,
                    definitions: vec![definition.clone()],
                    visibility: IntentionalBoundarySemanticVisibility::Public,
                    surfaces: Vec::new(),
                    origin: IntentionalBoundarySemanticOrigin::Repository,
                    ambiguity_notes: Vec::new(),
                }),
                joined_definition: Some(definition),
            },
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
    IntentionalBoundarySemanticCallFacts {
        caller: SUBJECT.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: if target == "target" {
                CALLEE.to_string()
            } else {
                format!("python fixture {target}")
            },
        },
        callsite: source_range(source, target),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    }
}

#[test]
fn records_returned_compiler_resolved_delegation() {
    let source = "def process(value):\n    return target(value)\n";
    let call = resolved_call(source, "target");
    let (source_census, semantic_census, files) = fixture(source, vec![call.clone()]);

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.languages, ["python"]);
    assert_eq!(census.fact_count, 1);
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
}

#[test]
fn records_async_await_delegation() {
    let source = "async def process(value):\n    return await target(value)\n";
    let call = resolved_call(source, "target");
    let (source_census, semantic_census, files) = fixture(source, vec![call]);

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
}

#[test]
fn accepts_ast_body_inside_a_conservatively_wide_parser_range() {
    let source = "def process(value):\n    return target(value)\nSENTINEL = 1\n";
    let call = resolved_call(source, "target");
    let (source_census, semantic_census, files) = fixture(source, vec![call]);
    assert!(source_census.source_files[0].methods[0].end_line > 2);

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
}

#[test]
fn rejects_nested_calls() {
    let source = "def process(value):\n    return target(normalize(value))\n";
    let calls = vec![
        resolved_call(source, "target"),
        resolved_call(source, "normalize"),
    ];
    let (source_census, semantic_census, files) = fixture(source, calls);

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn rejects_docstring_and_unresolved_call() {
    let source =
        "def process(value):\n    \"\"\"Compatibility adapter.\"\"\"\n    return target(value)\n";
    let mut call = resolved_call(source, "target");
    call.callee = IntentionalBoundarySemanticResolution::Unresolved {
        reason: super::super::IntentionalBoundarySemanticUnresolvedReason::DynamicDispatch,
        raw_target: Some("target".to_string()),
        detail: "fixture".to_string(),
    };
    let (source_census, semantic_census, files) = fixture(source, vec![call]);

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}
