use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryAstFact, IntentionalBoundaryAstMethodStatus, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundarySemanticCallFacts,
    IntentionalBoundarySemanticDispatch, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOccurrenceRole,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticReferenceTarget,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSourceReference,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceFile,
};
use crate::types::FileRecord;

const SUBJECT: &str = "python fixture process";
const CALLEE: &str = "python fixture target";
const WARN: &str = "scip-python python python-stdlib 3.11 _warnings/warn().";
const DEPRECATION_WARNING: &str =
    "scip-python python python-stdlib 3.11 builtins/DeprecationWarning#";

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
    fixture_with_references(source, calls, Vec::new())
}

fn fixture_with_references(
    source: &str,
    calls: Vec<IntentionalBoundarySemanticCallFacts>,
    source_references: Vec<IntentionalBoundarySemanticSourceReference>,
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
        source_references,
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
                    signatures: vec![
                        crate::benchmark::IntentionalBoundarySemanticSignatureFacts {
                            language: "python".to_string(),
                            text: "def process(value)".to_string(),
                            referenced_symbols: Vec::new(),
                        },
                    ],
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

fn resolved_source_reference(
    location: IntentionalBoundarySemanticRange,
    provider_identity: &str,
    origin: IntentionalBoundarySemanticOrigin,
) -> IntentionalBoundarySemanticSourceReference {
    IntentionalBoundarySemanticSourceReference {
        indexer: IntentionalBoundaryIndexerKind::Python,
        location,
        roles: vec![IntentionalBoundarySemanticOccurrenceRole::Read],
        target: IntentionalBoundarySemanticResolution::Resolved {
            value: IntentionalBoundarySemanticReferenceTarget {
                symbol_id: format!(
                    "scip-global:{}:{}",
                    provider_identity.len(),
                    provider_identity
                ),
                provider_identity: provider_identity.to_string(),
                display_name: None,
                provider_kind: "UnspecifiedKind".to_string(),
                origin,
            },
        },
    }
}

fn warning_references(source: &str) -> Vec<IntentionalBoundarySemanticSourceReference> {
    let warning_start = source.find(".warn").expect("warning attribute") + 1;
    let mut warning_range = source_range(source, ".warn");
    warning_range.start_character_zero_based += 1;
    assert_eq!(&source[warning_start..warning_start + 4], "warn");
    vec![
        resolved_source_reference(
            warning_range,
            WARN,
            IntentionalBoundarySemanticOrigin::External,
        ),
        resolved_source_reference(
            source_range(source, "DeprecationWarning"),
            DEPRECATION_WARNING,
            IntentionalBoundarySemanticOrigin::External,
        ),
    ]
}

fn has_compatibility_syntax(source: &str) -> bool {
    let file = crate::parser::parse_source_checked("src/example.py", source.as_bytes()).unwrap();
    let process = file
        .methods
        .iter()
        .find(|method| method.name == "process")
        .expect("process method");
    python_syntax_facts("src/example.py", &file)
        .unwrap()
        .get(&(process.name.clone(), process.start_line))
        .is_some_and(|fact| fact.versioned_compatibility_source_contract.is_some())
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

#[test]
fn records_retry_and_terminal_python_match_cases() {
    let source = concat!(
        "def process():\n",
        "    while True:\n",
        "        match target():\n",
        "            case (\"retry\", _):\n",
        "                continue\n",
        "            case (\"done\", value):\n",
        "                return value\n",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new());

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

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
    assert_eq!(retryable_outcome.start_line_zero_based, 4);
    assert_eq!(terminal_outcome.start_line_zero_based, 6);
}

#[test]
fn records_retrying_python_exception_boundary() {
    let source = concat!(
        "def process():\n",
        "    while True:\n",
        "        try:\n",
        "            return target()\n",
        "        except Retryable:\n",
        "            continue\n",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new());

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
}

#[test]
fn retry_and_terminal_flow_in_one_python_case_is_not_distinct() {
    let source = concat!(
        "def process():\n",
        "    while True:\n",
        "        match target():\n",
        "            case \"idle\":\n",
        "                pass\n",
        "            case \"retry\":\n",
        "                if should_retry():\n",
        "                    continue\n",
        "                raise Fatal()\n",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new());

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn nested_python_loop_continue_does_not_count_for_outer_match() {
    let source = concat!(
        "def process():\n",
        "    while True:\n",
        "        match target():\n",
        "            case \"done\":\n",
        "                return 1\n",
        "            case \"retry\":\n",
        "                while True:\n",
        "                    continue\n",
    );
    let (source_census, semantic_census, files) = fixture(source, Vec::new());

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 0);
}

#[test]
fn recognizes_exact_caller_facing_versioned_python_warnings() {
    for source in [
        concat!(
            "import warnings\n",
            "def process(value):\n",
            "    warnings.warn(\"removed in v2.0\", DeprecationWarning, stacklevel=2)\n",
            "    return value\n",
        ),
        concat!(
            "import warnings\n",
            "def process(value):\n",
            "    \"\"\"Compatibility boundary.\"\"\"\n",
            "    warnings.warn(message=\"removed in version 3\", category=DeprecationWarning, stacklevel=3)\n",
            "    return value\n",
        ),
    ] {
        assert!(has_compatibility_syntax(source), "{source}");
    }
}

#[test]
fn rejects_python_warning_shapes_that_do_not_prove_a_contract() {
    for source in [
        "import warnings\ndef process():\n    warnings.warn(\"use current\", DeprecationWarning, stacklevel=2)\n",
        "import warnings\ndef process(v):\n    warnings.warn(f\"removed in {v}\", DeprecationWarning, stacklevel=2)\n",
        "import warnings\ndef process():\n    warnings.warn(\"removed in v2\", FutureWarning, stacklevel=2)\n",
        "import warnings\ndef process():\n    warnings.warn(\"removed in v2\", DeprecationWarning)\n",
        "import warnings\ndef process():\n    warnings.warn(\"removed in v2\", DeprecationWarning, stacklevel=1)\n",
        "import warnings\ndef process(flag):\n    if flag:\n        warnings.warn(\"removed in v2\", DeprecationWarning, stacklevel=2)\n",
        "import warnings\ndef process():\n    value = 1\n    warnings.warn(\"removed in v2\", DeprecationWarning, stacklevel=2)\n",
        "from warnings import warn\ndef process():\n    warn(\"removed in v2\", DeprecationWarning, stacklevel=2)\n",
    ] {
        assert!(!has_compatibility_syntax(source), "{source}");
    }
}

#[test]
fn emits_python_compatibility_only_with_exact_external_compiler_identities() {
    let source = concat!(
        "import warnings\n",
        "def process(value):\n",
        "    warnings.warn(\"removed in v2.0\", DeprecationWarning, stacklevel=2)\n",
        "    return value\n",
    );
    let references = warning_references(source);
    let (source_census, semantic_census, files) =
        fixture_with_references(source, Vec::new(), references);

    let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();

    assert_eq!(census.fact_count, 1);
    let IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } = &census.methods[0].status
    else {
        panic!("expected resolved AST method");
    };
    assert!(matches!(
        facts.as_slice(),
        [IntentionalBoundaryAstFact::VersionedCompatibilitySourceContract { .. }]
    ));
}

#[test]
fn refuses_missing_shadowed_or_mislabeled_python_compiler_references() {
    let source = concat!(
        "import warnings\n",
        "def process(value):\n",
        "    warnings.warn(\"removed in v2.0\", DeprecationWarning, stacklevel=2)\n",
        "    return value\n",
    );
    let variants = [
        Vec::new(),
        {
            let mut references = warning_references(source);
            let IntentionalBoundarySemanticResolution::Resolved { value } =
                &mut references[0].target
            else {
                unreachable!()
            };
            value.origin = IntentionalBoundarySemanticOrigin::Repository;
            references
        },
        {
            let mut references = warning_references(source);
            let wrong = "scip-python python python third-party 1.0 warnings/warn().";
            let IntentionalBoundarySemanticResolution::Resolved { value } =
                &mut references[0].target
            else {
                unreachable!()
            };
            value.provider_identity = wrong.to_string();
            value.symbol_id = format!("scip-global:{}:{}", wrong.len(), wrong);
            references
        },
        {
            let mut references = warning_references(source);
            references[1].target = IntentionalBoundarySemanticResolution::Unresolved {
                reason:
                    super::super::IntentionalBoundarySemanticUnresolvedReason::MissingDefinition,
                raw_target: Some("DeprecationWarning".to_string()),
                detail: "compiler omitted the target".to_string(),
            };
            references
        },
    ];

    for references in variants {
        let (source_census, semantic_census, files) =
            fixture_with_references(source, Vec::new(), references);
        let census = derive_python_ast_census(&source_census, &semantic_census, &files).unwrap();
        assert_eq!(census.fact_count, 0);
    }
}
