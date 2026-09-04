use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundaryMethodCensusEntry,
    IntentionalBoundarySemanticCallFacts, IntentionalBoundarySemanticDispatch,
    IntentionalBoundarySemanticIndexerCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticOccurrenceRole, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticReferenceTarget,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSourceReference,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceFile,
};

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

fn source_range(
    repository_path: &str,
    source: &str,
    needle: &str,
) -> IntentionalBoundarySemanticRange {
    let start = source.find(needle).expect("fixture source range");
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32;
    let character = prefix
        .rfind('\n')
        .map_or(start, |line_start| start - line_start - 1) as u32;
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: line,
        start_character_zero_based: character,
        end_line_zero_based: line,
        end_character_zero_based: character + needle.len() as u32,
    }
}

fn fixture_with(
    source: &str,
    calls: Vec<IntentionalBoundarySemanticCallFacts>,
) -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    IntentionalBoundaryAstCensus,
) {
    fixture_with_language(
        "src/lib.rs",
        "rust",
        IntentionalBoundaryIndexerKind::Rust,
        source,
        calls,
    )
}

fn fixture_with_language(
    repository_path: &str,
    language: &str,
    indexer: IntentionalBoundaryIndexerKind,
    source: &str,
    calls: Vec<IntentionalBoundarySemanticCallFacts>,
) -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    IntentionalBoundaryAstCensus,
) {
    fixture_with_language_and_references(
        repository_path,
        language,
        indexer,
        source,
        calls,
        Vec::new(),
    )
}

fn fixture_with_language_and_references(
    repository_path: &str,
    language: &str,
    indexer: IntentionalBoundaryIndexerKind,
    source: &str,
    calls: Vec<IntentionalBoundarySemanticCallFacts>,
    source_references: Vec<IntentionalBoundarySemanticSourceReference>,
) -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    IntentionalBoundaryAstCensus,
) {
    let file = crate::parser::parse_source_checked(repository_path, source.as_bytes()).unwrap();
    let parsed_method = &file.methods[0];
    let parser_unit_id = "ibm-v1:ast-evidence-fixture".to_string();
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture".to_string(),
        repository: "github.com/example/ast-evidence".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![IntentionalBoundarySourceFile {
            repository_path: repository_path.to_string(),
            object_id: "c".repeat(40),
            byte_length: source.len() as u64,
            source_sha256: "d".repeat(64),
            language: language.to_string(),
            methods: vec![IntentionalBoundaryMethodCensusEntry {
                parser_unit_id: parser_unit_id.clone(),
                symbol_name: parsed_method.name.clone(),
                start_line: parsed_method.start_line,
                end_line: parsed_method.end_line,
                source_sha256: "e".repeat(64),
                is_exported: true,
            }],
        }],
        source_file_count: 1,
        method_count: 1,
        census_sha256: "f".repeat(64),
    };
    let definition = source_range(repository_path, source, &parsed_method.name);
    let mut semantic_census = IntentionalBoundarySemanticCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
            .to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers: vec![IntentionalBoundarySemanticIndexerCensus {
            indexer,
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            semantic_facts_sha256: "1".repeat(64),
            diagnostic_count: 0,
            diagnostics_sha256: "2".repeat(64),
            document_count: 1,
            symbol_count: 2,
            relationship_count: 0,
            import_count: 0,
            call_count: calls.len(),
            test_relationship_count: 0,
            unresolved_edge_count: 0,
        }],
        source_references:
            super::super::intentional_boundary_semantic::canonical_source_references(
                source_references,
            )
            .unwrap(),
        methods: vec![IntentionalBoundarySemanticMethod {
            parser_unit_id,
            repository_path: repository_path.to_string(),
            symbol_name: parsed_method.name.clone(),
            start_line: parsed_method.start_line,
            end_line: parsed_method.end_line,
            indexer,
            status: IntentionalBoundarySemanticMethodStatus::Resolved {
                symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                    symbol_id: SUBJECT.to_string(),
                    provider_identity: SUBJECT.to_string(),
                    display_name: Some(parsed_method.name.clone()),
                    category: IntentionalBoundarySemanticSymbolCategory::Callable,
                    provider_kind: "function".to_string(),
                    documentation: Vec::new(),
                    signatures: vec![
                        crate::benchmark::IntentionalBoundarySemanticSignatureFacts {
                            language: "rust".to_string(),
                            text: "fn process(value: i32) -> i32".to_string(),
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
        semantic_census_sha256: String::new(),
    };
    semantic_census.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(
            &semantic_census,
        )
        .unwrap();
    let ast = match language {
        "rust" => super::super::intentional_boundary_ast_rust::derive_rust_ast_census(
            &source_census,
            &semantic_census,
            &[file],
        ),
        "go" => super::super::intentional_boundary_ast_go_kotlin::derive_go_ast_census(
            &source_census,
            &semantic_census,
            &[file],
        ),
        "kotlin" => super::super::intentional_boundary_ast_go_kotlin::derive_kotlin_ast_census(
            &source_census,
            &semantic_census,
            &[file],
        ),
        "javascript" | "typescript" => {
            super::super::intentional_boundary_ast_js_ts::derive_js_ts_ast_census(
                &source_census,
                &semantic_census,
                &[file],
                language,
            )
        }
        "python" => super::super::intentional_boundary_ast_python::derive_python_ast_census(
            &source_census,
            &semantic_census,
            &[file],
        ),
        _ => panic!("unsupported AST evidence fixture language: {language}"),
    }
    .unwrap();
    (source_census, semantic_census, ast)
}

fn compiler_reference(
    indexer: IntentionalBoundaryIndexerKind,
    location: IntentionalBoundarySemanticRange,
    provider_identity: &str,
) -> IntentionalBoundarySemanticSourceReference {
    IntentionalBoundarySemanticSourceReference {
        indexer,
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
                origin: IntentionalBoundarySemanticOrigin::External,
            },
        },
    }
}

fn fixture() -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    IntentionalBoundaryAstCensus,
) {
    let source = "pub fn process(value: i32) -> i32 { target(value) }";
    let call_start = source.find("target").unwrap();
    fixture_with(
        source,
        vec![IntentionalBoundarySemanticCallFacts {
            caller: SUBJECT.to_string(),
            callee: IntentionalBoundarySemanticResolution::Resolved {
                value: CALLEE.to_string(),
            },
            callsite: range(call_start, call_start + "target".len()),
            dispatch: IntentionalBoundarySemanticDispatch::Static,
        }],
    )
}

#[test]
fn composes_hash_bound_compiler_and_ast_delegation_evidence() {
    let (source, semantic, ast) = fixture();
    let asts = BTreeMap::from([("rust", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert_eq!(evidence.schema_version, 4);
    assert_eq!(evidence.atoms.len(), 2);
    assert_eq!(
        evidence.input_census_sha256.get("source_ast:rust"),
        Some(&ast.ast_census_sha256)
    );
    assert_eq!(
        evidence.input_census_sha256.get("compiler_semantic_index"),
        Some(&semantic.semantic_census_sha256)
    );
    let ast_atoms = evidence
        .atoms
        .iter()
        .filter(|atom| matches!(atom.proof, IntentionalBoundaryEvidenceProof::SourceAst(_)))
        .collect::<Vec<_>>();
    let [atom] = ast_atoms.as_slice() else {
        panic!("expected exactly one AST evidence atom");
    };
    assert_eq!(
        atom.evidence_kind,
        BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation
    );
    assert!(matches!(
        atom.proof,
        IntentionalBoundaryEvidenceProof::SourceAst(
            IntentionalBoundaryAstProofKind::ThinDelegation
        )
    ));
    assert_eq!(atom.subject_symbol_id, SUBJECT);
    assert_eq!(atom.related_symbol_ids, [CALLEE]);
    assert_eq!(atom.locations.len(), 2);
}

#[test]
fn qualifies_versioned_rust_api_only_with_a_resolved_retained_consumer() {
    let source_text = "#[deprecated(since = \"1.2.0\", note = \"use current\")]\npub fn process(value: i32) -> i32 { value }";
    let callsite_start = source_text.find("process").unwrap();
    let incoming_call = IntentionalBoundarySemanticCallFacts {
        caller: CALLEE.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: SUBJECT.to_string(),
        },
        callsite: range(callsite_start, callsite_start + "process".len()),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    };
    let (source, semantic, ast) = fixture_with(source_text, vec![incoming_call]);
    let asts = BTreeMap::from([("rust", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::VersionedCompatibilityContract
            && matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::VersionedCompatibilitySourceContract
                )
            )
    }));
    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::RetainedCompatibilityConsumer
            && matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::CompilerSemanticIndex(
                    super::super::IntentionalBoundaryCompilerProofKind::IncomingCall
                )
            )
    }));

    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();
    assert!(candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::CompatibilityApi
    }));
}

#[test]
fn qualifies_versioned_go_api_only_with_a_resolved_retained_consumer() {
    let repository_path = "src/lib.go";
    let source_text = concat!(
        "package sample\n",
        "// Deprecated: retained for callers until v2.\n",
        "func Process(value int) int { return value }",
    );
    let incoming_call = IntentionalBoundarySemanticCallFacts {
        caller: CALLEE.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: SUBJECT.to_string(),
        },
        callsite: source_range(repository_path, source_text, "Process"),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    };
    let (source, semantic, ast) = fixture_with_language(
        repository_path,
        "go",
        IntentionalBoundaryIndexerKind::Go,
        source_text,
        vec![incoming_call],
    );
    let asts = BTreeMap::from([("go", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::VersionedCompatibilityContract
            && matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::VersionedCompatibilitySourceContract
                )
            )
    }));
    assert!(
        evidence.atoms.iter().any(|atom| {
            atom.evidence_kind == BoundaryEvidenceKind::RetainedCompatibilityConsumer
        })
    );

    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();
    assert!(candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::CompatibilityApi
    }));
}

#[test]
fn qualifies_versioned_typescript_api_only_with_a_resolved_retained_consumer() {
    let repository_path = "src/lib.ts";
    let source_text = concat!(
        "/** @deprecated retained for callers until v3. */\n",
        "export function Process(value: number): number { return value; }",
    );
    let incoming_call = IntentionalBoundarySemanticCallFacts {
        caller: CALLEE.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: SUBJECT.to_string(),
        },
        callsite: source_range(repository_path, source_text, "Process"),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    };
    let (source, semantic, ast) = fixture_with_language(
        repository_path,
        "typescript",
        IntentionalBoundaryIndexerKind::TypeScriptJavaScript,
        source_text,
        vec![incoming_call],
    );
    let asts = BTreeMap::from([("typescript", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::VersionedCompatibilityContract
            && matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::VersionedCompatibilitySourceContract
                )
            )
    }));
    assert!(
        evidence.atoms.iter().any(|atom| {
            atom.evidence_kind == BoundaryEvidenceKind::RetainedCompatibilityConsumer
        })
    );

    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();
    assert!(candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::CompatibilityApi
    }));
}

#[test]
fn qualifies_python_warning_contract_only_with_compiler_identities_and_a_consumer() {
    let repository_path = "src/lib.py";
    let source_text = concat!(
        "import warnings\n",
        "def process(value):\n",
        "    warnings.warn(\"removed in v2.0\", DeprecationWarning, stacklevel=2)\n",
        "    return value\n",
    );
    let incoming_call = IntentionalBoundarySemanticCallFacts {
        caller: CALLEE.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: SUBJECT.to_string(),
        },
        callsite: source_range(repository_path, source_text, "process"),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    };
    let mut warn_range = source_range(repository_path, source_text, ".warn");
    warn_range.start_character_zero_based += 1;
    let references = vec![
        compiler_reference(
            IntentionalBoundaryIndexerKind::Python,
            warn_range.clone(),
            "scip-python python python-stdlib 3.11 _warnings/warn().",
        ),
        compiler_reference(
            IntentionalBoundaryIndexerKind::Python,
            warn_range,
            "scip-python python python-stdlib 3.11 builtins/str#",
        ),
        compiler_reference(
            IntentionalBoundaryIndexerKind::Python,
            source_range(repository_path, source_text, "DeprecationWarning"),
            "scip-python python python-stdlib 3.11 builtins/DeprecationWarning#",
        ),
    ];
    let (source, semantic, ast) = fixture_with_language_and_references(
        repository_path,
        "python",
        IntentionalBoundaryIndexerKind::Python,
        source_text,
        vec![incoming_call],
        references,
    );
    let asts = BTreeMap::from([("python", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::VersionedCompatibilityContract
    }));
    assert!(
        evidence.atoms.iter().any(|atom| {
            atom.evidence_kind == BoundaryEvidenceKind::RetainedCompatibilityConsumer
        })
    );
    assert!(candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::CompatibilityApi
    }));
}

#[test]
fn qualifies_kotlin_deprecation_only_with_exact_compiler_identity_and_a_consumer() {
    let repository_path = "src/Lib.kt";
    let source_text = concat!(
        "package sample\n",
        "@Deprecated(\"removed in v2.0; use current\")\n",
        "fun process(value: Int): Int = value\n",
    );
    let incoming_call = IntentionalBoundarySemanticCallFacts {
        caller: CALLEE.to_string(),
        callee: IntentionalBoundarySemanticResolution::Resolved {
            value: SUBJECT.to_string(),
        },
        callsite: source_range(repository_path, source_text, "process"),
        dispatch: IntentionalBoundarySemanticDispatch::Static,
    };
    let reference = compiler_reference(
        IntentionalBoundaryIndexerKind::Kotlin,
        source_range(repository_path, source_text, "Deprecated"),
        "scip-java maven maven/org.jetbrains.kotlin/kotlin-stdlib 2.2.0 kotlin/Deprecated#",
    );
    let (source, semantic, ast) = fixture_with_language_and_references(
        repository_path,
        "kotlin",
        IntentionalBoundaryIndexerKind::Kotlin,
        source_text,
        vec![incoming_call],
        vec![reference],
    );
    let asts = BTreeMap::from([("kotlin", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::VersionedCompatibilityContract
    }));
    assert!(
        evidence.atoms.iter().any(|atom| {
            atom.evidence_kind == BoundaryEvidenceKind::RetainedCompatibilityConsumer
        })
    );
}

#[test]
fn refuses_kotlin_deprecation_without_the_exact_external_compiler_identity() {
    let repository_path = "src/Lib.kt";
    let source_text = concat!(
        "package sample\n",
        "@Deprecated(\"removed in v2.0; use current\")\n",
        "fun process(value: Int): Int = value\n",
    );
    let variants = [
        Vec::new(),
        vec![compiler_reference(
            IntentionalBoundaryIndexerKind::Kotlin,
            source_range(repository_path, source_text, "Deprecated"),
            "scip-java maven example 1.0 sample/Deprecated#",
        )],
        vec![compiler_reference(
            IntentionalBoundaryIndexerKind::Kotlin,
            source_range(repository_path, source_text, "Deprecated"),
            "scip-java maven maven/org.jetbrains.kotlin/kotlin-stdlib 2.2.0 kotlin/Deprecated().",
        )],
    ];

    for references in variants {
        let (_, _, ast) = fixture_with_language_and_references(
            repository_path,
            "kotlin",
            IntentionalBoundaryIndexerKind::Kotlin,
            source_text,
            Vec::new(),
            references,
        );
        assert_eq!(ast.fact_count, 0);
    }
}

#[test]
fn versioned_rust_api_without_a_resolved_consumer_does_not_qualify() {
    let source_text =
        "#[deprecated(since = \"1.2.0\")]\npub fn process(value: i32) -> i32 { value }";
    let (source, semantic, ast) = fixture_with(source_text, Vec::new());
    let asts = BTreeMap::from([("rust", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::VersionedCompatibilityContract
    }));
    assert!(
        !evidence.atoms.iter().any(|atom| {
            atom.evidence_kind == BoundaryEvidenceKind::RetainedCompatibilityConsumer
        })
    );
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();
    assert!(!candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::CompatibilityApi
    }));
}

#[test]
fn retry_outcome_ast_proof_alone_does_not_qualify_without_behavior() {
    let source_text = concat!(
        "pub fn process() -> Result<i32, ()> { loop { match target() { ",
        "Ok(value) => return Ok(value), Err(_) => continue } } }",
    );
    let (source, semantic, ast) = fixture_with(source_text, Vec::new());
    let asts = BTreeMap::from([("rust", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes
            && matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::DistinctOutcomeBranches
                )
            )
    }));
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();
    assert!(!candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::RetryBoundary
    }));
}

#[test]
fn generator_marker_alone_does_not_qualify_a_generated_surface() {
    let source_text = "// @generated\npub fn process(value: i32) -> i32 { value }";
    let (source, semantic, ast) = fixture_with(source_text, Vec::new());
    let asts = BTreeMap::from([("rust", &ast)]);

    let evidence = derive_compiler_and_ast_evidence(&source, &semantic, &asts).unwrap();

    assert!(evidence.atoms.iter().any(|atom| {
        atom.evidence_kind == BoundaryEvidenceKind::GeneratorIdentity
            && matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::GeneratorMarker
                )
            )
    }));
    let protocol = super::super::validate_intentional_boundary_protocol(
        include_bytes!("../sniffbench/non-blind-v1-selection-policy.json"),
        include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json"),
        include_bytes!("../sniffbench/blind-oss-v1-source-seal.json"),
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json"),
    )
    .unwrap();
    let candidates = super::super::qualify_intentional_boundary_candidates(
        &protocol, &source, &semantic, &evidence,
    )
    .unwrap();
    assert!(!candidates.candidates.iter().any(|candidate| {
        candidate.category == super::super::IntentionalBoundaryCategory::GeneratedSurface
    }));
}

#[test]
fn rejects_ast_evidence_attached_to_a_different_symbol() {
    let (source, semantic, mut ast) = fixture();
    let IntentionalBoundaryAstMethodStatus::Resolved {
        subject_symbol_id, ..
    } = &mut ast.methods[0].status
    else {
        unreachable!();
    };
    *subject_symbol_id = "rust fixture wrong".to_string();
    let asts = BTreeMap::from([("rust", &ast)]);

    assert!(
        derive_compiler_and_ast_evidence(&source, &semantic, &asts)
            .unwrap_err()
            .contains("changed subject symbol")
    );
}
