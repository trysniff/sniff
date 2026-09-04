use super::*;
use crate::semantic_index::{
    SemanticOccurrenceRole, SemanticPositionEncoding, SemanticRelationshipKind,
    SemanticSymbolCategory, SemanticSymbolOrigin,
};
use protobuf::{EnumOrUnknown, Message, MessageField};
use scip::types::{
    Document, Index, Metadata, MultiLineRange, Occurrence, PositionEncoding, ProtocolVersion,
    Relationship, Signature, SingleLineRange, SymbolInformation, TextEncoding, ToolInfo,
    symbol_information::Kind,
};
use sha2::Digest;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const RUN: &str = "rust-analyzer cargo demo 1.0.0 run().";
const SERVICE: &str = "rust-analyzer cargo demo 1.0.0 Service#";
const SCIP_GO_BLANK: &str =
    "scip-go gomod github.com/cloudflare/cloudflare-go . `github.com/cloudflare/cloudflare-go`/_.";

fn root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("sniff-scip-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

fn base_index() -> Index {
    let mut tool = ToolInfo::new();
    tool.name = "rust-analyzer".to_string();
    tool.version = "1.88.0".to_string();
    tool.arguments = vec!["scip".to_string(), ".".to_string()];
    let mut metadata = Metadata::new();
    metadata.tool_info = MessageField::some(tool);
    metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
    let mut index = Index::new();
    index.metadata = MessageField::some(metadata);
    index
}

fn document(path: &str) -> Document {
    let mut document = Document::new();
    document.relative_path = path.to_string();
    document.language = "rust".to_string();
    document.position_encoding =
        EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
    document
}

fn single_line(symbol: &str, line: i32, start: i32, end: i32, roles: i32) -> Occurrence {
    let mut occurrence = Occurrence::new();
    occurrence.symbol = symbol.to_string();
    occurrence.symbol_roles = roles;
    let mut range = SingleLineRange::new();
    range.line = line;
    range.start_character = start;
    range.end_character = end;
    occurrence.set_single_line_range(range);
    occurrence
}

fn ingest(root: &Path, source: &Index) -> Result<SemanticIndex, String> {
    ingest_scip_bytes(root, &source.write_to_bytes().unwrap())
}

#[test]
fn imports_global_identities_definitions_references_and_relationships() {
    let root = root("global");
    let mut index = base_index();
    let mut definition_document = document("src/service.rs");
    let mut information = SymbolInformation::new();
    information.symbol = RUN.to_string();
    information.display_name = "run".to_string();
    information.kind = EnumOrUnknown::new(Kind::Function);
    let mut relationship = Relationship::new();
    relationship.symbol = SERVICE.to_string();
    relationship.is_implementation = true;
    information.relationships.push(relationship);
    definition_document.symbols.push(information);
    definition_document
        .occurrences
        .push(single_line(RUN, 2, 3, 6, 1));

    let mut consumer = document("src/main.rs");
    let mut reference = Occurrence::new();
    reference.symbol = RUN.to_string();
    reference.symbol_roles = 2 | 8;
    reference.range = vec![4, 1, 4];
    consumer.occurrences.push(reference);
    index.documents = vec![definition_document, consumer];

    let imported = ingest(&root, &index).unwrap();
    let run_id = symbols::stable_symbol_id(RUN, None).unwrap();
    let service_id = symbols::stable_symbol_id(SERVICE, None).unwrap();
    let run = imported.symbols.get(&run_id).unwrap();
    assert_eq!(run.kind.category, SemanticSymbolCategory::Callable);
    assert_eq!(run.definitions.len(), 1);
    assert_eq!(run.origin, SemanticSymbolOrigin::Repository);
    assert_eq!(imported.imports.len(), 1);
    assert!(matches!(
        &imported.imports.iter().next().unwrap().reexport,
        crate::semantic_index::SemanticResolution::Unresolved {
            reason: crate::semantic_index::SemanticUnresolvedReason::MissingIndexerFact,
            ..
        }
    ));
    assert!(
        imported
            .relationships
            .contains(&crate::semantic_index::SemanticRelationship {
                source: run_id.clone(),
                target: service_id.clone(),
                kind: SemanticRelationshipKind::Implementation,
            })
    );
    assert_eq!(
        imported.symbols.get(&service_id).unwrap().origin,
        SemanticSymbolOrigin::Unknown
    );
    let main = imported
        .documents
        .get(&RepositoryPath("src/main.rs".to_string()))
        .unwrap();
    assert_eq!(main.occurrences[0].symbol.as_ref(), Some(&run_id));
    assert!(
        main.occurrences[0]
            .roles
            .contains(&SemanticOccurrenceRole::Read)
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn document_local_symbols_are_collision_free_across_files() {
    let root = root("locals");
    let mut index = base_index();
    for path in ["src/a.rs", "src/b.rs"] {
        let mut source = document(path);
        let mut information = SymbolInformation::new();
        information.symbol = "local 0".to_string();
        information.display_name = "value".to_string();
        information.kind = EnumOrUnknown::new(Kind::Variable);
        source.symbols.push(information);
        source.occurrences.push(single_line("local 0", 0, 4, 9, 1));
        index.documents.push(source);
    }

    let imported = ingest(&root, &index).unwrap();
    let a = symbols::stable_symbol_id("local 0", Some(&RepositoryPath("src/a.rs".to_string())))
        .unwrap();
    let b = symbols::stable_symbol_id("local 0", Some(&RepositoryPath("src/b.rs".to_string())))
        .unwrap();
    assert_ne!(a, b);
    assert!(imported.symbols.contains_key(&a));
    assert!(imported.symbols.contains_key(&b));
    fs::remove_dir_all(root).ok();
}

#[test]
fn python_local_external_symbols_are_discarded_with_a_provenance_diagnostic() {
    let root = root("python-local-external");
    let mut index = base_index();
    index
        .metadata
        .as_mut()
        .unwrap()
        .tool_info
        .as_mut()
        .unwrap()
        .name = "scip-python".to_string();
    let mut external = SymbolInformation::new();
    external.symbol = "local 5".to_string();
    index.external_symbols.push(external);

    let mut source = document("src/main.py");
    source.language = "python".to_string();
    source.position_encoding =
        EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
    source.occurrences.push(single_line("local 5", 0, 0, 1, 2));
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    assert!(!imported.symbols.values().any(|symbol| {
        symbol.origin == SemanticSymbolOrigin::External && symbol.provider_identity == "local 5"
    }));
    assert_eq!(imported.provenance.diagnostics.len(), 1);
    assert!(imported.provenance.diagnostics[0].contains("local 5"));
    assert!(imported.provenance.diagnostics[0].contains("document-scoped"));
    fs::remove_dir_all(root).ok();
}

#[test]
fn non_python_local_external_symbols_remain_strictly_rejected() {
    let root = root("non-python-local-external");
    let mut index = base_index();
    let mut external = SymbolInformation::new();
    external.symbol = "local 5".to_string();
    index.external_symbols.push(external);

    let error = ingest(&root, &index).unwrap_err();
    assert!(
        error.contains("has no containing document identity"),
        "{error}"
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn scip_java_package_coordinates_reconstruct_only_proven_external_origins() {
    const OWNED: &str = "scip-java maven com.example/demo 1.0 demo/Owned#";
    const SAME_PACKAGE_UNKNOWN: &str = "scip-java maven com.example/demo 1.0 demo/Generated#";
    const DEPRECATED: &str =
        "scip-java maven maven/org.jetbrains.kotlin/kotlin-stdlib 2.2.0 kotlin/Deprecated#";
    const UNRESOLVED_INTRINSIC: &str = "scip-java maven . . kotlin/Int#";

    let root = root("scip-java-external-origin");
    let mut index = base_index();
    index
        .metadata
        .as_mut()
        .unwrap()
        .tool_info
        .as_mut()
        .unwrap()
        .name = "scip-java".to_string();
    let mut source = document("src/main/kotlin/demo/Main.kt");
    source.language = "kotlin".to_string();
    source.position_encoding =
        EnumOrUnknown::new(PositionEncoding::UTF16CodeUnitOffsetFromLineStart);
    let mut owned = SymbolInformation::new();
    owned.symbol = OWNED.to_string();
    owned.kind = EnumOrUnknown::new(Kind::Class);
    source.symbols.push(owned);
    source.occurrences.extend([
        single_line(OWNED, 0, 0, 5, 1),
        single_line(SAME_PACKAGE_UNKNOWN, 1, 0, 9, 8),
        single_line(DEPRECATED, 2, 1, 11, 8),
        single_line(UNRESOLVED_INTRINSIC, 3, 0, 3, 8),
    ]);
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let origin = |identity: &str| {
        imported
            .symbols
            .get(&symbols::stable_symbol_id(identity, None).unwrap())
            .unwrap()
            .origin
    };
    assert_eq!(origin(OWNED), SemanticSymbolOrigin::Repository);
    assert_eq!(origin(SAME_PACKAGE_UNKNOWN), SemanticSymbolOrigin::Unknown);
    assert_eq!(origin(DEPRECATED), SemanticSymbolOrigin::External);
    assert_eq!(origin(UNRESOLVED_INTRINSIC), SemanticSymbolOrigin::Unknown);
    assert!(
        imported
            .provenance
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("reconstructed 1 external origins"))
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn malformed_python_local_occurrences_remain_unresolved() {
    let root = root("python-malformed-local");
    let mut index = base_index();
    index
        .metadata
        .as_mut()
        .unwrap()
        .tool_info
        .as_mut()
        .unwrap()
        .name = "scip-python".to_string();

    let mut source = document("src/main.py");
    source.language = "python".to_string();
    source.position_encoding =
        EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
    source
        .occurrences
        .push(single_line("local 1(event)", 0, 0, 1, 8));
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let occurrence = &imported
        .documents
        .get(&crate::semantic_index::RepositoryPath(
            "src/main.py".to_string(),
        ))
        .unwrap()
        .occurrences[0];
    assert!(occurrence.symbol.is_none());
    assert_eq!(imported.provenance.diagnostics.len(), 1);
    assert!(imported.provenance.diagnostics[0].contains("local 1(event)"));
    assert!(imported.provenance.diagnostics[0].contains("unresolved"));
    fs::remove_dir_all(root).ok();
}

#[test]
fn typed_ranges_take_precedence_over_deprecated_ranges() {
    let root = root("encoding");
    let mut index = base_index();
    let mut source = document("src/main.rs");
    let mut occurrence = single_line(RUN, 7, 2, 5, 8);
    occurrence.range = vec![-1];
    source.occurrences.push(occurrence);
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let source = imported
        .documents
        .get(&RepositoryPath("src/main.rs".to_string()))
        .unwrap();
    assert_eq!(source.position_encoding, SemanticPositionEncoding::Utf8);
    assert_eq!(source.occurrences[0].range.start.line, 7);
    fs::remove_dir_all(root).ok();
}

#[test]
fn captures_signature_symbol_references_and_multiline_ranges() {
    let root = root("signature");
    let mut index = base_index();
    let mut source = document("src/service.rs");
    let mut information = SymbolInformation::new();
    information.symbol = RUN.to_string();
    information.kind = EnumOrUnknown::new(Kind::Function);
    let mut signature = Signature::new();
    signature.language = "rust".to_string();
    signature.text = "fn run() -> Service".to_string();
    signature
        .occurrences
        .push(single_line(SERVICE, 0, 12, 19, 8));
    information.signature_documentation = MessageField::some(signature);
    source.symbols.push(information);
    let mut occurrence = Occurrence::new();
    occurrence.symbol = RUN.to_string();
    occurrence.symbol_roles = 1;
    let mut range = MultiLineRange::new();
    range.start_line = 1;
    range.start_character = 0;
    range.end_line = 2;
    range.end_character = 1;
    occurrence.set_multi_line_range(range);
    source.occurrences.push(occurrence);
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let run = imported
        .symbols
        .get(&symbols::stable_symbol_id(RUN, None).unwrap())
        .unwrap();
    let signature = run.signatures.iter().next().unwrap();
    assert!(
        signature
            .referenced_symbols
            .contains(&symbols::stable_symbol_id(SERVICE, None).unwrap())
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn corrupt_protobuf_and_missing_metadata_fail_closed() {
    let root = root("protobuf");
    let corrupt = ingest_scip_bytes(&root, b"not-a-protobuf").unwrap_err();
    assert!(
        corrupt.contains("failed to decode SCIP protobuf"),
        "{corrupt}"
    );

    let missing = Index::new();
    let error = ingest(&root, &missing).unwrap_err();
    assert!(error.contains("missing required metadata"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn unsafe_or_duplicate_document_paths_fail_closed() {
    let root = root("paths");
    for unsafe_path in ["../outside.rs", "/absolute.rs", "C:\\outside.rs"] {
        let mut index = base_index();
        index.documents.push(document(unsafe_path));
        let error = ingest(&root, &index).unwrap_err();
        assert!(
            error.contains("escapes the repository root") || error.contains("must be relative"),
            "{unsafe_path}: {error}"
        );
    }
    let mut duplicate = base_index();
    duplicate.documents.push(document("src/main.rs"));
    duplicate.documents.push(document("src/./main.rs"));
    let error = ingest(&root, &duplicate).unwrap_err();
    assert!(error.contains("duplicate document"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn malformed_ranges_roles_symbols_and_encodings_fail_closed() {
    let root = root("invalid");
    let cases = [
        (vec![-1, 0, 2], 0, RUN, "negative coordinate"),
        (vec![2, 4, 1, 0], 0, RUN, "inverted"),
        (vec![1, 2], 0, RUN, "3 or 4 coordinates"),
        (vec![1, 0, 1], 128, RUN, "unknown symbol-role bits"),
        (vec![1, 0, 1], 1, "not a symbol", "invalid SCIP symbol"),
    ];
    for (range, roles, symbol, expected) in cases {
        let mut index = base_index();
        let mut source = document("src/main.rs");
        let mut occurrence = Occurrence::new();
        occurrence.range = range;
        occurrence.symbol_roles = roles;
        occurrence.symbol = symbol.to_string();
        source.occurrences.push(occurrence);
        index.documents.push(source);
        let error = ingest(&root, &index).unwrap_err();
        assert!(error.contains(expected), "expected {expected:?}: {error}");
    }

    let mut index = base_index();
    let mut source = document("src/main.rs");
    source.position_encoding = EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
    index.documents.push(source);
    let error = ingest(&root, &index).unwrap_err();
    assert!(
        error.contains("omits its source position encoding"),
        "{error}"
    );

    let mut index = base_index();
    index.documents.push(document("src/main.rs"));
    index.documents[0].position_encoding = EnumOrUnknown::from_i32(99);
    let error = ingest(&root, &index).unwrap_err();
    assert!(error.contains("unknown position encoding"), "{error}");

    let mut index = base_index();
    index.metadata.as_mut().unwrap().text_document_encoding = EnumOrUnknown::from_i32(99);
    let error = ingest(&root, &index).unwrap_err();
    assert!(error.contains("unknown text encoding"), "{error}");

    let mut index = base_index();
    index.metadata.as_mut().unwrap().version = EnumOrUnknown::<ProtocolVersion>::from_i32(99);
    let error = ingest(&root, &index).unwrap_err();
    assert!(error.contains("unsupported protocol version"), "{error}");

    let mut index = base_index();
    let mut source = document("src/main.rs");
    let mut information = SymbolInformation::new();
    information.symbol = RUN.to_string();
    information.kind = EnumOrUnknown::from_i32(999);
    source.symbols.push(information);
    index.documents.push(source);
    let error = ingest(&root, &index).unwrap_err();
    assert!(error.contains("unknown kind value"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn conflicting_symbol_kinds_become_ambiguity_while_roleless_relationships_fail_closed() {
    let root = root("conflict");
    let mut conflict = base_index();
    let mut source = document("src/main.rs");
    for kind in [Kind::Function, Kind::Class, Kind::Variable] {
        let mut information = SymbolInformation::new();
        information.symbol = RUN.to_string();
        information.kind = EnumOrUnknown::new(kind);
        source.symbols.push(information);
    }
    conflict.documents.push(source);
    let imported = ingest(&root, &conflict).unwrap();
    let run_id = symbols::stable_symbol_id(RUN, None).unwrap();
    let run = imported.symbols.get(&run_id).unwrap();
    assert_eq!(run.kind.category, SemanticSymbolCategory::Unknown);
    assert_eq!(run.kind.provider_name, "ConflictingKinds");
    assert_eq!(
        run.ambiguity_notes,
        vec![
            format!(
                "conflicting SCIP symbol kinds for {}: Class and Function",
                run_id.0
            ),
            format!(
                "additional conflicting SCIP symbol kind for {}: Variable",
                run_id.0
            ),
        ]
    );

    let mut roleless = base_index();
    let mut source = document("src/main.rs");
    let mut information = SymbolInformation::new();
    information.symbol = RUN.to_string();
    let mut relationship = Relationship::new();
    relationship.symbol = SERVICE.to_string();
    information.relationships.push(relationship);
    source.symbols.push(information);
    roleless.documents.push(source);
    let error = ingest(&root, &roleless).unwrap_err();
    assert!(error.contains("no relationship role"), "{error}");
    fs::remove_dir_all(root).ok();
}

#[test]
fn scip_go_blank_identifier_collisions_preserve_the_rest_of_the_index() {
    let root = root("scip-go-blank");
    let mut index = base_index();
    index
        .metadata
        .as_mut()
        .unwrap()
        .tool_info
        .as_mut()
        .unwrap()
        .name = "scip-go".to_string();
    let mut source = document("cloudflare.go");
    source.language = "go".to_string();

    for (kind, signature_text) in [
        (Kind::Variable, "var _ = assertVariable()"),
        (Kind::Constant, "const _ = assertConstant"),
    ] {
        let mut information = SymbolInformation::new();
        information.symbol = SCIP_GO_BLANK.to_string();
        information.display_name = "_".to_string();
        information.kind = EnumOrUnknown::new(kind);
        let mut signature = Signature::new();
        signature.language = "go".to_string();
        signature.text = signature_text.to_string();
        information.signature_documentation = MessageField::some(signature);
        source.symbols.push(information);
    }
    source
        .occurrences
        .push(single_line(SCIP_GO_BLANK, 1, 4, 5, 1));
    source
        .occurrences
        .push(single_line(SCIP_GO_BLANK, 2, 6, 7, 1));
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let blank_id = symbols::stable_symbol_id(SCIP_GO_BLANK, None).unwrap();
    let blank = imported.symbols.get(&blank_id).unwrap();
    assert_eq!(blank.kind.category, SemanticSymbolCategory::Unknown);
    assert_eq!(blank.kind.provider_name, "ConflictingKinds");
    assert_eq!(blank.display_name.as_deref(), Some("_"));
    assert_eq!(blank.definitions.len(), 2);
    assert_eq!(blank.signatures.len(), 2);
    assert_eq!(
        blank
            .signatures
            .iter()
            .map(|signature| signature.text.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["const _ = assertConstant", "var _ = assertVariable()"])
    );
    assert_eq!(blank.ambiguity_notes.len(), 1);
    assert!(
        blank.ambiguity_notes[0].contains("conflicting SCIP symbol kinds"),
        "{:?}",
        blank.ambiguity_notes
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn repeated_symbol_information_preserves_every_compiler_signature() {
    let root = root("overloaded-signatures");
    let mut index = base_index();
    let mut source = document("overloads.ts");
    let identity = "scip-typescript npm demo 1.0.0 `overloads.ts`/parse().";
    for signature_text in ["(value: number): number", "(value: string): string"] {
        let mut information = SymbolInformation::new();
        information.symbol = identity.to_string();
        information.kind = EnumOrUnknown::new(Kind::Function);
        let mut signature = Signature::new();
        signature.language = "typescript".to_string();
        signature.text = signature_text.to_string();
        information.signature_documentation = MessageField::some(signature);
        source.symbols.push(information);
    }
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let symbol_id = symbols::stable_symbol_id(identity, None).unwrap();
    let symbol = imported.symbols.get(&symbol_id).unwrap();
    assert_eq!(symbol.signatures.len(), 2);
    assert!(symbol.ambiguity_notes.is_empty());
    assert_eq!(
        symbol
            .signatures
            .iter()
            .map(|signature| signature.text.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["(value: number): number", "(value: string): string"])
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn file_ingestion_uses_the_same_strict_contract() {
    let root = root("file");
    let mut index = base_index();
    index.documents.push(document("src/main.rs"));
    let path = root.join("index.scip");
    let bytes = index.write_to_bytes().unwrap();
    fs::write(&path, &bytes).unwrap();

    let imported = ingest_scip_file(&root, &path).unwrap();
    assert_eq!(imported.provenance.tool_name, "rust-analyzer");
    assert_eq!(
        imported.provenance.source_text_encoding,
        Some(crate::semantic_index::SemanticTextEncoding::Utf8)
    );
    assert_eq!(imported.provenance.invocations.len(), 1);
    assert_eq!(
        imported.provenance.invocations[0].output_sha256,
        format!("{:x}", sha2::Sha256::digest(&bytes))
    );
    assert_eq!(imported.documents.len(), 1);
    fs::remove_dir_all(root).ok();
}

#[test]
fn missing_document_language_requires_an_explicit_expected_source_language() {
    let root = root("language");
    let mut index = base_index();
    let mut source = document("src/main.ts");
    source.language.clear();
    source.position_encoding = EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
    index.documents.push(source);
    let path = root.join("index.scip");
    fs::write(&path, index.write_to_bytes().unwrap()).unwrap();

    let error = ingest_scip_file(&root, &path).unwrap_err();
    assert!(error.contains("has no language"), "{error}");

    let expected = BTreeMap::from([(
        crate::semantic_index::RepositoryPath("src/main.ts".to_string()),
        "typescript".to_string(),
    )]);
    let imported = super::ingest_scip_file_with_expected_languages(
        &root,
        &path,
        Some(&expected),
        Some(crate::semantic_index::SemanticPositionEncoding::Utf16),
    )
    .unwrap();
    assert_eq!(
        imported.documents[&crate::semantic_index::RepositoryPath("src/main.ts".to_string())]
            .language,
        "typescript"
    );
    assert_eq!(
        imported.documents[&crate::semantic_index::RepositoryPath("src/main.ts".to_string())]
            .position_encoding,
        crate::semantic_index::SemanticPositionEncoding::Utf16
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn typescript_repository_prefixed_documents_use_explicit_inventory_paths() {
    let root = root("typescript-prefix");
    let repository_name = root.file_name().unwrap().to_string_lossy();
    let mut index = base_index();
    index
        .metadata
        .as_mut()
        .unwrap()
        .tool_info
        .as_mut()
        .unwrap()
        .name = "scip-typescript".to_string();
    let mut source = document(&format!("{repository_name}/src/main.ts"));
    source.language.clear();
    source.position_encoding = EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
    index.documents.push(source);
    let mut excluded = document(&format!("{repository_name}/generated/next-env.d.ts"));
    excluded.language.clear();
    excluded.position_encoding = EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
    index.documents.push(excluded);
    let path = root.join("index.scip");
    fs::write(&path, index.write_to_bytes().unwrap()).unwrap();

    let expected = BTreeMap::from([(
        crate::semantic_index::RepositoryPath("src/main.ts".to_string()),
        "typescript".to_string(),
    )]);
    let imported = super::ingest_scip_file_with_expected_languages(
        &root,
        &path,
        Some(&expected),
        Some(crate::semantic_index::SemanticPositionEncoding::Utf16),
    )
    .unwrap();

    assert!(
        imported
            .documents
            .contains_key(&crate::semantic_index::RepositoryPath(
                "src/main.ts".to_string(),
            ))
    );
    assert!(
        imported
            .provenance
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.contains("repository-prefixed document paths") })
    );
    assert!(
        imported
            .provenance
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.contains("outside Sniff's semantic inventory") })
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn typescript_absolute_documents_use_repository_relative_inventory_paths() {
    let root = root("typescript-absolute");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/main.ts"), "export function main() {}\n").unwrap();
    let mut index = base_index();
    index
        .metadata
        .as_mut()
        .unwrap()
        .tool_info
        .as_mut()
        .unwrap()
        .name = "scip-typescript".to_string();
    let mut source = document(&root.join("src/main.ts").to_string_lossy());
    source.language.clear();
    source.position_encoding = EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
    index.documents.push(source);
    let path = root.join("index.scip");
    fs::write(&path, index.write_to_bytes().unwrap()).unwrap();

    let expected = BTreeMap::from([(
        crate::semantic_index::RepositoryPath("src/main.ts".to_string()),
        "typescript".to_string(),
    )]);
    let imported = super::ingest_scip_file_with_expected_languages(
        &root,
        &path,
        Some(&expected),
        Some(crate::semantic_index::SemanticPositionEncoding::Utf16),
    )
    .unwrap();

    assert!(
        imported
            .documents
            .contains_key(&crate::semantic_index::RepositoryPath(
                "src/main.ts".to_string(),
            ))
    );
    assert!(
        imported
            .provenance
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("absolute document paths"))
    );
    fs::remove_dir_all(root).ok();
}

#[test]
fn unspecified_provider_kinds_use_structured_scip_descriptors() {
    let root = root("unspecified-kind");
    let mut index = base_index();
    let mut source = document("src/main.ts");
    let mut function = SymbolInformation::new();
    function.symbol = "scip-typescript npm . . demo/`main.ts`/target().".to_string();
    function.kind = EnumOrUnknown::new(Kind::UnspecifiedKind);
    source
        .occurrences
        .push(single_line(&function.symbol, 1, 0, 6, 1));
    source.symbols.push(function);
    let mut type_information = SymbolInformation::new();
    type_information.symbol = "scip-typescript npm . . demo/`main.ts`/Payload#".to_string();
    type_information.kind = EnumOrUnknown::new(Kind::UnspecifiedKind);
    source.symbols.push(type_information);
    for identity in [
        "scip-typescript npm . . demo/`main.ts`/",
        "scip-typescript npm . . demo/`main.ts`/Payload#run().",
        "scip-typescript npm . . demo/`main.ts`/value.",
        "scip-typescript npm . . demo/`main.ts`/Payload#field.",
        "scip-typescript npm . . demo/`main.ts`/target().(argument)",
        "scip-typescript npm . . demo/`main.ts`/expand!",
    ] {
        let mut information = SymbolInformation::new();
        information.symbol = identity.to_string();
        information.kind = EnumOrUnknown::new(Kind::UnspecifiedKind);
        source.symbols.push(information);
    }
    index.documents.push(source);

    let imported = ingest(&root, &index).unwrap();
    let callable = imported
        .symbols
        .values()
        .find(|symbol| symbol.provider_identity.ends_with("target()."))
        .unwrap();
    let type_symbol = imported
        .symbols
        .values()
        .find(|symbol| symbol.provider_identity.ends_with("Payload#"))
        .unwrap();
    assert_eq!(callable.kind.category, SemanticSymbolCategory::Callable);
    assert_eq!(type_symbol.kind.category, SemanticSymbolCategory::Type);
    let categories = imported
        .symbols
        .values()
        .map(|symbol| (symbol.provider_identity.as_str(), symbol.kind.category))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        categories["scip-typescript npm . . demo/`main.ts`/"],
        SemanticSymbolCategory::Module
    );
    assert_eq!(
        categories["scip-typescript npm . . demo/`main.ts`/Payload#run()."],
        SemanticSymbolCategory::Method
    );
    assert_eq!(
        categories["scip-typescript npm . . demo/`main.ts`/value."],
        SemanticSymbolCategory::Variable
    );
    assert_eq!(
        categories["scip-typescript npm . . demo/`main.ts`/Payload#field."],
        SemanticSymbolCategory::FieldOrProperty
    );
    assert_eq!(
        categories["scip-typescript npm . . demo/`main.ts`/target().(argument)"],
        SemanticSymbolCategory::Parameter
    );
    assert_eq!(
        categories["scip-typescript npm . . demo/`main.ts`/expand!"],
        SemanticSymbolCategory::Macro
    );
    fs::remove_dir_all(root).ok();
}
