use super::*;
use protobuf::{EnumOrUnknown, Message, MessageField};
use scip::types::{
    Document, Index, Metadata, Occurrence, PositionEncoding, Relationship, Signature,
    SingleLineRange, SymbolInformation, TextEncoding, ToolInfo, symbol_information::Kind,
};

const METHOD: &str = "rust-analyzer cargo demo 1.0.0 Service#process().";
const REQUIRED: &str = "rust-analyzer cargo demo 1.0.0 Protocol#process().";
const OWNER: &str = "rust-analyzer cargo demo 1.0.0 Service#";
const PROTOCOL: &str = "rust-analyzer cargo demo 1.0.0 Protocol#";

fn symbol(identity: &str, name: &str, kind: Kind, signature: &str) -> SymbolInformation {
    let mut information = SymbolInformation::new();
    information.symbol = identity.to_string();
    information.display_name = name.to_string();
    information.kind = EnumOrUnknown::new(kind);
    let mut documentation = Signature::new();
    documentation.language = "rust".to_string();
    documentation.text = signature.to_string();
    information.signature_documentation = MessageField::some(documentation);
    information
}

fn implements(target: &str) -> Relationship {
    let mut relationship = Relationship::new();
    relationship.symbol = target.to_string();
    relationship.is_implementation = true;
    relationship
}

fn definition(identity: &str, line: i32, character: i32, length: i32) -> Occurrence {
    let mut occurrence = Occurrence::new();
    occurrence.symbol = identity.to_string();
    occurrence.symbol_roles = 1;
    let mut range = SingleLineRange::new();
    range.line = line;
    range.start_character = character;
    range.end_character = character + length;
    occurrence.set_single_line_range(range);
    occurrence
}

#[test]
fn scip_ingestion_and_ast_join_preserve_contracts_in_normal_method_contexts() {
    // Synthetic SCIP bytes exercise the real ingestion/join/render path, not a compiler run.
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    let path = root.path().join("src/lib.rs");
    let source = "trait Protocol {\n    fn process(&self, value: i32) -> i32;\n}\nstruct Service;\nimpl Protocol for Service {\n    fn process(&self, value: i32) -> i32 { value }\n}\n";
    fs::write(&path, source).unwrap();
    let file = crate::parser::parse_file_checked(&path.to_string_lossy()).unwrap();
    assert_eq!(file.methods.len(), 2);

    let mut tool = ToolInfo::new();
    tool.name = "rust-analyzer".to_string();
    let mut metadata = Metadata::new();
    metadata.tool_info = MessageField::some(tool);
    metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
    let mut method = symbol(
        METHOD,
        "process",
        Kind::Method,
        "fn process(&self, value: i32) -> i32",
    );
    method.enclosing_symbol = OWNER.to_string();
    method.relationships.push(implements(REQUIRED));
    let mut owner = symbol(OWNER, "Service", Kind::Struct, "struct Service");
    owner.relationships.push(implements(PROTOCOL));
    let mut required = symbol(
        REQUIRED,
        "process",
        Kind::Method,
        "fn process(&self, value: i32) -> i32;",
    );
    required.enclosing_symbol = PROTOCOL.to_string();
    let mut document = Document::new();
    document.relative_path = "src/lib.rs".to_string();
    document.language = "rust".to_string();
    document.position_encoding =
        EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
    document.symbols = vec![
        method,
        owner,
        required,
        symbol(PROTOCOL, "Protocol", Kind::Interface, "trait Protocol"),
    ];
    document.occurrences = vec![
        definition(PROTOCOL, 0, 6, 8),
        definition(REQUIRED, 1, 7, 7),
        definition(OWNER, 3, 7, 7),
        definition(METHOD, 5, 7, 7),
    ];
    let mut scip = Index::new();
    scip.metadata = MessageField::some(metadata);
    scip.documents.push(document);
    let index =
        crate::semantic_index_scip::ingest_scip_bytes(root.path(), &scip.write_to_bytes().unwrap())
            .unwrap();
    let files = vec![file];
    let join = super::super::join_methods(root.path(), &files, &index).unwrap();
    join.require_complete().unwrap();
    let contexts = render_compiler_method_contexts(root.path(), &files, &index, &join).unwrap();
    assert_eq!(contexts.len(), 2);
    let implementation = files[0]
        .methods
        .iter()
        .find(|method| method.start_line == 6)
        .unwrap();
    let text = &contexts[&method_context_key(&files[0].file_path, &implementation.name, 6)];
    assert!(text.contains("compiler method relationship:"));
    assert!(text.contains(REQUIRED));
    assert!(text.contains("compiler enclosing symbol relationship:"));
    assert!(text.contains(PROTOCOL));
    assert!(text.contains("fn process(&self, value: i32) -> i32;"));
    assert!(text.contains("compiler public/entrypoint surfaces: not established by this index"));
    assert!(text.contains("not proof that tests are absent"));
}
