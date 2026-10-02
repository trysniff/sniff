use super::{definition_line, definition_range};
use crate::semantic_index::SemanticPositionEncoding;

#[test]
fn parser_ranges_keep_attribute_and_multiline_identifiers_for_every_callable_kind() {
    for (source, name, start_line, identifier_line) in [
        ("#[inline]\nfn\nfree() {}\n", "free", 1, 2),
        (
            "struct S;\nimpl S {\n    #[inline]\n    fn\n    member() {}\n}\n",
            "member",
            3,
            4,
        ),
        (
            "trait T {\n    #[must_use]\n    fn\n    required(&self);\n}\n",
            "required",
            2,
            3,
        ),
        (
            "trait T {\n    #[inline]\n    fn\n    defaulted(&self) {}\n}\n",
            "defaulted",
            2,
            3,
        ),
        (
            "#[cfg(any())]\nunsafe extern \"C\" {\n    #[link_name = \"external\"]\n    fn\n    foreign();\n}\n",
            "foreign",
            3,
            4,
        ),
    ] {
        let repository = tempfile::tempdir().unwrap();
        let path = repository.path().join("lib.rs");
        std::fs::write(&path, source).unwrap();
        let file = crate::parser::parse_file_checked(&path.to_string_lossy()).unwrap();
        let method = file
            .methods
            .iter()
            .find(|method| method.name == name)
            .unwrap();
        assert_eq!(method.start_line, start_line, "{name}");
        assert_eq!(
            definition_line(&file, method).unwrap(),
            Some(identifier_line),
            "{name}"
        );
    }
}

#[test]
fn identifier_columns_match_each_compiler_position_encoding() {
    let repository = tempfile::tempdir().unwrap();
    let path = repository.path().join("lib.rs");
    // A supplementary character distinguishes bytes, UTF-16 units and scalar columns.
    let source = "/* \u{1f436} */ fn r#type() {}\n";
    std::fs::write(&path, source).unwrap();
    let file = crate::parser::parse_file_checked(&path.to_string_lossy()).unwrap();
    let method = &file.methods[0];
    for encoding in [
        SemanticPositionEncoding::Utf8,
        SemanticPositionEncoding::Utf16,
        SemanticPositionEncoding::Utf32,
    ] {
        let range = definition_range(&file, method, encoding).unwrap().unwrap();
        let offset = source.find("r#type").unwrap();
        let prefix = &source[..offset];
        let expected_start = match encoding {
            SemanticPositionEncoding::Utf8 => prefix.len(),
            SemanticPositionEncoding::Utf16 => prefix.encode_utf16().count(),
            SemanticPositionEncoding::Utf32 => prefix.chars().count(),
        };
        assert_eq!(range.start.character as usize, expected_start);
        assert_eq!(range.end.character - range.start.character, 6);
    }
}

#[test]
fn leading_bom_identifier_ranges_use_original_source_coordinates() {
    let repository = tempfile::tempdir().unwrap();
    let path = repository.path().join("lib.rs");
    std::fs::write(&path, "\u{feff}fn f() {}\n").unwrap();
    let file = crate::parser::parse_file_checked(&path.to_string_lossy()).unwrap();
    for (encoding, start) in [
        (SemanticPositionEncoding::Utf8, 6),
        (SemanticPositionEncoding::Utf16, 4),
        (SemanticPositionEncoding::Utf32, 4),
    ] {
        let range = definition_range(&file, &file.methods[0], encoding)
            .unwrap()
            .unwrap();
        assert_eq!(range.start.line, 0);
        assert_eq!(range.start.character, start);
        assert_eq!(range.end.character, start + 1);
    }
}
