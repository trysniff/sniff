use super::{SourcePublicSymbolKind, census_source_public_surface};

#[test]
fn go_surface_collects_every_exported_declaration_kind_with_exact_spans() {
    let source = br#"package surface

const PublicConstant, privateConstant = 1, 2
var PublicVariable string

type PublicAlias = string
type PublicStruct struct {
    PublicField string
    privateField string
    PublicEmbedded
}

type PublicInterface interface {
    PublicMethod(value string) error
    privateMethod()
}

func PublicFunction() {}
func privateFunction() {}
func (PublicStruct) PublicReceiverMethod() {}
"#;

    let surface = census_source_public_surface("surface.go", source).expect("Go surface census");
    let actual = surface
        .declarations
        .iter()
        .map(|declaration| {
            assert_eq!(
                &source[declaration.identifier.start..declaration.identifier.end],
                declaration.name.as_bytes()
            );
            (
                declaration.name.as_str(),
                declaration.owner.as_deref(),
                declaration.kind,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            ("PublicAlias", None, SourcePublicSymbolKind::Type),
            ("PublicConstant", None, SourcePublicSymbolKind::Constant),
            (
                "PublicEmbedded",
                Some("PublicStruct"),
                SourcePublicSymbolKind::Field
            ),
            (
                "PublicField",
                Some("PublicStruct"),
                SourcePublicSymbolKind::Field
            ),
            ("PublicFunction", None, SourcePublicSymbolKind::Callable),
            ("PublicInterface", None, SourcePublicSymbolKind::Type),
            (
                "PublicMethod",
                Some("PublicInterface"),
                SourcePublicSymbolKind::Method
            ),
            (
                "PublicReceiverMethod",
                Some("PublicStruct"),
                SourcePublicSymbolKind::Method
            ),
            ("PublicStruct", None, SourcePublicSymbolKind::Type),
            ("PublicVariable", None, SourcePublicSymbolKind::Variable),
        ]
    );
}

#[test]
fn source_surface_rejects_languages_without_a_complete_collector() {
    let error = census_source_public_surface("surface.py", b"def public():\n    pass\n")
        .expect_err("unsupported public-surface collector must fail closed");
    assert!(error.contains("not implemented for python"), "{error}");
}
