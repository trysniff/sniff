use super::{
    SourcePublicBindingKind, SourcePublicReexportKind, SourcePublicSymbolKind,
    census_source_public_surface,
};

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
                &source[declaration.exposed_identifier.start..declaration.exposed_identifier.end],
                declaration.name.as_bytes()
            );
            assert_eq!(declaration.name, declaration.target_name);
            assert_eq!(declaration.exposed_identifier, declaration.compiler_anchor);
            assert_eq!(declaration.binding, SourcePublicBindingKind::Definition);
            assert_eq!(declaration.source_module, None);
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
fn js_ts_surface_separates_public_names_from_compiler_anchors() {
    let source = br#"export function direct(): string { return "direct"; }
export const value = 1;
export interface Shape { area(): number; }
export class Service {
  static run(): string { return "static"; }
  run(): string { return "instance"; }
  protected stop(): void {}
  private hidden(): void {}
  #secret = 1;
}
export enum Mode { Fast = "fast", Safe = "safe" }
export { direct as aliased } from "./named";
export { value as exposedValue, direct };
export default function namedDefault(): string { return "default"; }
export default function (): string { return "anonymous"; }
export * from "./wildcard";
export * as publicNamespace from "./namespace";
"#;

    let surface = census_source_public_surface("surface.ts", source).expect("TypeScript surface");
    let declaration = |name: &str, binding: SourcePublicBindingKind| {
        surface
            .declarations
            .iter()
            .find(|declaration| declaration.name == name && declaration.binding == binding)
            .unwrap_or_else(|| panic!("missing declaration {name}"))
    };

    let direct = declaration("direct", SourcePublicBindingKind::Definition);
    assert_eq!(direct.target_name, "direct");
    assert_eq!(direct.binding, SourcePublicBindingKind::Definition);
    assert_eq!(slice(source, direct.exposed_identifier), "direct");
    assert_eq!(slice(source, direct.compiler_anchor), "direct");
    assert_eq!(direct.namespace, super::SourcePublicNamespace::Module);

    let area = surface
        .declarations
        .iter()
        .find(|declaration| declaration.owner.as_deref() == Some("Shape"))
        .expect("interface method");
    assert_eq!(area.name, "area");
    assert_eq!(area.kind, SourcePublicSymbolKind::Method);
    assert_eq!(area.namespace, super::SourcePublicNamespace::InstanceMember);

    let runs = surface
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.owner.as_deref() == Some("Service") && declaration.name == "run"
        })
        .collect::<Vec<_>>();
    assert_eq!(runs.len(), 2);
    assert!(runs.iter().any(|declaration| {
        declaration.namespace == super::SourcePublicNamespace::StaticMember
    }));
    assert!(runs.iter().any(|declaration| {
        declaration.namespace == super::SourcePublicNamespace::InstanceMember
    }));
    assert!(surface.declarations.iter().any(|declaration| {
        declaration.owner.as_deref() == Some("Service") && declaration.name == "stop"
    }));
    assert!(!surface.declarations.iter().any(|declaration| {
        declaration.owner.as_deref() == Some("Service")
            && matches!(declaration.name.as_str(), "hidden" | "secret")
    }));
    assert_eq!(
        surface
            .declarations
            .iter()
            .filter(|declaration| declaration.owner.as_deref() == Some("Mode"))
            .count(),
        2
    );

    let aliased = declaration("aliased", SourcePublicBindingKind::Reference);
    assert_eq!(aliased.target_name, "direct");
    assert_eq!(aliased.binding, SourcePublicBindingKind::Reference);
    assert_eq!(aliased.source_module.as_deref(), Some("./named"));
    assert_eq!(slice(source, aliased.exposed_identifier), "aliased");
    assert_eq!(slice(source, aliased.compiler_anchor), "aliased");

    let default = surface
        .declarations
        .iter()
        .find(|declaration| {
            declaration.name == "default"
                && declaration.binding == SourcePublicBindingKind::Definition
        })
        .expect("named default declaration");
    assert_eq!(default.target_name, "namedDefault");
    assert_eq!(slice(source, default.exposed_identifier), "default");
    assert_eq!(slice(source, default.compiler_anchor), "namedDefault");

    let unsupported = surface
        .declarations
        .iter()
        .find(|declaration| declaration.binding == SourcePublicBindingKind::Unsupported)
        .expect("anonymous default declaration");
    assert_eq!(unsupported.name, "default");
    assert_eq!(slice(source, unsupported.exposed_identifier), "default");

    assert_eq!(surface.reexports.len(), 2);
    let wildcard = surface
        .reexports
        .iter()
        .find(|reexport| reexport.kind == SourcePublicReexportKind::Wildcard)
        .expect("wildcard re-export");
    assert_eq!(wildcard.name, None);
    assert_eq!(wildcard.source_module, "./wildcard");
    assert_eq!(slice(source, wildcard.compiler_anchor), "./wildcard");
    let namespace = surface
        .reexports
        .iter()
        .find(|reexport| reexport.kind == SourcePublicReexportKind::Namespace)
        .expect("namespace re-export");
    assert_eq!(namespace.name.as_deref(), Some("publicNamespace"));
    assert_eq!(
        slice(
            source,
            namespace.exposed_identifier.expect("namespace name")
        ),
        "publicNamespace"
    );
    assert_eq!(slice(source, namespace.compiler_anchor), "publicNamespace");
}

#[test]
fn js_ts_surface_rejects_unnamed_exported_type_members() {
    let error = census_source_public_surface(
        "surface.ts",
        b"export interface Callable { (value: string): string; }\n",
    )
    .expect_err("unnamed interface call signature must fail closed");

    assert!(error.contains("unnamed callable or index"), "{error}");
}

fn slice(source: &[u8], range: super::SourceByteRange) -> &str {
    std::str::from_utf8(&source[range.start..range.end]).expect("UTF-8 range")
}

#[test]
fn source_surface_rejects_languages_without_a_complete_collector() {
    let error = census_source_public_surface("surface.py", b"def public():\n    pass\n")
        .expect_err("unsupported public-surface collector must fail closed");
    assert!(error.contains("not implemented for python"), "{error}");
}
