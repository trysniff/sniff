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
    assert_eq!(slice(source, wildcard.compiler_anchor), "\"./wildcard\"");
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

#[test]
fn python_surface_collects_public_definitions_and_class_members_with_exact_spans() {
    let source = br#"from typing import ClassVar, overload

PUBLIC_CONSTANT: int = 7
_PRIVATE_CONSTANT: int = 8

def public(value: str) -> str:
    return value

class Widget:
    static_category = "widget"
    version: ClassVar[int] = 1
    category: str = "public"

    def __init__(self) -> None:
        self.label: str = "ready"
        if self.label:
            self.ready = True
        self._cache = {}

    def render(self) -> str:
        return self.category

    @staticmethod
    def build() -> "Widget":
        return Widget()

    @classmethod
    def configure(cls) -> None:
        cls.mode = "configured"

    def _hidden(self) -> None:
        pass
"#;

    let surface = census_source_public_surface("pkg/core.py", source).expect("Python surface");
    let declaration = |name: &str, owner: Option<&str>| {
        surface
            .declarations
            .iter()
            .find(|declaration| declaration.name == name && declaration.owner.as_deref() == owner)
            .unwrap_or_else(|| panic!("missing Python declaration {owner:?}::{name}"))
    };

    for (name, owner) in [
        ("PUBLIC_CONSTANT", None),
        ("public", None),
        ("Widget", None),
        ("static_category", Some("Widget")),
        ("version", Some("Widget")),
        ("category", Some("Widget")),
        ("label", Some("Widget")),
        ("ready", Some("Widget")),
        ("mode", Some("Widget")),
        ("__init__", Some("Widget")),
        ("render", Some("Widget")),
        ("build", Some("Widget")),
        ("configure", Some("Widget")),
    ] {
        let item = declaration(name, owner);
        assert_eq!(slice(source, item.exposed_identifier), name);
        assert_eq!(item.exposed_identifier, item.compiler_anchor);
        assert_eq!(item.binding, SourcePublicBindingKind::Definition);
    }
    assert_eq!(
        declaration("build", Some("Widget")).namespace,
        super::SourcePublicNamespace::StaticMember
    );
    assert_eq!(
        declaration("render", Some("Widget")).namespace,
        super::SourcePublicNamespace::InstanceMember
    );
    for name in ["category", "label", "ready"] {
        assert_eq!(
            declaration(name, Some("Widget")).namespace,
            super::SourcePublicNamespace::InstanceMember
        );
    }
    for name in ["static_category", "version", "mode"] {
        assert_eq!(
            declaration(name, Some("Widget")).namespace,
            super::SourcePublicNamespace::StaticMember
        );
    }
    assert!(!surface.declarations.iter().any(|declaration| {
        matches!(
            declaration.name.as_str(),
            "_PRIVATE_CONSTANT" | "_hidden" | "overload"
        )
    }));
}

#[test]
fn python_surface_models_explicit_imports_and_selective_wildcards() {
    let source = br#"from .core import Widget as PublicWidget, parse
from .extra import *
from . import core as namespace
import pkg.tools as tools

__all__ = ["PublicWidget", "parse"] + ("Extra", "namespace", "tools")
"#;

    let surface = census_source_public_surface("pkg/__init__.py", source).expect("Python surface");
    let declaration = |name: &str| {
        surface
            .declarations
            .iter()
            .find(|declaration| declaration.name == name)
            .unwrap_or_else(|| panic!("missing Python import {name}"))
    };
    let widget = declaration("PublicWidget");
    assert_eq!(widget.target_name, "Widget");
    assert_eq!(widget.source_module.as_deref(), Some(".core"));
    assert_eq!(slice(source, widget.exposed_identifier), "PublicWidget");
    assert_eq!(
        slice(source, widget.compiler_anchor),
        "Widget as PublicWidget"
    );
    let parse = declaration("parse");
    assert_eq!(parse.target_name, "parse");
    assert_eq!(slice(source, parse.compiler_anchor), "parse");

    let namespace = surface
        .reexports
        .iter()
        .find(|reexport| reexport.name.as_deref() == Some("namespace"))
        .expect("relative namespace import");
    assert_eq!(namespace.kind, SourcePublicReexportKind::Namespace);
    assert_eq!(namespace.source_module, ".core");
    assert_eq!(
        slice(source, namespace.compiler_anchor),
        "core as namespace"
    );
    assert_eq!(
        slice(
            source,
            namespace.exposed_identifier.expect("namespace name")
        ),
        "namespace"
    );

    let tools = surface
        .reexports
        .iter()
        .find(|reexport| reexport.name.as_deref() == Some("tools"))
        .expect("absolute namespace import");
    assert_eq!(tools.source_module, "pkg.tools");
    assert_eq!(slice(source, tools.compiler_anchor), "pkg.tools");

    let wildcard = surface
        .reexports
        .iter()
        .find(|reexport| {
            reexport.kind == SourcePublicReexportKind::Wildcard
                && reexport.name.as_deref() == Some("Extra")
        })
        .expect("selective wildcard");
    assert_eq!(wildcard.source_module, ".extra");
    assert_eq!(slice(source, wildcard.compiler_anchor), ".extra");
}

#[test]
fn python_surface_keeps_only_explicit_self_aliases_without_all() {
    let source = br#"from os import path
from .core import Widget as Widget
import pkg.tools as pkg_tools
"#;

    let surface = census_source_public_surface("pkg/public.py", source).expect("Python surface");

    assert_eq!(surface.declarations.len(), 1);
    assert_eq!(surface.declarations[0].name, "Widget");
    assert!(surface.reexports.is_empty());
}

#[test]
fn python_surface_rejects_dynamic_all_and_public_destructuring() {
    let dynamic = census_source_public_surface(
        "pkg/dynamic.py",
        b"__all__ = ['first']\n__all__.append(name)\n",
    )
    .expect_err("dynamic __all__ must fail closed");
    assert!(dynamic.contains("mutated dynamically"), "{dynamic}");

    let destructured =
        census_source_public_surface("pkg/destructured.py", b"public, other = make_values()\n")
            .expect_err("public destructuring must fail closed");
    assert!(destructured.contains("destructuring"), "{destructured}");
}

#[test]
fn python_surface_rejects_unrepresented_conditional_public_bindings() {
    let conditional = census_source_public_surface(
        "pkg/conditional.py",
        br#"if use_fast:
    from .fast import Client as Client
else:
    from .slow import Client as Client
"#,
    )
    .expect_err("conditional public import must require variant identity");
    assert!(
        conditional.contains("explicit build/runtime variant"),
        "{conditional}"
    );

    let deletion = census_source_public_surface("pkg/deleted.py", b"public = 1\ndel public\n")
        .expect_err("public deletion must fail closed");
    assert!(deletion.contains("public deletion"), "{deletion}");

    let entrypoint = census_source_public_surface(
        "pkg/entrypoint.py",
        br#"def main() -> None:
    pass

if __name__ == "__main__":
    main()
"#,
    )
    .expect("non-binding entrypoint branch remains representable");
    assert_eq!(entrypoint.declarations.len(), 1);
    assert_eq!(entrypoint.declarations[0].name, "main");
}

#[test]
fn python_surface_binds_overloads_to_one_compiler_definition() {
    let source = br#"from typing import overload

@overload
def parse(value: str) -> str: ...

@overload
def parse(value: int) -> int: ...

def parse(value: str | int) -> str | int:
    return value
"#;

    let surface = census_source_public_surface("pkg/core.py", source).expect("Python surface");
    let parse = surface
        .declarations
        .iter()
        .filter(|declaration| declaration.name == "parse")
        .collect::<Vec<_>>();

    assert_eq!(parse.len(), 3);
    assert_eq!(parse[0].binding, SourcePublicBindingKind::Definition);
    assert!(
        parse[1..]
            .iter()
            .all(|declaration| declaration.binding == SourcePublicBindingKind::Reference)
    );
}

fn slice(source: &[u8], range: super::SourceByteRange) -> &str {
    std::str::from_utf8(&source[range.start..range.end]).expect("UTF-8 range")
}

#[test]
fn rust_surface_collects_public_definitions_members_and_reexports() {
    let source = br#"mod hidden;
pub mod public;

pub use hidden::Hidden as Alias;
pub use public::*;

pub struct Record {
    pub value: u32,
    private: u32,
}

pub enum Choice {
    First,
    Second { value: u32 },
}

pub trait Contract {
    type Output;
    const LIMIT: usize;
    fn transform(&self) -> Self::Output;
    fn construct() -> Self;
}

impl Record {
    pub fn method(&self) -> u32 { self.value }
    pub fn associated() -> Self { Self { value: 0, private: 0 } }
    fn private_method(&self) -> u32 { self.private }
}

pub fn run() {}
pub const LIMIT: usize = 3;
pub static ENABLED: bool = true;
pub type PublicAlias = Record;
"#;

    let surface = census_source_public_surface("src/lib.rs", source).expect("Rust surface");
    let declarations = surface
        .declarations
        .iter()
        .map(|declaration| {
            assert_eq!(
                slice(source, declaration.exposed_identifier),
                declaration.name
            );
            assert_eq!(slice(source, declaration.compiler_anchor), declaration.name);
            (
                declaration.name.as_str(),
                declaration.owner.as_deref(),
                declaration.namespace,
                declaration.kind,
                declaration.binding,
            )
        })
        .collect::<Vec<_>>();

    assert!(declarations.contains(&(
        "Record",
        None,
        super::SourcePublicNamespace::Module,
        SourcePublicSymbolKind::Type,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "value",
        Some("Record"),
        super::SourcePublicNamespace::InstanceMember,
        SourcePublicSymbolKind::Field,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "First",
        Some("Choice"),
        super::SourcePublicNamespace::StaticMember,
        SourcePublicSymbolKind::Constant,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "method",
        Some("Record"),
        super::SourcePublicNamespace::InstanceMember,
        SourcePublicSymbolKind::Method,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "associated",
        Some("Record"),
        super::SourcePublicNamespace::StaticMember,
        SourcePublicSymbolKind::Method,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "transform",
        Some("Contract"),
        super::SourcePublicNamespace::InstanceMember,
        SourcePublicSymbolKind::Method,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "construct",
        Some("Contract"),
        super::SourcePublicNamespace::StaticMember,
        SourcePublicSymbolKind::Method,
        SourcePublicBindingKind::Definition,
    )));
    assert!(declarations.contains(&(
        "Alias",
        None,
        super::SourcePublicNamespace::Module,
        SourcePublicSymbolKind::CompilerDefined,
        SourcePublicBindingKind::Reference,
    )));
    assert!(
        !declarations
            .iter()
            .any(|(name, _, _, _, _)| { matches!(*name, "private" | "private_method") })
    );

    assert_eq!(surface.reexports.len(), 2);
    let module = surface
        .reexports
        .iter()
        .find(|reexport| reexport.kind == SourcePublicReexportKind::Namespace)
        .expect("public module");
    assert_eq!(module.name.as_deref(), Some("public"));
    assert_eq!(slice(source, module.compiler_anchor), "public");
    let wildcard = surface
        .reexports
        .iter()
        .find(|reexport| reexport.kind == SourcePublicReexportKind::Wildcard)
        .expect("public glob");
    assert_eq!(wildcard.source_module, "public");
    assert_eq!(slice(source, wildcard.compiler_anchor), "public");
}

#[test]
fn rust_surface_rejects_restricted_conditional_inline_and_tuple_exports() {
    let restricted = census_source_public_surface(
        "src/lib.rs",
        b"pub(crate) fn crate_only() {}\npub(super) const PARENT: usize = 1;\n",
    )
    .expect("restricted visibility is not externally public");
    assert!(restricted.declarations.is_empty());
    assert!(restricted.reexports.is_empty());

    let conditional = census_source_public_surface(
        "src/lib.rs",
        b"#[cfg(feature = \"fast\")]\npub fn selected() {}\n",
    )
    .expect_err("conditional API requires a variant");
    assert!(
        conditional.contains("explicit build variant"),
        "{conditional}"
    );

    let inline =
        census_source_public_surface("src/lib.rs", b"pub mod inline { pub fn nested() {} }\n")
            .expect_err("inline module must not be flattened");
    assert!(inline.contains("inline public Rust module"), "{inline}");

    let tuple = census_source_public_surface("src/lib.rs", b"pub struct Newtype(pub u32);\n")
        .expect_err("tuple field must not use its type as an identifier");
    assert!(tuple.contains("no exact source identifier"), "{tuple}");

    let private_owner = census_source_public_surface(
        "src/lib.rs",
        b"struct Private;\nimpl Private { pub fn inaccessible(&self) {} }\n",
    )
    .expect("public syntax on a private type is not external API");
    assert!(private_owner.declarations.is_empty());

    let cross_file_owner = census_source_public_surface(
        "src/extensions.rs",
        b"impl crate::Root { pub fn cross_file(&self) {} }\n",
    )
    .expect("cross-file inherent impl retains an exact owner anchor");
    let method = cross_file_owner
        .declarations
        .iter()
        .find(|declaration| declaration.name == "cross_file")
        .unwrap();
    assert_eq!(method.owner.as_deref(), Some("Root"));
    assert_eq!(
        slice(
            b"impl crate::Root { pub fn cross_file(&self) {} }\n",
            method.owner_compiler_anchor.unwrap()
        ),
        "Root"
    );
}
