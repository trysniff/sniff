use super::{
    SourceByteRange, SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicNamespace,
    SourcePublicReexport, SourcePublicReexportKind, SourcePublicSurface, SourcePublicSymbolKind,
};
use oxc_ast::ast::{
    BindingPattern, BindingPatternKind, Class, ClassElement, Declaration, ExportAllDeclaration,
    ExportDefaultDeclaration, ExportDefaultDeclarationKind, ExportNamedDeclaration,
    MethodDefinitionKind, PropertyKey, Statement, TSAccessibility, TSEnumDeclaration,
    TSEnumMemberName, TSInterfaceDeclaration, TSSignature,
};
use oxc_span::{GetSpan, SourceType, Span};
use std::path::Path;

pub(super) fn census(file_path: &str, source: &[u8]) -> Result<SourcePublicSurface, String> {
    let source = std::str::from_utf8(source)
        .map_err(|error| format!("JavaScript/TypeScript source is not UTF-8: {error}"))?;
    let source_type = SourceType::from_path(Path::new(file_path)).map_err(|error| {
        format!("failed to resolve JavaScript/TypeScript source type for {file_path}: {error:?}")
    })?;
    let allocator = oxc_allocator::Allocator::default();
    let parsed = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() {
        return Err(format!(
            "failed to parse JavaScript/TypeScript public surface for {file_path}: {} parser error(s): {:?}",
            parsed.errors.len(),
            parsed.errors
        ));
    }

    let mut surface = SourcePublicSurface {
        declarations: Vec::new(),
        reexports: Vec::new(),
    };
    for statement in &parsed.program.body {
        match statement {
            Statement::ExportNamedDeclaration(export) => collect_named(export, &mut surface)?,
            Statement::ExportDefaultDeclaration(export) => collect_default(export, &mut surface)?,
            Statement::ExportAllDeclaration(export) => {
                collect_export_all(export, source, &mut surface)?;
            }
            _ => {}
        }
    }
    Ok(surface)
}

fn collect_named(
    export: &ExportNamedDeclaration<'_>,
    surface: &mut SourcePublicSurface,
) -> Result<(), String> {
    if let Some(declaration) = &export.declaration {
        collect_direct_declaration(declaration, &mut surface.declarations)?;
    }
    let source_module = export
        .source
        .as_ref()
        .map(|source| source.value.to_string());
    for specifier in &export.specifiers {
        let exposed = specifier.exported.span();
        surface.declarations.push(SourcePublicDeclaration {
            name: specifier.exported.name().to_string(),
            target_name: specifier.local.name().to_string(),
            owner: None,
            namespace: SourcePublicNamespace::Module,
            kind: SourcePublicSymbolKind::CompilerDefined,
            exposed_identifier: byte_range(exposed),
            compiler_anchor: byte_range(exposed),
            owner_compiler_anchor: None,
            binding: SourcePublicBindingKind::Reference,
            source_module: source_module.clone(),
        });
    }
    Ok(())
}

fn collect_direct_declaration(
    declaration: &Declaration<'_>,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<(), String> {
    match declaration {
        Declaration::FunctionDeclaration(function) => {
            if let Some(identifier) = &function.id {
                push_definition(
                    declarations,
                    identifier.name.as_str(),
                    identifier.span,
                    SourcePublicSymbolKind::Callable,
                );
            }
        }
        Declaration::ClassDeclaration(class) => {
            if let Some(identifier) = &class.id {
                push_definition(
                    declarations,
                    identifier.name.as_str(),
                    identifier.span,
                    SourcePublicSymbolKind::Type,
                );
                collect_class_members(class, identifier.name.as_str(), declarations)?;
            }
        }
        Declaration::VariableDeclaration(variable) => {
            for declarator in &variable.declarations {
                collect_binding_pattern(&declarator.id, declarations);
            }
        }
        Declaration::TSTypeAliasDeclaration(declaration) => push_definition(
            declarations,
            declaration.id.name.as_str(),
            declaration.id.span,
            SourcePublicSymbolKind::Type,
        ),
        Declaration::TSInterfaceDeclaration(declaration) => {
            push_definition(
                declarations,
                declaration.id.name.as_str(),
                declaration.id.span,
                SourcePublicSymbolKind::Type,
            );
            collect_interface_members(declaration, declarations)?;
        }
        Declaration::TSEnumDeclaration(declaration) => {
            push_definition(
                declarations,
                declaration.id.name.as_str(),
                declaration.id.span,
                SourcePublicSymbolKind::Type,
            );
            collect_enum_members(declaration, declarations)?;
        }
        Declaration::TSModuleDeclaration(declaration) => match &declaration.id {
            oxc_ast::ast::TSModuleDeclarationName::Identifier(identifier) => push_definition(
                declarations,
                identifier.name.as_str(),
                identifier.span,
                SourcePublicSymbolKind::Module,
            ),
            oxc_ast::ast::TSModuleDeclarationName::StringLiteral(_) => {
                return Err(
                    "exported ambient string-literal modules are not a public API slot".into(),
                );
            }
        },
        Declaration::UsingDeclaration(_) | Declaration::TSImportEqualsDeclaration(_) => {
            return Err("unsupported exported JavaScript/TypeScript declaration kind".into());
        }
    }
    Ok(())
}

fn collect_binding_pattern(
    pattern: &BindingPattern<'_>,
    declarations: &mut Vec<SourcePublicDeclaration>,
) {
    match &pattern.kind {
        BindingPatternKind::BindingIdentifier(identifier) => push_definition(
            declarations,
            identifier.name.as_str(),
            identifier.span,
            SourcePublicSymbolKind::Variable,
        ),
        BindingPatternKind::ObjectPattern(pattern) => {
            for property in &pattern.properties {
                collect_binding_pattern(&property.value, declarations);
            }
            if let Some(rest) = &pattern.rest {
                collect_binding_pattern(&rest.argument, declarations);
            }
        }
        BindingPatternKind::ArrayPattern(pattern) => {
            for element in pattern.elements.iter().flatten() {
                collect_binding_pattern(element, declarations);
            }
            if let Some(rest) = &pattern.rest {
                collect_binding_pattern(&rest.argument, declarations);
            }
        }
        BindingPatternKind::AssignmentPattern(pattern) => {
            collect_binding_pattern(&pattern.left, declarations);
        }
    }
}

fn collect_default(
    export: &ExportDefaultDeclaration<'_>,
    surface: &mut SourcePublicSurface,
) -> Result<(), String> {
    let exposed = byte_range(export.exported.span());
    let (target_name, anchor, kind, binding) = match &export.declaration {
        ExportDefaultDeclarationKind::FunctionDeclaration(function) => function.id.as_ref().map_or(
            (
                "default",
                exposed,
                SourcePublicSymbolKind::Callable,
                SourcePublicBindingKind::Unsupported,
            ),
            |identifier| {
                (
                    identifier.name.as_str(),
                    byte_range(identifier.span),
                    SourcePublicSymbolKind::Callable,
                    SourcePublicBindingKind::Definition,
                )
            },
        ),
        ExportDefaultDeclarationKind::ClassDeclaration(class) => class.id.as_ref().map_or(
            (
                "default",
                exposed,
                SourcePublicSymbolKind::Type,
                SourcePublicBindingKind::Unsupported,
            ),
            |identifier| {
                (
                    identifier.name.as_str(),
                    byte_range(identifier.span),
                    SourcePublicSymbolKind::Type,
                    SourcePublicBindingKind::Definition,
                )
            },
        ),
        ExportDefaultDeclarationKind::TSInterfaceDeclaration(declaration) => (
            declaration.id.name.as_str(),
            byte_range(declaration.id.span),
            SourcePublicSymbolKind::Type,
            SourcePublicBindingKind::Definition,
        ),
        ExportDefaultDeclarationKind::TSEnumDeclaration(declaration) => (
            declaration.id.name.as_str(),
            byte_range(declaration.id.span),
            SourcePublicSymbolKind::Type,
            SourcePublicBindingKind::Definition,
        ),
        _ => (
            "default",
            exposed,
            SourcePublicSymbolKind::CompilerDefined,
            SourcePublicBindingKind::Unsupported,
        ),
    };
    surface.declarations.push(SourcePublicDeclaration {
        name: "default".to_string(),
        target_name: target_name.to_string(),
        owner: None,
        namespace: SourcePublicNamespace::Module,
        kind,
        exposed_identifier: exposed,
        compiler_anchor: anchor,
        owner_compiler_anchor: None,
        binding,
        source_module: None,
    });
    match &export.declaration {
        ExportDefaultDeclarationKind::ClassDeclaration(class) => {
            if let Some(identifier) = &class.id {
                collect_class_members(class, identifier.name.as_str(), &mut surface.declarations)?;
            }
        }
        ExportDefaultDeclarationKind::TSInterfaceDeclaration(declaration) => {
            collect_interface_members(declaration, &mut surface.declarations)?;
        }
        ExportDefaultDeclarationKind::TSEnumDeclaration(declaration) => {
            collect_enum_members(declaration, &mut surface.declarations)?;
        }
        _ => {}
    }
    Ok(())
}

fn collect_class_members(
    class: &Class<'_>,
    owner: &str,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<(), String> {
    for element in &class.body.body {
        match element {
            ClassElement::StaticBlock(_) => {}
            ClassElement::MethodDefinition(method) => {
                if method.accessibility == Some(TSAccessibility::Private)
                    || method.key.is_private_identifier()
                {
                    continue;
                }
                let namespace =
                    if method.r#static || method.kind == MethodDefinitionKind::Constructor {
                        SourcePublicNamespace::StaticMember
                    } else {
                        SourcePublicNamespace::InstanceMember
                    };
                push_key_member(
                    declarations,
                    owner,
                    &method.key,
                    SourcePublicSymbolKind::Method,
                    namespace,
                )?;
            }
            ClassElement::PropertyDefinition(property) => {
                if property.accessibility == Some(TSAccessibility::Private)
                    || property.key.is_private_identifier()
                {
                    continue;
                }
                push_key_member(
                    declarations,
                    owner,
                    &property.key,
                    SourcePublicSymbolKind::Field,
                    if property.r#static {
                        SourcePublicNamespace::StaticMember
                    } else {
                        SourcePublicNamespace::InstanceMember
                    },
                )?;
            }
            ClassElement::AccessorProperty(property) => {
                if property.key.is_private_identifier() {
                    continue;
                }
                push_key_member(
                    declarations,
                    owner,
                    &property.key,
                    SourcePublicSymbolKind::Field,
                    if property.r#static {
                        SourcePublicNamespace::StaticMember
                    } else {
                        SourcePublicNamespace::InstanceMember
                    },
                )?;
            }
            ClassElement::TSIndexSignature(_) => {
                return Err(format!(
                    "exported class {owner} has an unnamed index-signature API surface"
                ));
            }
        }
    }
    Ok(())
}

fn collect_interface_members(
    interface: &TSInterfaceDeclaration<'_>,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<(), String> {
    let owner = interface.id.name.as_str();
    for member in &interface.body.body {
        let (key, kind) = match member {
            TSSignature::TSPropertySignature(property) => {
                (&property.key, SourcePublicSymbolKind::Field)
            }
            TSSignature::TSMethodSignature(method) => (&method.key, SourcePublicSymbolKind::Method),
            TSSignature::TSIndexSignature(_)
            | TSSignature::TSCallSignatureDeclaration(_)
            | TSSignature::TSConstructSignatureDeclaration(_) => {
                return Err(format!(
                    "exported interface {owner} has an unnamed callable or index API surface"
                ));
            }
        };
        push_key_member(
            declarations,
            owner,
            key,
            kind,
            SourcePublicNamespace::InstanceMember,
        )?;
    }
    Ok(())
}

fn collect_enum_members(
    declaration: &TSEnumDeclaration<'_>,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<(), String> {
    let owner = declaration.id.name.as_str();
    for member in &declaration.members {
        let (name, span) = match &member.id {
            TSEnumMemberName::StaticIdentifier(identifier) => {
                (identifier.name.to_string(), identifier.span)
            }
            TSEnumMemberName::StaticStringLiteral(literal) => {
                (literal.value.to_string(), literal.span)
            }
            _ => {
                return Err(format!(
                    "exported enum {owner} has a non-static member name"
                ));
            }
        };
        push_member(
            declarations,
            owner,
            &name,
            span,
            SourcePublicSymbolKind::Field,
            SourcePublicNamespace::StaticMember,
        );
    }
    Ok(())
}

fn push_key_member(
    declarations: &mut Vec<SourcePublicDeclaration>,
    owner: &str,
    key: &PropertyKey<'_>,
    kind: SourcePublicSymbolKind,
    namespace: SourcePublicNamespace,
) -> Result<(), String> {
    let name = key
        .static_name()
        .ok_or_else(|| format!("exported type {owner} has a computed public member name"))?;
    push_member(
        declarations,
        owner,
        name.as_str(),
        key.span(),
        kind,
        namespace,
    );
    Ok(())
}

fn push_member(
    declarations: &mut Vec<SourcePublicDeclaration>,
    owner: &str,
    name: &str,
    span: Span,
    kind: SourcePublicSymbolKind,
    namespace: SourcePublicNamespace,
) {
    let identifier = byte_range(span);
    declarations.push(SourcePublicDeclaration {
        name: name.to_string(),
        target_name: name.to_string(),
        owner: Some(owner.to_string()),
        namespace,
        kind,
        exposed_identifier: identifier,
        compiler_anchor: identifier,
        owner_compiler_anchor: None,
        binding: SourcePublicBindingKind::Definition,
        source_module: None,
    });
}

fn collect_export_all(
    export: &ExportAllDeclaration<'_>,
    source: &str,
    surface: &mut SourcePublicSurface,
) -> Result<(), String> {
    let (kind, name, exposed_identifier, compiler_anchor) = match &export.exported {
        Some(exported) => (
            SourcePublicReexportKind::Namespace,
            Some(exported.name().to_string()),
            Some(byte_range(exported.span())),
            byte_range(exported.span()),
        ),
        None => (
            SourcePublicReexportKind::Wildcard,
            None,
            None,
            quoted_string_range(export.source.span, source)?,
        ),
    };
    surface.reexports.push(SourcePublicReexport {
        kind,
        name,
        source_module: export.source.value.to_string(),
        directive: byte_range(export.span),
        exposed_identifier,
        compiler_anchor,
    });
    Ok(())
}

fn push_definition(
    declarations: &mut Vec<SourcePublicDeclaration>,
    name: &str,
    span: Span,
    kind: SourcePublicSymbolKind,
) {
    let identifier = byte_range(span);
    declarations.push(SourcePublicDeclaration {
        name: name.to_string(),
        target_name: name.to_string(),
        owner: None,
        namespace: SourcePublicNamespace::Module,
        kind,
        exposed_identifier: identifier,
        compiler_anchor: identifier,
        owner_compiler_anchor: None,
        binding: SourcePublicBindingKind::Definition,
        source_module: None,
    });
}

fn quoted_string_range(span: Span, source: &str) -> Result<SourceByteRange, String> {
    let range = byte_range(span);
    if range.end.saturating_sub(range.start) < 2 || range.end > source.len() {
        return Err("JavaScript/TypeScript module specifier has an invalid range".into());
    }
    let bytes = source.as_bytes();
    if !matches!(
        (bytes[range.start], bytes[range.end - 1]),
        (b'\'', b'\'') | (b'"', b'"')
    ) {
        return Err("JavaScript/TypeScript module specifier is not quoted".into());
    }
    Ok(range)
}

fn byte_range(span: Span) -> SourceByteRange {
    SourceByteRange {
        start: span.start as usize,
        end: span.end as usize,
    }
}
