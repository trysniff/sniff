use super::{
    SourceByteRange, SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicReexport,
    SourcePublicReexportKind, SourcePublicSurface, SourcePublicSymbolKind,
};
use oxc_ast::ast::{
    BindingPattern, BindingPatternKind, Declaration, ExportAllDeclaration,
    ExportDefaultDeclaration, ExportDefaultDeclarationKind, ExportNamedDeclaration, Statement,
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
            Statement::ExportDefaultDeclaration(export) => collect_default(export, &mut surface),
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
            kind: SourcePublicSymbolKind::CompilerDefined,
            exposed_identifier: byte_range(exposed),
            compiler_anchor: byte_range(exposed),
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
        Declaration::TSInterfaceDeclaration(declaration) => push_definition(
            declarations,
            declaration.id.name.as_str(),
            declaration.id.span,
            SourcePublicSymbolKind::Type,
        ),
        Declaration::TSEnumDeclaration(declaration) => push_definition(
            declarations,
            declaration.id.name.as_str(),
            declaration.id.span,
            SourcePublicSymbolKind::Type,
        ),
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

fn collect_default(export: &ExportDefaultDeclaration<'_>, surface: &mut SourcePublicSurface) {
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
        kind,
        exposed_identifier: exposed,
        compiler_anchor: anchor,
        binding,
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
            string_content_range(export.source.span, source)?,
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
        kind,
        exposed_identifier: identifier,
        compiler_anchor: identifier,
        binding: SourcePublicBindingKind::Definition,
        source_module: None,
    });
}

fn string_content_range(span: Span, source: &str) -> Result<SourceByteRange, String> {
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
    Ok(SourceByteRange {
        start: range.start + 1,
        end: range.end - 1,
    })
}

fn byte_range(span: Span) -> SourceByteRange {
    SourceByteRange {
        start: span.start as usize,
        end: span.end as usize,
    }
}
