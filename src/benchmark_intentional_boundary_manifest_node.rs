use super::{ParsedManifestDeclaration, resolve_manifest_path};
use crate::benchmark::release::{
    IntentionalBoundaryManifestDeclarationKind as DeclarationKind,
    IntentionalBoundaryManifestTarget as Target,
};
use oxc_ast::ast::{Expression, ObjectExpression, ObjectProperty, ObjectPropertyKind, Statement};
use oxc_span::SourceType;
use std::collections::BTreeSet;

const WRAPPER_PREFIX_BYTES: usize = 1;

pub(super) fn parse_package_json(
    manifest_path: &str,
    source: &str,
) -> Result<Vec<ParsedManifestDeclaration>, String> {
    let value: serde_json::Value = serde_json::from_str(source).map_err(|error| {
        format!("failed to parse intentional-boundary package manifest {manifest_path}: {error}")
    })?;
    if !value.is_object() {
        return Err(format!(
            "package manifest {manifest_path} must be a JSON object"
        ));
    }
    let wrapped = format!("({source})");
    let allocator = oxc_allocator::Allocator::default();
    let parsed = oxc_parser::Parser::new(&allocator, &wrapped, SourceType::default()).parse();
    if !parsed.errors.is_empty() {
        return Err(format!(
            "failed to parse package manifest AST {manifest_path}: {:?}",
            parsed.errors
        ));
    }
    let [Statement::ExpressionStatement(statement)] = parsed.program.body.as_slice() else {
        return Err(format!(
            "package manifest AST {manifest_path} is not one JSON expression"
        ));
    };
    let root = match &statement.expression {
        Expression::ParenthesizedExpression(value) => &value.expression,
        value => value,
    };
    let Expression::ObjectExpression(object) = root else {
        return Err(format!(
            "package manifest AST {manifest_path} is not an object"
        ));
    };
    validate_json_shape(root, manifest_path)?;

    let mut declarations = Vec::new();
    if let Some(property) = find_property(object, "exports", manifest_path)? {
        let mut targets = Vec::new();
        collect_target_strings(&property.value, "package exports", &mut targets)?;
        for (target, span) in targets {
            if !target.starts_with("./") {
                return Err(format!(
                    "package exports target must be repository-relative: {target}"
                ));
            }
            declarations.push(path_declaration(
                manifest_path,
                target,
                span,
                DeclarationKind::PublishedModule,
            )?);
        }
    }
    if let Some(property) = find_property(object, "main", manifest_path)? {
        let (target, span) = required_string(&property.value, "package main")?;
        declarations.push(path_declaration(
            manifest_path,
            target,
            span,
            DeclarationKind::PublishedModule,
        )?);
    }
    if let Some(property) = find_property(object, "bin", manifest_path)? {
        let mut targets = Vec::new();
        collect_bin_targets(&property.value, &mut targets)?;
        for (target, span) in targets {
            declarations.push(path_declaration(
                manifest_path,
                target,
                span,
                DeclarationKind::RuntimeEntrypoint,
            )?);
        }
    }
    let package_manager = find_property(object, "packageManager", manifest_path)?
        .map(|property| required_string(&property.value, "package manager"))
        .transpose()?
        .map(|(value, _)| value);
    if let Some(property) = find_property(object, "scripts", manifest_path)? {
        collect_package_scripts(&property.value, package_manager, &mut declarations)?;
    }
    Ok(declarations)
}

fn collect_package_scripts(
    expression: &Expression<'_>,
    package_manager: Option<&str>,
    declarations: &mut Vec<ParsedManifestDeclaration>,
) -> Result<(), String> {
    let Expression::ObjectExpression(scripts) = expression else {
        return Err("package scripts must be an object of strings".to_string());
    };
    for property in &scripts.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return Err("package scripts contains a spread property".to_string());
        };
        let script_name = property
            .key
            .static_name()
            .ok_or_else(|| "package scripts contains a dynamic name".to_string())?;
        let (command, span) = required_string(&property.value, "package script")?;
        let start = span.start as usize;
        let end = span.end as usize;
        if start < WRAPPER_PREFIX_BYTES || end < WRAPPER_PREFIX_BYTES {
            return Err("package script AST span escaped its wrapper".to_string());
        }
        declarations.push(ParsedManifestDeclaration {
            declaration_kind: DeclarationKind::PackageScript,
            span: start - WRAPPER_PREFIX_BYTES..end - WRAPPER_PREFIX_BYTES,
            target: Target::PackageScript {
                script_name: script_name.to_string(),
                command: command.to_string(),
                package_manager: package_manager.map(str::to_string),
            },
        });
    }
    Ok(())
}

fn validate_json_shape(expression: &Expression<'_>, manifest_path: &str) -> Result<(), String> {
    match expression {
        Expression::ObjectExpression(object) => {
            let mut names = BTreeSet::new();
            for property in &object.properties {
                let ObjectPropertyKind::ObjectProperty(property) = property else {
                    return Err(format!(
                        "package manifest {manifest_path} contains a non-JSON spread"
                    ));
                };
                let name = property.key.static_name().ok_or_else(|| {
                    format!("package manifest {manifest_path} contains a dynamic key")
                })?;
                if !names.insert(name.to_string()) {
                    return Err(format!(
                        "package manifest {manifest_path} repeats JSON key {name}"
                    ));
                }
                validate_json_shape(&property.value, manifest_path)?;
            }
        }
        Expression::ArrayExpression(array) => {
            for element in &array.elements {
                let expression = element.as_expression().ok_or_else(|| {
                    format!("package manifest {manifest_path} contains a non-JSON array element")
                })?;
                validate_json_shape(expression, manifest_path)?;
            }
        }
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => {}
        _ => {
            return Err(format!(
                "package manifest {manifest_path} contains a non-JSON expression"
            ));
        }
    }
    Ok(())
}

fn find_property<'a>(
    object: &'a ObjectExpression<'a>,
    name: &str,
    manifest_path: &str,
) -> Result<Option<&'a ObjectProperty<'a>>, String> {
    let mut found = None;
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return Err(format!(
                "package manifest {manifest_path} contains a spread property"
            ));
        };
        if property.key.static_name().is_some_and(|key| key == name)
            && found.replace(&**property).is_some()
        {
            return Err(format!(
                "package manifest {manifest_path} repeats JSON key {name}"
            ));
        }
    }
    Ok(found)
}

fn collect_target_strings<'a>(
    expression: &'a Expression<'a>,
    label: &str,
    targets: &mut Vec<(&'a str, oxc_span::Span)>,
) -> Result<(), String> {
    match expression {
        Expression::StringLiteral(value) => targets.push((value.value.as_str(), value.span)),
        Expression::NullLiteral(_) => {}
        Expression::ObjectExpression(object) => {
            for property in &object.properties {
                let ObjectPropertyKind::ObjectProperty(property) = property else {
                    return Err(format!("{label} contains a spread property"));
                };
                collect_target_strings(&property.value, label, targets)?;
            }
        }
        Expression::ArrayExpression(array) => {
            for element in &array.elements {
                let value = element
                    .as_expression()
                    .ok_or_else(|| format!("{label} contains an array hole or spread"))?;
                collect_target_strings(value, label, targets)?;
            }
        }
        _ => return Err(format!("{label} contains an unsupported target value")),
    }
    Ok(())
}

fn collect_bin_targets<'a>(
    expression: &'a Expression<'a>,
    targets: &mut Vec<(&'a str, oxc_span::Span)>,
) -> Result<(), String> {
    match expression {
        Expression::StringLiteral(value) => {
            targets.push((value.value.as_str(), value.span));
            Ok(())
        }
        Expression::ObjectExpression(object) => {
            for property in &object.properties {
                let ObjectPropertyKind::ObjectProperty(property) = property else {
                    return Err("package bin contains a spread property".to_string());
                };
                targets.push(required_string(&property.value, "package bin entry")?);
            }
            Ok(())
        }
        _ => Err("package bin must be a string or object of strings".to_string()),
    }
}

fn required_string<'a>(
    expression: &'a Expression<'a>,
    label: &str,
) -> Result<(&'a str, oxc_span::Span), String> {
    let Expression::StringLiteral(value) = expression else {
        return Err(format!("{label} must be a string"));
    };
    Ok((value.value.as_str(), value.span))
}

fn path_declaration(
    manifest_path: &str,
    target: &str,
    span: oxc_span::Span,
    declaration_kind: DeclarationKind,
) -> Result<ParsedManifestDeclaration, String> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start < WRAPPER_PREFIX_BYTES || end < WRAPPER_PREFIX_BYTES {
        return Err("package manifest AST span escaped its wrapper".to_string());
    }
    Ok(ParsedManifestDeclaration {
        declaration_kind,
        span: start - WRAPPER_PREFIX_BYTES..end - WRAPPER_PREFIX_BYTES,
        target: Target::RepositoryPath {
            repository_path: resolve_manifest_path(manifest_path, target)?,
        },
    })
}
