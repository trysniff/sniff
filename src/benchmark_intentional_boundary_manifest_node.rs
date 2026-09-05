use super::{ParsedManifestDeclaration, resolve_manifest_path};
use crate::benchmark::release::{
    IntentionalBoundaryManifestDeclarationKind as DeclarationKind,
    IntentionalBoundaryManifestTarget as Target,
};
use oxc_ast::ast::{Expression, ObjectExpression, ObjectProperty, ObjectPropertyKind, Statement};
use oxc_span::{GetSpan, SourceType};
use std::collections::BTreeSet;
use std::ops::Range;

const WRAPPER_PREFIX_BYTES: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::benchmark::release) enum ParsedNodePackageEntryKind {
    Exports,
    Main,
    Module,
    Types,
    Typings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::benchmark::release) struct ParsedNodePackageCondition {
    pub(in crate::benchmark::release) name: String,
    pub(in crate::benchmark::release) ordinal: usize,
    pub(in crate::benchmark::release) span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::benchmark::release) struct ParsedNodePackageExposure {
    pub(in crate::benchmark::release) entry_kind: ParsedNodePackageEntryKind,
    pub(in crate::benchmark::release) public_subpath: String,
    pub(in crate::benchmark::release) public_subpath_span: Range<usize>,
    pub(in crate::benchmark::release) conditions: Vec<ParsedNodePackageCondition>,
    pub(in crate::benchmark::release) fallback_indices: Vec<usize>,
    pub(in crate::benchmark::release) target: String,
    pub(in crate::benchmark::release) target_span: Range<usize>,
}

#[derive(Debug)]
pub(in crate::benchmark::release) struct ParsedNodePackage {
    pub(in crate::benchmark::release) package_name: Option<String>,
    pub(in crate::benchmark::release) private: bool,
    pub(in crate::benchmark::release) has_exports: bool,
    pub(in crate::benchmark::release) exposures: Vec<ParsedNodePackageExposure>,
    pub(in crate::benchmark::release) declarations: Vec<ParsedManifestDeclaration>,
}

pub(super) fn parse_package_json(
    manifest_path: &str,
    source: &str,
) -> Result<Vec<ParsedManifestDeclaration>, String> {
    Ok(parse_node_package_json(manifest_path, source)?.declarations)
}

pub(in crate::benchmark::release) fn parse_node_package_json(
    manifest_path: &str,
    source: &str,
) -> Result<ParsedNodePackage, String> {
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

    let package_name = find_property(object, "name", manifest_path)?
        .map(|property| required_string(&property.value, "package name"))
        .transpose()?
        .map(|(name, _)| name.to_string());
    let private = find_property(object, "private", manifest_path)?
        .map(|property| required_bool(&property.value, "package private"))
        .transpose()?
        .unwrap_or(false);
    let mut exposures = Vec::new();
    let mut declarations = Vec::new();
    if let Some(property) = find_property(object, "exports", manifest_path)? {
        collect_export_targets(
            &property.value,
            ".",
            source_span(property.key.span())?,
            &[],
            &[],
            true,
            &mut exposures,
        )?;
        for exposure in &exposures {
            declarations.push(ParsedManifestDeclaration {
                declaration_kind: DeclarationKind::PublishedModule,
                span: exposure.target_span.clone(),
                target: Target::RepositoryPath {
                    repository_path: resolve_manifest_path(manifest_path, &exposure.target)?,
                },
            });
        }
    }
    for (field, entry_kind) in [
        ("main", ParsedNodePackageEntryKind::Main),
        ("module", ParsedNodePackageEntryKind::Module),
        ("types", ParsedNodePackageEntryKind::Types),
        ("typings", ParsedNodePackageEntryKind::Typings),
    ] {
        if let Some(property) = find_property(object, field, manifest_path)? {
            let (target, span) = required_string(&property.value, &format!("package {field}"))?;
            let target_span = source_span(span)?;
            exposures.push(ParsedNodePackageExposure {
                entry_kind,
                public_subpath: ".".to_string(),
                public_subpath_span: source_span(property.key.span())?,
                conditions: Vec::new(),
                fallback_indices: Vec::new(),
                target: target.to_string(),
                target_span: target_span.clone(),
            });
            declarations.push(path_declaration(
                manifest_path,
                target,
                span,
                DeclarationKind::PublishedModule,
            )?);
        }
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
    Ok(ParsedNodePackage {
        package_name,
        private,
        has_exports: find_property(object, "exports", manifest_path)?.is_some(),
        exposures,
        declarations,
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_export_targets(
    expression: &Expression<'_>,
    public_subpath: &str,
    public_subpath_span: Range<usize>,
    conditions: &[ParsedNodePackageCondition],
    fallback_indices: &[usize],
    allow_subpaths: bool,
    exposures: &mut Vec<ParsedNodePackageExposure>,
) -> Result<(), String> {
    match expression {
        Expression::StringLiteral(value) => {
            validate_export_target(value.value.as_str())?;
            exposures.push(ParsedNodePackageExposure {
                entry_kind: ParsedNodePackageEntryKind::Exports,
                public_subpath: public_subpath.to_string(),
                public_subpath_span,
                conditions: conditions.to_vec(),
                fallback_indices: fallback_indices.to_vec(),
                target: value.value.to_string(),
                target_span: source_span(value.span)?,
            });
        }
        Expression::NullLiteral(_) => {}
        Expression::ArrayExpression(array) => {
            for (index, element) in array.elements.iter().enumerate() {
                let value = element.as_expression().ok_or_else(|| {
                    "package exports contains an array hole or spread".to_string()
                })?;
                let mut nested_fallbacks = fallback_indices.to_vec();
                nested_fallbacks.push(index);
                collect_export_targets(
                    value,
                    public_subpath,
                    public_subpath_span.clone(),
                    conditions,
                    &nested_fallbacks,
                    false,
                    exposures,
                )?;
            }
        }
        Expression::ObjectExpression(object) => {
            let properties = object_properties(object, "package exports")?;
            let has_subpaths = properties.iter().any(|property| {
                property
                    .key
                    .static_name()
                    .is_some_and(|name| name.starts_with('.'))
            });
            let has_conditions = properties.iter().any(|property| {
                property
                    .key
                    .static_name()
                    .is_some_and(|name| !name.starts_with('.'))
            });
            if has_subpaths && has_conditions {
                return Err(
                    "package exports cannot mix subpath keys and condition keys".to_string()
                );
            }
            if has_subpaths {
                if !allow_subpaths {
                    return Err("package exports contains a nested subpath map".to_string());
                }
                for property in properties {
                    let subpath = property
                        .key
                        .static_name()
                        .ok_or_else(|| "package exports contains a dynamic key".to_string())?;
                    validate_export_subpath(subpath.as_ref())?;
                    collect_export_targets(
                        &property.value,
                        subpath.as_ref(),
                        source_span(property.key.span())?,
                        conditions,
                        fallback_indices,
                        false,
                        exposures,
                    )?;
                }
            } else {
                for (ordinal, property) in properties.into_iter().enumerate() {
                    let condition = property.key.static_name().ok_or_else(|| {
                        "package exports contains a dynamic condition".to_string()
                    })?;
                    if condition.is_empty() {
                        return Err("package exports contains an empty condition".to_string());
                    }
                    let mut nested_conditions = conditions.to_vec();
                    nested_conditions.push(ParsedNodePackageCondition {
                        name: condition.to_string(),
                        ordinal,
                        span: source_span(property.key.span())?,
                    });
                    collect_export_targets(
                        &property.value,
                        public_subpath,
                        public_subpath_span.clone(),
                        &nested_conditions,
                        fallback_indices,
                        false,
                        exposures,
                    )?;
                }
            }
        }
        _ => return Err("package exports contains an unsupported target value".to_string()),
    }
    Ok(())
}

fn object_properties<'a>(
    object: &'a ObjectExpression<'a>,
    label: &str,
) -> Result<Vec<&'a ObjectProperty<'a>>, String> {
    object
        .properties
        .iter()
        .map(|property| {
            let ObjectPropertyKind::ObjectProperty(property) = property else {
                return Err(format!("{label} contains a spread property"));
            };
            Ok(&**property)
        })
        .collect()
}

fn validate_export_subpath(subpath: &str) -> Result<(), String> {
    if subpath != "." && !subpath.starts_with("./") {
        return Err(format!("package exports has an invalid subpath: {subpath}"));
    }
    if subpath == "." {
        return Ok(());
    }
    if subpath.contains('*') {
        return Err(format!(
            "package exports pattern is not yet compiler-enumerated: {subpath}"
        ));
    }
    validate_package_relative_segments(subpath.strip_prefix("./").unwrap_or(""), "subpath")
}

fn validate_export_target(target: &str) -> Result<(), String> {
    if !target.starts_with("./") {
        return Err(format!(
            "package exports target must be package-relative: {target}"
        ));
    }
    if target.contains('*') {
        return Err(format!(
            "package exports target pattern is not yet compiler-enumerated: {target}"
        ));
    }
    validate_package_relative_segments(&target[2..], "target")
}

fn validate_package_relative_segments(path: &str, label: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains('%')
        || path.contains('?')
        || path.contains('#')
        || path.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.eq_ignore_ascii_case("node_modules")
        })
    {
        return Err(format!(
            "package exports {label} is unsupported or unsafe: {path}"
        ));
    }
    Ok(())
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

fn required_bool(expression: &Expression<'_>, label: &str) -> Result<bool, String> {
    let Expression::BooleanLiteral(value) = expression else {
        return Err(format!("{label} must be a boolean"));
    };
    Ok(value.value)
}

fn source_span(span: oxc_span::Span) -> Result<Range<usize>, String> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start < WRAPPER_PREFIX_BYTES || end < WRAPPER_PREFIX_BYTES || start >= end {
        return Err("package manifest AST span escaped its wrapper".to_string());
    }
    Ok(start - WRAPPER_PREFIX_BYTES..end - WRAPPER_PREFIX_BYTES)
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
