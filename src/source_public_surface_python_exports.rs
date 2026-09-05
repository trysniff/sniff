use super::{
    GatedDeclaration, GatedReexport, SourceByteRange, SourcePublicBindingKind,
    SourcePublicDeclaration, SourcePublicNamespace, SourcePublicReexport, SourcePublicReexportKind,
    SourcePublicSymbolKind, Token, byte_range, contains,
};
use rustpython_ast::{Alias, Constant, Expr, Operator, Stmt, text_size::TextRange};
use std::collections::BTreeSet;

pub(super) fn collect_import_from(
    import: &rustpython_ast::StmtImportFrom,
    tokens: &[Token],
    reexports: &mut Vec<GatedReexport>,
    declarations: &mut Vec<GatedDeclaration>,
    wildcards: &mut Vec<SourcePublicReexport>,
) -> Result<(), String> {
    let source_module = import_source_module(import);
    let module_anchor = import_from_module_range(tokens, import.range)?;
    let directive = byte_range(import.range);
    for alias in &import.names {
        if alias.name.as_str() == "*" {
            wildcards.push(SourcePublicReexport {
                kind: SourcePublicReexportKind::Wildcard,
                name: None,
                source_module: source_module.clone(),
                directive,
                exposed_identifier: None,
                compiler_anchor: module_anchor,
            });
            continue;
        }
        let local = alias.asname.as_ref().unwrap_or(&alias.name).as_str();
        let exposed = alias_exposed_range(tokens, alias, local)?;
        let explicit_alias = alias
            .asname
            .as_ref()
            .is_some_and(|asname| asname.as_str() == alias.name.as_str());
        if import.module.is_none() {
            reexports.push(GatedReexport {
                gate: local.to_string(),
                default_public: explicit_alias,
                reexport: SourcePublicReexport {
                    kind: SourcePublicReexportKind::Namespace,
                    name: Some(local.to_string()),
                    source_module: format!("{source_module}{}", alias.name),
                    directive,
                    exposed_identifier: Some(exposed),
                    compiler_anchor: byte_range(alias.range),
                },
            });
        } else {
            declarations.push(GatedDeclaration {
                gate: local.to_string(),
                default_public: explicit_alias,
                declaration: SourcePublicDeclaration {
                    name: local.to_string(),
                    target_name: alias.name.to_string(),
                    owner: None,
                    namespace: SourcePublicNamespace::Module,
                    kind: SourcePublicSymbolKind::CompilerDefined,
                    exposed_identifier: exposed,
                    compiler_anchor: byte_range(alias.range),
                    binding: SourcePublicBindingKind::Reference,
                    source_module: Some(source_module.clone()),
                },
            });
        }
    }
    Ok(())
}

pub(super) fn collect_import(
    import: &rustpython_ast::StmtImport,
    tokens: &[Token],
    reexports: &mut Vec<GatedReexport>,
) -> Result<(), String> {
    let directive = byte_range(import.range);
    for alias in &import.names {
        let local = alias.asname.as_ref().map_or_else(
            || alias.name.as_str().split('.').next().unwrap_or(""),
            |name| name.as_str(),
        );
        let exposed = alias_exposed_range(tokens, alias, local)?;
        let explicit_alias = alias
            .asname
            .as_ref()
            .is_some_and(|asname| asname.as_str() == alias.name.as_str());
        reexports.push(GatedReexport {
            gate: local.to_string(),
            default_public: explicit_alias,
            reexport: SourcePublicReexport {
                kind: SourcePublicReexportKind::Namespace,
                name: Some(local.to_string()),
                source_module: alias.name.to_string(),
                directive,
                exposed_identifier: Some(exposed),
                compiler_anchor: import_alias_module_range(tokens, alias)?,
            },
        });
    }
    Ok(())
}

pub(super) fn explicit_exports(body: &[Stmt]) -> Result<Option<BTreeSet<String>>, String> {
    let mut explicit = None::<BTreeSet<String>>;
    for statement in body {
        match statement {
            Stmt::Assign(assign) if assign.targets.iter().any(is_all_name) => {
                explicit = Some(static_export_names(&assign.value).ok_or_else(|| {
                    "Python __all__ assignment is dynamic; refusing incomplete public coverage"
                        .to_string()
                })?);
            }
            Stmt::AnnAssign(assign) if is_all_name(&assign.target) => {
                if let Some(value) = assign.value.as_deref() {
                    explicit = Some(static_export_names(value).ok_or_else(|| {
                        "Python __all__ assignment is dynamic; refusing incomplete public coverage"
                            .to_string()
                    })?);
                }
            }
            Stmt::AugAssign(assign)
                if is_all_name(&assign.target) && assign.op == Operator::Add =>
            {
                let additions = static_export_names(&assign.value).ok_or_else(|| {
                    "Python __all__ extension is dynamic; refusing incomplete public coverage"
                        .to_string()
                })?;
                explicit
                    .as_mut()
                    .ok_or_else(|| {
                        "Python __all__ is extended before a static assignment".to_string()
                    })?
                    .extend(additions);
            }
            Stmt::AugAssign(assign) if is_all_name(&assign.target) => {
                return Err("Python __all__ uses an unsupported mutation".to_string());
            }
            Stmt::Expr(expression) if mutates_all(&expression.value) => {
                return Err(
                    "Python __all__ is mutated dynamically; refusing incomplete public coverage"
                        .to_string(),
                );
            }
            Stmt::Delete(delete) if delete.targets.iter().any(is_all_name) => {
                return Err(
                    "Python __all__ is deleted; refusing incomplete public coverage".to_string(),
                );
            }
            _ => {}
        }
    }
    Ok(explicit)
}

pub(super) fn is_all_name(expression: &Expr) -> bool {
    matches!(expression, Expr::Name(name) if name.id.as_str() == "__all__")
}

fn static_export_names(expression: &Expr) -> Option<BTreeSet<String>> {
    let elements = match expression {
        Expr::List(list) => &list.elts,
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::BinOp(binary) if binary.op == Operator::Add => {
            let mut names = static_export_names(&binary.left)?;
            names.extend(static_export_names(&binary.right)?);
            return Some(names);
        }
        _ => return None,
    };
    elements
        .iter()
        .map(|element| match element {
            Expr::Constant(value) => match &value.value {
                Constant::Str(name) => Some(name.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn mutates_all(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Call(call)
            if matches!(call.func.as_ref(), Expr::Attribute(attribute) if is_all_name(&attribute.value))
    )
}

fn alias_exposed_range(
    tokens: &[Token],
    alias: &Alias,
    expected: &str,
) -> Result<SourceByteRange, String> {
    tokens
        .iter()
        .filter(|token| contains(byte_range(alias.range), token.range))
        .filter_map(|token| match &token.kind {
            rustpython_parser::Tok::Name { name } if name == expected => Some(token.range),
            _ => None,
        })
        .next_back()
        .ok_or_else(|| {
            format!("Python import alias has no exact exposed identifier for {expected}")
        })
}

fn import_alias_module_range(tokens: &[Token], alias: &Alias) -> Result<SourceByteRange, String> {
    let mut names = tokens
        .iter()
        .filter(|token| contains(byte_range(alias.range), token.range))
        .take_while(|token| !matches!(token.kind, rustpython_parser::Tok::As))
        .filter(|token| {
            matches!(
                token.kind,
                rustpython_parser::Tok::Name { .. } | rustpython_parser::Tok::Dot
            )
        });
    let first = names
        .next()
        .ok_or_else(|| "Python import has no exact module start".to_string())?;
    let mut end = first.range.end;
    for token in names {
        end = token.range.end;
    }
    Ok(SourceByteRange {
        start: first.range.start,
        end,
    })
}

fn import_from_module_range(tokens: &[Token], range: TextRange) -> Result<SourceByteRange, String> {
    let statement = byte_range(range);
    let relevant = tokens
        .iter()
        .filter(|token| contains(statement, token.range))
        .collect::<Vec<_>>();
    let from = relevant
        .iter()
        .position(|token| matches!(token.kind, rustpython_parser::Tok::From))
        .ok_or_else(|| "Python from-import has no from token".to_string())?;
    let import = relevant
        .iter()
        .enumerate()
        .skip(from + 1)
        .find(|(_, token)| matches!(token.kind, rustpython_parser::Tok::Import))
        .map(|(index, _)| index)
        .ok_or_else(|| "Python from-import has no import token".to_string())?;
    let module = &relevant[from + 1..import];
    let first = module
        .first()
        .ok_or_else(|| "Python from-import has no exact module anchor".to_string())?;
    let last = module.last().unwrap();
    Ok(SourceByteRange {
        start: first.range.start,
        end: last.range.end,
    })
}

fn import_source_module(import: &rustpython_ast::StmtImportFrom) -> String {
    let mut source = ".".repeat(import.level.as_ref().map_or(0, |level| level.to_usize()));
    if let Some(module) = &import.module {
        source.push_str(module.as_str());
    }
    source
}
