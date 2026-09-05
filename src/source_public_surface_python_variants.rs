use super::is_public_module_name;
use rustpython_ast::{Expr, Pattern, Stmt};
use std::collections::BTreeSet;

pub(super) fn reject_unrepresented_public_variants(
    file_path: &str,
    body: &[Stmt],
    explicit: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    for statement in body {
        if let Stmt::Delete(delete) = statement
            && delete
                .targets
                .iter()
                .any(|target| target_binds_public(target, explicit))
        {
            return Err(format!(
                "Python public deletion is not representable in the current variant ledger: {file_path}"
            ));
        }
        if is_compound(statement) && statement_binds_public(statement, explicit) {
            return Err(format!(
                "Python conditional public surface requires an explicit build/runtime variant: {file_path}"
            ));
        }
    }
    Ok(())
}

fn is_compound(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::For(_)
            | Stmt::AsyncFor(_)
            | Stmt::While(_)
            | Stmt::If(_)
            | Stmt::With(_)
            | Stmt::AsyncWith(_)
            | Stmt::Match(_)
            | Stmt::Try(_)
            | Stmt::TryStar(_)
    )
}

fn statement_binds_public(statement: &Stmt, explicit: Option<&BTreeSet<String>>) -> bool {
    match statement {
        Stmt::FunctionDef(function) => name_is_public(function.name.as_str(), explicit),
        Stmt::AsyncFunctionDef(function) => name_is_public(function.name.as_str(), explicit),
        Stmt::ClassDef(class) => name_is_public(class.name.as_str(), explicit),
        Stmt::Assign(assign) => assign
            .targets
            .iter()
            .any(|target| target_binds_public(target, explicit)),
        Stmt::AnnAssign(assign) => target_binds_public(&assign.target, explicit),
        Stmt::TypeAlias(alias) => target_binds_public(&alias.name, explicit),
        Stmt::Delete(delete) => delete
            .targets
            .iter()
            .any(|target| target_binds_public(target, explicit)),
        Stmt::Import(import) => import.names.iter().any(|alias| {
            let local = alias.asname.as_ref().map_or_else(
                || alias.name.as_str().split('.').next().unwrap_or(""),
                |name| name.as_str(),
            );
            let explicit_alias = alias
                .asname
                .as_ref()
                .is_some_and(|name| name.as_str() == alias.name.as_str());
            explicit.map_or(explicit_alias, |names| names.contains(local))
        }),
        Stmt::ImportFrom(import) => import.names.iter().any(|alias| {
            if alias.name.as_str() == "*" {
                return true;
            }
            let local = alias.asname.as_ref().unwrap_or(&alias.name).as_str();
            let explicit_alias = alias
                .asname
                .as_ref()
                .is_some_and(|name| name.as_str() == alias.name.as_str());
            explicit.map_or(explicit_alias, |names| names.contains(local))
        }),
        Stmt::For(node) => {
            target_binds_public(&node.target, explicit)
                || statements_bind_public(&node.body, explicit)
                || statements_bind_public(&node.orelse, explicit)
        }
        Stmt::AsyncFor(node) => {
            target_binds_public(&node.target, explicit)
                || statements_bind_public(&node.body, explicit)
                || statements_bind_public(&node.orelse, explicit)
        }
        Stmt::While(node) => {
            statements_bind_public(&node.body, explicit)
                || statements_bind_public(&node.orelse, explicit)
        }
        Stmt::If(node) => {
            statements_bind_public(&node.body, explicit)
                || statements_bind_public(&node.orelse, explicit)
        }
        Stmt::With(node) => {
            node.items.iter().any(|item| {
                item.optional_vars
                    .as_deref()
                    .is_some_and(|target| target_binds_public(target, explicit))
            }) || statements_bind_public(&node.body, explicit)
        }
        Stmt::AsyncWith(node) => {
            node.items.iter().any(|item| {
                item.optional_vars
                    .as_deref()
                    .is_some_and(|target| target_binds_public(target, explicit))
            }) || statements_bind_public(&node.body, explicit)
        }
        Stmt::Match(node) => node.cases.iter().any(|case| {
            pattern_binds_public(&case.pattern, explicit)
                || statements_bind_public(&case.body, explicit)
        }),
        Stmt::Try(node) => {
            statements_bind_public(&node.body, explicit)
                || node.handlers.iter().any(|handler| {
                    let rustpython_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    statements_bind_public(&handler.body, explicit)
                })
                || statements_bind_public(&node.orelse, explicit)
                || statements_bind_public(&node.finalbody, explicit)
        }
        Stmt::TryStar(node) => {
            statements_bind_public(&node.body, explicit)
                || node.handlers.iter().any(|handler| {
                    let rustpython_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    statements_bind_public(&handler.body, explicit)
                })
                || statements_bind_public(&node.orelse, explicit)
                || statements_bind_public(&node.finalbody, explicit)
        }
        _ => false,
    }
}

fn statements_bind_public(body: &[Stmt], explicit: Option<&BTreeSet<String>>) -> bool {
    body.iter()
        .any(|statement| statement_binds_public(statement, explicit))
}

fn target_binds_public(target: &Expr, explicit: Option<&BTreeSet<String>>) -> bool {
    match target {
        Expr::Name(name) => name_is_public(name.id.as_str(), explicit),
        Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .any(|target| target_binds_public(target, explicit)),
        Expr::List(list) => list
            .elts
            .iter()
            .any(|target| target_binds_public(target, explicit)),
        Expr::Starred(starred) => target_binds_public(&starred.value, explicit),
        _ => false,
    }
}

fn pattern_binds_public(pattern: &Pattern, explicit: Option<&BTreeSet<String>>) -> bool {
    match pattern {
        Pattern::MatchSequence(sequence) => sequence
            .patterns
            .iter()
            .any(|pattern| pattern_binds_public(pattern, explicit)),
        Pattern::MatchMapping(mapping) => {
            mapping
                .rest
                .as_ref()
                .is_some_and(|name| name_is_public(name.as_str(), explicit))
                || mapping
                    .patterns
                    .iter()
                    .any(|pattern| pattern_binds_public(pattern, explicit))
        }
        Pattern::MatchClass(class) => class
            .patterns
            .iter()
            .chain(&class.kwd_patterns)
            .any(|pattern| pattern_binds_public(pattern, explicit)),
        Pattern::MatchStar(star) => star
            .name
            .as_ref()
            .is_some_and(|name| name_is_public(name.as_str(), explicit)),
        Pattern::MatchAs(as_pattern) => {
            as_pattern
                .name
                .as_ref()
                .is_some_and(|name| name_is_public(name.as_str(), explicit))
                || as_pattern
                    .pattern
                    .as_deref()
                    .is_some_and(|pattern| pattern_binds_public(pattern, explicit))
        }
        Pattern::MatchOr(or_pattern) => or_pattern
            .patterns
            .iter()
            .any(|pattern| pattern_binds_public(pattern, explicit)),
        Pattern::MatchValue(_) | Pattern::MatchSingleton(_) => false,
    }
}

fn name_is_public(name: &str, explicit: Option<&BTreeSet<String>>) -> bool {
    name == "__all__"
        || explicit.map_or_else(|| is_public_module_name(name), |names| names.contains(name))
}
