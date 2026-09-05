use super::{
    SourceByteRange, SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicNamespace,
    SourcePublicReexport, SourcePublicReexportKind, SourcePublicSurface, SourcePublicSymbolKind,
};
use rustpython_ast::{Expr, Stmt, text_size::TextRange};
use rustpython_parser::{Mode, Tok, lexer};
use std::collections::{BTreeMap, BTreeSet};

#[path = "source_public_surface_python_exports.rs"]
mod exports;
#[path = "source_public_surface_python_members.rs"]
mod members;
#[path = "source_public_surface_python_variants.rs"]
mod variants;

#[derive(Debug)]
struct Token {
    kind: Tok,
    range: SourceByteRange,
}

#[derive(Debug)]
struct GatedDeclaration {
    gate: String,
    default_public: bool,
    declaration: SourcePublicDeclaration,
}

#[derive(Debug)]
struct GatedReexport {
    gate: String,
    default_public: bool,
    reexport: SourcePublicReexport,
}

pub(super) fn census(file_path: &str, source: &[u8]) -> Result<SourcePublicSurface, String> {
    let source = std::str::from_utf8(source)
        .map_err(|error| format!("Python source is not UTF-8 in {file_path}: {error}"))?;
    let parsed = rustpython_parser::parse(source, Mode::Module, file_path).map_err(|error| {
        format!("failed to parse Python public surface for {file_path}: {error}")
    })?;
    let rustpython_ast::Mod::Module(module) = parsed else {
        return Err(format!(
            "Python parser did not produce a module for {file_path}"
        ));
    };
    let tokens = lexer::lex(source, Mode::Module)
        .map(|token| {
            let (kind, range) = token.map_err(|error| {
                format!("failed to lex Python public surface for {file_path}: {error:?}")
            })?;
            Ok(Token {
                kind,
                range: byte_range(range),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let explicit = exports::explicit_exports(&module.body)?;
    variants::reject_unrepresented_public_variants(file_path, &module.body, explicit.as_ref())?;
    let mut declarations = Vec::new();
    let mut reexports = Vec::new();
    let mut wildcards = Vec::new();
    for statement in &module.body {
        collect_module_statement(
            statement,
            &tokens,
            explicit.as_ref(),
            &mut declarations,
            &mut reexports,
            &mut wildcards,
        )?;
    }

    let mut surface = SourcePublicSurface {
        declarations: declarations
            .into_iter()
            .filter(|candidate| {
                explicit.as_ref().map_or_else(
                    || candidate.default_public && is_public_module_name(&candidate.gate),
                    |names| names.contains(&candidate.gate),
                )
            })
            .map(|candidate| candidate.declaration)
            .collect(),
        reexports: reexports
            .into_iter()
            .filter(|candidate| {
                explicit.as_ref().map_or(candidate.default_public, |names| {
                    names.contains(&candidate.gate)
                })
            })
            .map(|candidate| candidate.reexport)
            .collect(),
    };

    if let Some(names) = explicit {
        let bound = surface
            .declarations
            .iter()
            .map(|declaration| declaration.name.clone())
            .chain(
                surface
                    .reexports
                    .iter()
                    .filter_map(|reexport| reexport.name.clone()),
            )
            .collect::<BTreeSet<_>>();
        for name in names.iter().filter(|name| !bound.contains(*name)) {
            if wildcards.is_empty() {
                return Err(format!(
                    "Python __all__ exposes {name:?}, but no exact declaration or wildcard source provides it in {file_path}"
                ));
            }
            for wildcard in &wildcards {
                let mut selective = wildcard.clone();
                selective.name = Some(name.clone());
                surface.reexports.push(selective);
            }
        }
    } else {
        surface.reexports.extend(wildcards);
    }
    normalize_redefinitions(&mut surface.declarations)?;
    Ok(surface)
}

fn normalize_redefinitions(declarations: &mut [SourcePublicDeclaration]) -> Result<(), String> {
    let mut definitions = BTreeMap::new();
    declarations.sort_by_key(|declaration| declaration.compiler_anchor.start);
    for declaration in declarations
        .iter_mut()
        .filter(|declaration| declaration.binding == SourcePublicBindingKind::Definition)
    {
        let key = (declaration.owner.clone(), declaration.name.clone());
        if let Some((namespace, kind)) = definitions.get(&key) {
            if *namespace != declaration.namespace || *kind != declaration.kind {
                return Err(format!(
                    "Python public name {:?} is redefined with incompatible compiler symbol kinds",
                    declaration.name
                ));
            }
            declaration.binding = SourcePublicBindingKind::Reference;
        } else {
            definitions.insert(key, (declaration.namespace, declaration.kind));
        }
    }
    Ok(())
}

fn collect_module_statement(
    statement: &Stmt,
    tokens: &[Token],
    explicit: Option<&BTreeSet<String>>,
    declarations: &mut Vec<GatedDeclaration>,
    reexports: &mut Vec<GatedReexport>,
    wildcards: &mut Vec<SourcePublicReexport>,
) -> Result<(), String> {
    match statement {
        Stmt::FunctionDef(function) => collect_function(
            function.name.as_str(),
            function.range,
            &function.decorator_list,
            None,
            tokens,
            declarations,
        ),
        Stmt::AsyncFunctionDef(function) => collect_function(
            function.name.as_str(),
            function.range,
            &function.decorator_list,
            None,
            tokens,
            declarations,
        ),
        Stmt::ClassDef(class) => {
            let name = class.name.as_str();
            let name_range = definition_name(tokens, class.range, name, true)?;
            push_definition(
                declarations,
                name,
                name,
                None,
                SourcePublicNamespace::Module,
                SourcePublicSymbolKind::Type,
                name_range,
            );
            collect_class_body(name, &class.body, tokens, declarations)?;
            Ok(())
        }
        Stmt::Assign(assign) => {
            if assign.targets.iter().any(exports::is_all_name) {
                return Ok(());
            }
            for target in &assign.targets {
                collect_assignment_target(target, None, None, explicit, declarations)?;
            }
            Ok(())
        }
        Stmt::AnnAssign(assign) => {
            if exports::is_all_name(&assign.target) {
                return Ok(());
            }
            collect_assignment_target(&assign.target, None, None, explicit, declarations)
        }
        Stmt::TypeAlias(alias) => collect_typed_name(
            &alias.name,
            None,
            SourcePublicSymbolKind::Type,
            declarations,
        ),
        Stmt::ImportFrom(import) => {
            exports::collect_import_from(import, tokens, reexports, declarations, wildcards)
        }
        Stmt::Import(import) => exports::collect_import(import, tokens, reexports),
        _ => Ok(()),
    }
}

fn collect_function(
    name: &str,
    range: TextRange,
    decorators: &[Expr],
    owner: Option<&str>,
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    if owner.is_some() && !is_public_member_name(name) {
        return Ok(());
    }
    let name_range = definition_name(tokens, range, name, false)?;
    let namespace = if owner.is_some()
        && decorators.iter().any(|decorator| {
            matches!(
                decorator_final_name(decorator),
                Some("staticmethod" | "classmethod")
            )
        }) {
        SourcePublicNamespace::StaticMember
    } else if owner.is_some() {
        SourcePublicNamespace::InstanceMember
    } else {
        SourcePublicNamespace::Module
    };
    push_definition(
        declarations,
        owner.unwrap_or(name),
        name,
        owner,
        namespace,
        if owner.is_some() {
            SourcePublicSymbolKind::Method
        } else {
            SourcePublicSymbolKind::Callable
        },
        name_range,
    );
    Ok(())
}

fn collect_class_body(
    owner: &str,
    body: &[Stmt],
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    for statement in body {
        match statement {
            Stmt::FunctionDef(function) => collect_function(
                function.name.as_str(),
                function.range,
                &function.decorator_list,
                Some(owner),
                tokens,
                declarations,
            )?,
            Stmt::AsyncFunctionDef(function) => collect_function(
                function.name.as_str(),
                function.range,
                &function.decorator_list,
                Some(owner),
                tokens,
                declarations,
            )?,
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_assignment_target(
                        target,
                        Some(owner),
                        Some(SourcePublicNamespace::StaticMember),
                        None,
                        declarations,
                    )?;
                }
            }
            Stmt::AnnAssign(assign) => {
                let namespace = if members::annotation_is_class_var(&assign.annotation) {
                    SourcePublicNamespace::StaticMember
                } else {
                    SourcePublicNamespace::InstanceMember
                };
                collect_assignment_target(
                    &assign.target,
                    Some(owner),
                    Some(namespace),
                    None,
                    declarations,
                )?;
            }
            Stmt::TypeAlias(alias) => collect_typed_name(
                &alias.name,
                Some(owner),
                SourcePublicSymbolKind::Type,
                declarations,
            )?,
            Stmt::ClassDef(class) if is_public_member_name(class.name.as_str()) => {
                let range = definition_name(tokens, class.range, class.name.as_str(), true)?;
                push_definition(
                    declarations,
                    owner,
                    class.name.as_str(),
                    Some(owner),
                    SourcePublicNamespace::StaticMember,
                    SourcePublicSymbolKind::Type,
                    range,
                );
            }
            _ => {}
        }
        match statement {
            Stmt::FunctionDef(function) => members::collect_method_fields(
                owner,
                &function.args,
                &function.decorator_list,
                &function.body,
                tokens,
                declarations,
            )?,
            Stmt::AsyncFunctionDef(function) => members::collect_method_fields(
                owner,
                &function.args,
                &function.decorator_list,
                &function.body,
                tokens,
                declarations,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn collect_assignment_target(
    target: &Expr,
    owner: Option<&str>,
    member_namespace: Option<SourcePublicNamespace>,
    explicit: Option<&BTreeSet<String>>,
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    match target {
        Expr::Name(name) => {
            let identifier = name.id.as_str();
            if identifier == "__all__" || owner.is_some_and(|_| !is_public_member_name(identifier))
            {
                return Ok(());
            }
            push_definition(
                declarations,
                owner.unwrap_or(identifier),
                identifier,
                owner,
                member_namespace.unwrap_or(SourcePublicNamespace::Module),
                if owner.is_some() {
                    SourcePublicSymbolKind::Field
                } else {
                    SourcePublicSymbolKind::Variable
                },
                byte_range(name.range),
            );
            Ok(())
        }
        Expr::Tuple(tuple) => reject_public_destructuring(&tuple.elts, owner, explicit),
        Expr::List(list) => reject_public_destructuring(&list.elts, owner, explicit),
        _ => Ok(()),
    }
}

fn reject_public_destructuring(
    elements: &[Expr],
    owner: Option<&str>,
    explicit: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    let mut names = Vec::new();
    collect_bound_names(elements, &mut names);
    if names.iter().any(|name| {
        owner.map_or_else(
            || explicit.map_or_else(|| is_public_module_name(name), |all| all.contains(name)),
            |_| is_public_member_name(name),
        )
    }) {
        return Err(
            "Python public destructuring has no dedicated compiler API signature; refusing incomplete coverage"
                .to_string(),
        );
    }
    Ok(())
}

fn collect_bound_names(expressions: &[Expr], names: &mut Vec<String>) {
    for expression in expressions {
        match expression {
            Expr::Name(name) => names.push(name.id.to_string()),
            Expr::Tuple(tuple) => collect_bound_names(&tuple.elts, names),
            Expr::List(list) => collect_bound_names(&list.elts, names),
            Expr::Starred(starred) => {
                collect_bound_names(std::slice::from_ref(&starred.value), names)
            }
            _ => {}
        }
    }
}

fn collect_typed_name(
    target: &Expr,
    owner: Option<&str>,
    kind: SourcePublicSymbolKind,
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    let Expr::Name(name) = target else {
        return Err("Python public type alias has no exact identifier".to_string());
    };
    if owner.is_some_and(|_| !is_public_member_name(name.id.as_str())) {
        return Ok(());
    }
    push_definition(
        declarations,
        owner.unwrap_or(name.id.as_str()),
        name.id.as_str(),
        owner,
        if owner.is_some() {
            SourcePublicNamespace::StaticMember
        } else {
            SourcePublicNamespace::Module
        },
        kind,
        byte_range(name.range),
    );
    Ok(())
}

fn decorator_final_name(expression: &Expr) -> Option<&str> {
    match expression {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        Expr::Call(call) => decorator_final_name(&call.func),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_definition(
    declarations: &mut Vec<GatedDeclaration>,
    gate: &str,
    name: &str,
    owner: Option<&str>,
    namespace: SourcePublicNamespace,
    kind: SourcePublicSymbolKind,
    range: SourceByteRange,
) {
    declarations.push(GatedDeclaration {
        gate: gate.to_string(),
        default_public: true,
        declaration: SourcePublicDeclaration {
            name: name.to_string(),
            target_name: name.to_string(),
            owner: owner.map(str::to_string),
            namespace,
            kind,
            exposed_identifier: range,
            compiler_anchor: range,
            owner_compiler_anchor: None,
            binding: SourcePublicBindingKind::Definition,
            source_module: None,
        },
    });
}

fn definition_name(
    tokens: &[Token],
    range: TextRange,
    expected: &str,
    class: bool,
) -> Result<SourceByteRange, String> {
    let statement = byte_range(range);
    let mut saw_keyword = false;
    for token in tokens
        .iter()
        .filter(|token| contains(statement, token.range))
    {
        if matches!((&token.kind, class), (Tok::Class, true) | (Tok::Def, false)) {
            saw_keyword = true;
            continue;
        }
        if saw_keyword && matches!(&token.kind, Tok::Name { name } if name == expected) {
            return Ok(token.range);
        }
    }
    Err(format!(
        "Python definition has no exact identifier for {expected}"
    ))
}

fn contains(outer: SourceByteRange, inner: SourceByteRange) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn byte_range(range: TextRange) -> SourceByteRange {
    SourceByteRange {
        start: u32::from(range.start()) as usize,
        end: u32::from(range.end()) as usize,
    }
}

fn is_public_module_name(name: &str) -> bool {
    !name.starts_with('_')
}

fn is_public_member_name(name: &str) -> bool {
    !name.starts_with('_') || (name.len() > 4 && name.starts_with("__") && name.ends_with("__"))
}
