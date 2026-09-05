use super::{
    GatedDeclaration, SourceByteRange, SourcePublicNamespace, SourcePublicSymbolKind, Token,
    byte_range, contains, decorator_final_name, is_public_member_name, push_definition,
};
use rustpython_ast::{Arguments, Expr, Stmt, text_size::TextRange};

pub(super) fn collect_method_fields(
    owner: &str,
    arguments: &Arguments,
    decorators: &[Expr],
    body: &[Stmt],
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    let namespace = if decorators
        .iter()
        .any(|decorator| decorator_final_name(decorator) == Some("staticmethod"))
    {
        return Ok(());
    } else if decorators
        .iter()
        .any(|decorator| decorator_final_name(decorator) == Some("classmethod"))
    {
        SourcePublicNamespace::StaticMember
    } else {
        SourcePublicNamespace::InstanceMember
    };
    let Some(receiver) = arguments
        .posonlyargs
        .first()
        .or_else(|| arguments.args.first())
        .map(|argument| argument.def.arg.as_str())
    else {
        return Ok(());
    };
    collect_receiver_fields(owner, receiver, namespace, body, tokens, declarations)
}

pub(super) fn annotation_is_class_var(annotation: &Expr) -> bool {
    match annotation {
        Expr::Subscript(subscript) => decorator_final_name(&subscript.value) == Some("ClassVar"),
        _ => decorator_final_name(annotation) == Some("ClassVar"),
    }
}

fn collect_receiver_fields(
    owner: &str,
    receiver: &str,
    namespace: SourcePublicNamespace,
    body: &[Stmt],
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    for statement in body {
        match statement {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_receiver_target(
                        owner,
                        receiver,
                        namespace,
                        target,
                        tokens,
                        declarations,
                    )?;
                }
            }
            Stmt::AnnAssign(assign) => collect_receiver_target(
                owner,
                receiver,
                namespace,
                &assign.target,
                tokens,
                declarations,
            )?,
            Stmt::For(node) => {
                collect_receiver_target(
                    owner,
                    receiver,
                    namespace,
                    &node.target,
                    tokens,
                    declarations,
                )?;
                collect_receiver_fields(
                    owner,
                    receiver,
                    namespace,
                    &node.body,
                    tokens,
                    declarations,
                )?;
                collect_receiver_fields(
                    owner,
                    receiver,
                    namespace,
                    &node.orelse,
                    tokens,
                    declarations,
                )?;
            }
            Stmt::AsyncFor(node) => {
                collect_receiver_target(
                    owner,
                    receiver,
                    namespace,
                    &node.target,
                    tokens,
                    declarations,
                )?;
                collect_receiver_fields(
                    owner,
                    receiver,
                    namespace,
                    &node.body,
                    tokens,
                    declarations,
                )?;
                collect_receiver_fields(
                    owner,
                    receiver,
                    namespace,
                    &node.orelse,
                    tokens,
                    declarations,
                )?;
            }
            Stmt::If(node) => collect_two_bodies(
                owner,
                receiver,
                namespace,
                &node.body,
                &node.orelse,
                tokens,
                declarations,
            )?,
            Stmt::While(node) => collect_two_bodies(
                owner,
                receiver,
                namespace,
                &node.body,
                &node.orelse,
                tokens,
                declarations,
            )?,
            Stmt::With(node) => {
                collect_with_targets(
                    owner,
                    receiver,
                    namespace,
                    &node.items,
                    tokens,
                    declarations,
                )?;
                collect_receiver_fields(
                    owner,
                    receiver,
                    namespace,
                    &node.body,
                    tokens,
                    declarations,
                )?;
            }
            Stmt::AsyncWith(node) => {
                collect_with_targets(
                    owner,
                    receiver,
                    namespace,
                    &node.items,
                    tokens,
                    declarations,
                )?;
                collect_receiver_fields(
                    owner,
                    receiver,
                    namespace,
                    &node.body,
                    tokens,
                    declarations,
                )?;
            }
            Stmt::Try(node) => {
                collect_try_bodies(
                    owner,
                    receiver,
                    namespace,
                    &node.body,
                    &node.handlers,
                    &node.orelse,
                    &node.finalbody,
                    tokens,
                    declarations,
                )?;
            }
            Stmt::TryStar(node) => {
                collect_try_bodies(
                    owner,
                    receiver,
                    namespace,
                    &node.body,
                    &node.handlers,
                    &node.orelse,
                    &node.finalbody,
                    tokens,
                    declarations,
                )?;
            }
            Stmt::Match(node) => {
                for case in &node.cases {
                    collect_receiver_fields(
                        owner,
                        receiver,
                        namespace,
                        &case.body,
                        tokens,
                        declarations,
                    )?;
                }
            }
            Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_) | Stmt::ClassDef(_) => {}
            _ => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_two_bodies(
    owner: &str,
    receiver: &str,
    namespace: SourcePublicNamespace,
    first: &[Stmt],
    second: &[Stmt],
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    collect_receiver_fields(owner, receiver, namespace, first, tokens, declarations)?;
    collect_receiver_fields(owner, receiver, namespace, second, tokens, declarations)
}

fn collect_with_targets(
    owner: &str,
    receiver: &str,
    namespace: SourcePublicNamespace,
    items: &[rustpython_ast::WithItem],
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    for target in items
        .iter()
        .filter_map(|item| item.optional_vars.as_deref())
    {
        collect_receiver_target(owner, receiver, namespace, target, tokens, declarations)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_try_bodies(
    owner: &str,
    receiver: &str,
    namespace: SourcePublicNamespace,
    body: &[Stmt],
    handlers: &[rustpython_ast::ExceptHandler],
    orelse: &[Stmt],
    finalbody: &[Stmt],
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    collect_receiver_fields(owner, receiver, namespace, body, tokens, declarations)?;
    for handler in handlers {
        let rustpython_ast::ExceptHandler::ExceptHandler(handler) = handler;
        collect_receiver_fields(
            owner,
            receiver,
            namespace,
            &handler.body,
            tokens,
            declarations,
        )?;
    }
    collect_receiver_fields(owner, receiver, namespace, orelse, tokens, declarations)?;
    collect_receiver_fields(owner, receiver, namespace, finalbody, tokens, declarations)
}

fn collect_receiver_target(
    owner: &str,
    receiver: &str,
    namespace: SourcePublicNamespace,
    target: &Expr,
    tokens: &[Token],
    declarations: &mut Vec<GatedDeclaration>,
) -> Result<(), String> {
    match target {
        Expr::Attribute(attribute)
            if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == receiver)
                && is_public_member_name(attribute.attr.as_str()) =>
        {
            let range = attribute_name_range(tokens, attribute.range, attribute.attr.as_str())?;
            push_definition(
                declarations,
                owner,
                attribute.attr.as_str(),
                Some(owner),
                namespace,
                SourcePublicSymbolKind::Field,
                range,
            );
            Ok(())
        }
        Expr::Tuple(tuple) => {
            for target in &tuple.elts {
                collect_receiver_target(owner, receiver, namespace, target, tokens, declarations)?;
            }
            Ok(())
        }
        Expr::List(list) => {
            for target in &list.elts {
                collect_receiver_target(owner, receiver, namespace, target, tokens, declarations)?;
            }
            Ok(())
        }
        Expr::Starred(starred) => collect_receiver_target(
            owner,
            receiver,
            namespace,
            &starred.value,
            tokens,
            declarations,
        ),
        _ => Ok(()),
    }
}

fn attribute_name_range(
    tokens: &[Token],
    range: TextRange,
    expected: &str,
) -> Result<SourceByteRange, String> {
    tokens
        .iter()
        .filter(|token| contains(byte_range(range), token.range))
        .filter_map(|token| match &token.kind {
            rustpython_parser::Tok::Name { name } if name == expected => Some(token.range),
            _ => None,
        })
        .next_back()
        .ok_or_else(|| format!("Python receiver field has no exact identifier for {expected}"))
}
