use super::intentional_boundary_compatibility_version::contains_explicit_version;
use rustpython_ast::{
    Constant, Expr, Stmt,
    text_size::{TextRange, TextSize},
};

pub(super) struct PythonCompatibilityContract {
    pub contract: TextRange,
    pub warnings_warn: TextRange,
    pub deprecation_warning: TextRange,
}

pub(super) fn versioned_compatibility_contract(
    source: &str,
    body: &[Stmt],
) -> Option<PythonCompatibilityContract> {
    let statement = first_executable_statement(body)?;
    let Stmt::Expr(statement) = statement else {
        return None;
    };
    let Expr::Call(call) = statement.value.as_ref() else {
        return None;
    };
    let Expr::Attribute(function) = call.func.as_ref() else {
        return None;
    };
    let Expr::Name(module) = function.value.as_ref() else {
        return None;
    };
    if module.id.as_str() != "warnings" || function.attr.as_str() != "warn" {
        return None;
    }
    if !valid_call_shape(call) {
        return None;
    }

    let message = exact_argument(call, 0, "message")?;
    let Expr::Constant(message) = message else {
        return None;
    };
    let Constant::Str(message) = &message.value else {
        return None;
    };
    if !contains_explicit_version(message) {
        return None;
    }

    let category = exact_argument(call, 1, "category")?;
    let Expr::Name(category) = category else {
        return None;
    };
    if category.id.as_str() != "DeprecationWarning" {
        return None;
    }

    let stacklevel = exact_argument(call, 2, "stacklevel")?;
    let Expr::Constant(stacklevel) = stacklevel else {
        return None;
    };
    let Constant::Int(stacklevel) = &stacklevel.value else {
        return None;
    };
    if stacklevel.to_string().parse::<u64>().ok()? < 2 {
        return None;
    }

    Some(PythonCompatibilityContract {
        contract: statement.range,
        warnings_warn: trailing_identifier_range(source, function.range, "warn")?,
        deprecation_warning: category.range,
    })
}

fn first_executable_statement(body: &[Stmt]) -> Option<&Stmt> {
    let mut statements = body.iter();
    let first = statements.next()?;
    if is_docstring(first) {
        statements.next()
    } else {
        Some(first)
    }
}

fn is_docstring(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::Expr(value)
            if matches!(value.value.as_ref(), Expr::Constant(constant) if matches!(constant.value, Constant::Str(_)))
    )
}

fn valid_call_shape(call: &rustpython_ast::ExprCall) -> bool {
    if call.args.len() > 4
        || call.keywords.iter().any(|keyword| {
            !matches!(
                keyword.arg.as_ref().map(|name| name.as_str()),
                Some("message" | "category" | "stacklevel" | "source" | "skip_file_prefixes")
            )
        })
    {
        return false;
    }
    [
        (0, "message"),
        (1, "category"),
        (2, "stacklevel"),
        (3, "source"),
    ]
    .into_iter()
    .all(|(position, name)| {
        let keyword_count = call
            .keywords
            .iter()
            .filter(|keyword| {
                keyword
                    .arg
                    .as_ref()
                    .is_some_and(|value| value.as_str() == name)
            })
            .count();
        keyword_count <= 1 && !(call.args.get(position).is_some() && keyword_count == 1)
    })
}

fn exact_argument<'a>(
    call: &'a rustpython_ast::ExprCall,
    position: usize,
    name: &str,
) -> Option<&'a Expr> {
    call.args.get(position).or_else(|| {
        call.keywords
            .iter()
            .find(|keyword| {
                keyword
                    .arg
                    .as_ref()
                    .is_some_and(|value| value.as_str() == name)
            })
            .map(|keyword| &keyword.value)
    })
}

fn trailing_identifier_range(
    source: &str,
    expression: TextRange,
    identifier: &str,
) -> Option<TextRange> {
    let end = u32::from(expression.end()) as usize;
    let start = end.checked_sub(identifier.len())?;
    (source.get(start..end)? == identifier)
        .then(|| TextRange::new(TextSize::from(start as u32), TextSize::from(end as u32)))
}
