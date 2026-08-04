use super::ResolveContext;
use crate::types::ResolvedSymbol;

fn resolve_go_qualified_reference(
    ctx: &ResolveContext<'_>,
    reference_name: &str,
) -> Option<ResolvedSymbol> {
    let (qualifier, member) = reference_name.rsplit_once('.')?;
    let qualifier = qualifier.trim();
    let member = member.trim();
    if qualifier.is_empty() || member.is_empty() {
        return None;
    }

    let resolved_path = super::resolve_module_path(ctx, qualifier)?;
    Some(ResolvedSymbol::External {
        file_path: resolved_path,
        symbol_name: member.to_string(),
        definition_id: None,
    })
}

fn resolve_rust_qualified_reference_name(
    ctx: &ResolveContext<'_>,
    reference_name: &str,
) -> Option<ResolvedSymbol> {
    let (module_path, symbol_name) = reference_name.rsplit_once("::")?;
    let module_path = module_path.trim();
    let symbol_name = symbol_name.trim();
    if module_path.is_empty() || symbol_name.is_empty() {
        return None;
    }

    let resolved_path = super::resolve_module_path(ctx, module_path)?;
    Some(ResolvedSymbol::External {
        file_path: resolved_path,
        symbol_name: symbol_name.to_string(),
        definition_id: None,
    })
}

pub(crate) fn resolve_qualified_reference(
    ctx: &ResolveContext<'_>,
    reference_name: &str,
) -> Option<ResolvedSymbol> {
    match ctx.language {
        "go" => resolve_go_qualified_reference(ctx, reference_name),
        "rust" => resolve_rust_qualified_reference_name(ctx, reference_name),
        _ => None,
    }
}
