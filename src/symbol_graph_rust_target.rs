use super::paths::{resolve_module_path, same_path};
use super::{ResolveContext, SymbolGraph};
use crate::types::ResolvedSymbol;
use std::collections::HashSet;

fn resolved_rust_target(
    default_file: &str,
    symbol_name: &str,
    resolved: ResolvedSymbol,
) -> (String, String, String) {
    match resolved {
        ResolvedSymbol::Local(_) => (
            default_file.to_string(),
            symbol_name.to_string(),
            symbol_name.to_string(),
        ),
        ResolvedSymbol::External {
            file_path,
            symbol_name,
        } => (file_path, symbol_name.clone(), symbol_name),
    }
}

impl SymbolGraph {
    fn resolve_rust_direct_target(
        &self,
        ctx: &ResolveContext<'_>,
        segments: &[&str],
        visited: &mut HashSet<String>,
    ) -> Option<(String, String, String)> {
        let symbol_name = segments[segments.len() - 1];
        let module_prefix = segments[..segments.len() - 1].join("::");
        if !module_prefix.is_empty() {
            let module_file = resolve_module_path(ctx, &module_prefix)?;
            let resolved = self.resolve_symbol_in_file(ctx, &module_file, symbol_name, visited)?;
            return Some(resolved_rust_target(&module_file, symbol_name, resolved));
        }

        let resolved =
            self.resolve_symbol_in_file(ctx, ctx.importing_file, symbol_name, visited)?;
        Some(resolved_rust_target(
            ctx.importing_file,
            symbol_name,
            resolved,
        ))
    }

    fn resolve_rust_type_base(
        &self,
        ctx: &ResolveContext<'_>,
        segments: &[&str],
    ) -> Option<(String, String)> {
        let type_name = segments[segments.len() - 2];
        let base_prefix = if segments.len() > 2 {
            segments[..segments.len() - 2].join("::")
        } else {
            String::new()
        };
        let base_file = if base_prefix.is_empty() {
            ctx.importing_file.to_string()
        } else {
            resolve_module_path(ctx, &base_prefix)?
        };
        let current_symbols = self.files.get(ctx.importing_file)?;
        let base_resolved = if let Some(import) = current_symbols
            .imports
            .iter()
            .find(|import| import.local_name == type_name)
        {
            let imported_file = resolve_module_path(ctx, &import.source_module)?;
            let mut base_visited = HashSet::new();
            self.resolve_symbol_in_file(
                ctx,
                &imported_file,
                &import.imported_name,
                &mut base_visited,
            )?
        } else {
            let mut base_visited = HashSet::new();
            self.resolve_symbol_in_file(ctx, &base_file, type_name, &mut base_visited)?
        };

        Some(match base_resolved {
            ResolvedSymbol::Local(_) => (base_file, type_name.to_string()),
            ResolvedSymbol::External {
                file_path,
                symbol_name,
            } => (file_path, symbol_name),
        })
    }

    pub(super) fn resolve_rust_type_member(
        &self,
        ctx: &ResolveContext<'_>,
        type_file: &str,
        resolved_type_name: &str,
        member_name: &str,
    ) -> Option<ResolvedSymbol> {
        let type_symbols = self.files.get(type_file)?;
        let member_def =
            self.find_definition(type_symbols, member_name, Some(resolved_type_name))?;

        if same_path(ctx.importing_file, type_file) {
            Some(ResolvedSymbol::Local(member_def.id))
        } else {
            Some(ResolvedSymbol::External {
                file_path: type_file.to_string(),
                symbol_name: member_def.name.clone(),
            })
        }
    }

    pub(super) fn resolve_rust_type_target(
        &self,
        ctx: &ResolveContext<'_>,
        segments: &[&str],
        visited: &mut HashSet<String>,
    ) -> Option<(String, String, String)> {
        let member_name = segments[segments.len() - 1];
        if let Some(target) = self.resolve_rust_direct_target(ctx, segments, visited) {
            return Some(target);
        }

        let (type_file, resolved_type_name) = self.resolve_rust_type_base(ctx, segments)?;

        Some((type_file, resolved_type_name, member_name.to_string()))
    }
}
