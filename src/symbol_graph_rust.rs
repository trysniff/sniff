use super::{ResolveContext, SymbolGraph};
use crate::types::ResolvedSymbol;
use std::collections::HashSet;

impl SymbolGraph {
    pub(super) fn resolve_rust_qualified_reference_base(
        &self,
        ctx: &ResolveContext<'_>,
        segments: &[&str],
        visited: &mut HashSet<String>,
    ) -> Option<ResolvedSymbol> {
        if let Some(resolved) = self.resolve_rust_direct_reference(ctx, segments, visited) {
            return Some(resolved);
        }
        visited.clear();
        let (type_file, resolved_type_name, member_name) =
            self.resolve_rust_type_target(ctx, segments, visited)?;
        self.resolve_rust_type_member(ctx, &type_file, &resolved_type_name, &member_name)
    }

    pub(super) fn resolve_rust_qualified_reference(
        &self,
        ctx: &ResolveContext<'_>,
        reference_name: &str,
    ) -> Option<ResolvedSymbol> {
        let segments: Vec<&str> = reference_name
            .split("::")
            .filter(|segment| !segment.is_empty())
            .collect();

        if segments.len() < 2 {
            return None;
        }

        let mut visited = HashSet::new();
        self.resolve_rust_qualified_reference_base(ctx, &segments, &mut visited)
    }
}
