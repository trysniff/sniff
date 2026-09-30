use super::{
    CompilerMethodContexts, SemanticMethodBinding, SemanticMethodCoverage, SemanticMethodJoin,
    method_context_key, repository_relative_path,
};
use crate::semantic_index::{SemanticIndex, SemanticIndexVariant, SemanticResolution};
use crate::types::FileRecord;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[path = "semantic_method_context_contracts.rs"]
mod contracts;

pub fn render_compiler_method_contexts(
    repository_root: &Path,
    files: &[FileRecord],
    index: &SemanticIndex,
    join: &SemanticMethodJoin,
) -> Result<CompilerMethodContexts, String> {
    index.variant.validate()?;
    let contracts = contracts::CompilerContracts::new(index);
    let canonical_root = fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve compiler semantic context repository root {}: {error}",
            repository_root.display()
        )
    })?;
    let mut contexts = BTreeMap::new();
    for binding in join.bindings.values() {
        let file = files
            .iter()
            .find(|file| {
                repository_relative_path(&canonical_root, Path::new(&file.file_path))
                    .ok()
                    .as_ref()
                    == Some(&binding.method.file)
            })
            .ok_or_else(|| {
                format!(
                    "semantic method join file disappeared: {}",
                    binding.method.file.0
                )
            })?;
        let key = method_context_key(
            &file.file_path,
            &binding.method.name,
            binding.method.start_line as usize,
        );
        let context = render_binding_context(index, binding, &contracts);
        if contexts.insert(key.clone(), context).is_some() {
            return Err(format!("duplicate compiler method context: {key}"));
        }
    }
    Ok(contexts)
}

fn render_binding_context(
    index: &SemanticIndex,
    binding: &SemanticMethodBinding,
    contracts: &contracts::CompilerContracts<'_>,
) -> String {
    let mut lines = vec![format!("SCIP provider: {}", index.provenance.tool_name)];
    lines.push(match &index.variant {
        SemanticIndexVariant::Unqualified => {
            "compiler variant: unqualified; not proof of all build configurations".to_string()
        }
        SemanticIndexVariant::Qualified {
            identity,
            dimensions,
        } => {
            format!(
                "compiler variant: qualified {:?}; dimensions: {dimensions:?}",
                identity.0
            )
        }
    });
    match (&binding.coverage, &binding.symbol) {
        (SemanticMethodCoverage::CompilerExcluded { reason }, _) => {
            lines.push(format!("compiler coverage: excluded ({reason})"));
        }
        (_, SemanticResolution::Unresolved { reason, detail, .. }) => {
            lines.push(format!(
                "compiler symbol: unresolved ({reason:?}): {detail}"
            ));
        }
        (_, SemanticResolution::Resolved { value }) => {
            lines.push(format!("compiler symbol: resolved {}", value.0));
            if let Some(symbol) = index.symbols.get(value) {
                lines.push(format!(
                    "compiler kind: {:?}; visibility: {:?}; origin: {:?}",
                    symbol.kind.category, symbol.visibility, symbol.origin
                ));
                if !symbol.surfaces.is_empty() {
                    lines.push(format!("compiler surfaces: {:?}", symbol.surfaces));
                } else {
                    lines.push(
                        "compiler public/entrypoint surfaces: not established by this index"
                            .to_string(),
                    );
                }
                for signature in &symbol.signatures {
                    lines.push(format!("compiler signature: {}", signature.text));
                }
                if !symbol.ambiguity_notes.is_empty() {
                    lines.push(format!(
                        "compiler ambiguity notes: {}",
                        symbol.ambiguity_notes.join("; ")
                    ));
                }
            }
            contracts.render(index, value, &mut lines);
            let callers = index
                .calls
                .iter()
                .filter_map(|edge| match &edge.callee {
                    SemanticResolution::Resolved { value: callee } if callee == value => {
                        Some(format_call_edge(index, edge, "caller"))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if !callers.is_empty() {
                lines.push(format!(
                    "compiler-resolved callers: {}",
                    callers.join(" | ")
                ));
            }
            let callees = index
                .calls
                .iter()
                .filter(|edge| edge.caller == *value)
                .map(|edge| format_call_edge(index, edge, "callee"))
                .collect::<Vec<_>>();
            if !callees.is_empty() {
                lines.push(format!(
                    "compiler-resolved callees: {}",
                    callees.join(" | ")
                ));
            }
            let unresolved = index
                .unresolved_edges
                .iter()
                .filter(|edge| edge.source.as_ref() == Some(value))
                .map(|edge| format!("{:?}: {}", edge.reason, edge.detail))
                .collect::<Vec<_>>();
            if !unresolved.is_empty() {
                lines.push(format!(
                    "compiler-unresolved edges: {}",
                    unresolved.join(" | ")
                ));
            }
        }
    }
    lines.join("\n")
}

fn format_call_edge(
    index: &SemanticIndex,
    edge: &crate::semantic_index::SemanticCallEdge,
    role: &str,
) -> String {
    let other = if role == "caller" {
        &edge.caller
    } else {
        match &edge.callee {
            SemanticResolution::Resolved { value } => value,
            SemanticResolution::Unresolved { .. } => {
                return format!(
                    "{role} unresolved at {}:{}",
                    edge.callsite.document.0,
                    edge.callsite.range.start.line + 1
                );
            }
        }
    };
    let display = index
        .symbols
        .get(other)
        .and_then(|symbol| symbol.display_name.as_deref())
        .unwrap_or(other.0.as_str());
    format!(
        "{role} {display} at {}:{} ({:?})",
        edge.callsite.document.0,
        edge.callsite.range.start.line + 1,
        edge.dispatch
    )
}

#[cfg(test)]
#[path = "tests/semantic_method_context.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/semantic_method_context_scip.rs"]
mod scip_tests;
