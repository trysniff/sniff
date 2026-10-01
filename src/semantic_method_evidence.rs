use super::context::{CompilerMethodWorld, compiler_method_worlds};
use super::{
    CompilerMethodContexts, CompilerMethodReference, SemanticMethodCoverage,
    compiler_method_references, join_methods, method_context_key,
};
use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticIndexSet, SemanticResolution, SemanticUnresolvedReason,
};
use crate::semantic_indexer_manifest::{SemanticIndexerKind, required_indexers};
use crate::types::FileRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[path = "semantic_method_context_compaction.rs"]
mod compaction;

pub(crate) struct CompilerMethodEvidence {
    pub(crate) contexts: CompilerMethodContexts,
    pub(crate) references: Vec<CompilerMethodReference>,
}

pub(crate) fn build_compiler_method_evidence(
    repository_root: &Path,
    files: &[FileRecord],
    index_sets: &BTreeMap<SemanticIndexerKind, SemanticIndexSet>,
) -> Result<CompilerMethodEvidence, String> {
    if index_sets.keys().copied().collect::<BTreeSet<_>>() != required_indexers(files) {
        return Err(
            "compiler semantic indexer set does not match the required languages".to_string(),
        );
    }
    let root = fs::canonicalize(repository_root)
        .map_err(|error| format!("failed to resolve compiler evidence repository root: {error}"))?;
    let mut expected = BTreeSet::new();
    for file in files {
        for method in &file.methods {
            let key = method_context_key(&file.file_path, &method.name, method.start_line);
            if !expected.insert(key.clone()) {
                return Err(format!("duplicate compiler evidence AST method: {key}"));
            }
        }
    }
    let mut contexts = BTreeMap::<String, Vec<CompilerMethodWorld>>::new();
    let mut references = BTreeSet::new();
    for (kind, set) in index_sets {
        set.validate()?;
        let index_files = crate::semantic_indexer_runner::files_for_indexer(files, *kind);
        match set {
            SemanticIndexSet::Unqualified { index } => {
                add_variant(
                    &root,
                    &index_files,
                    index,
                    None,
                    &mut contexts,
                    &mut references,
                )?;
            }
            SemanticIndexSet::Qualified { variants } => {
                for qualified in variants.values() {
                    add_variant(
                        &root,
                        &index_files,
                        &qualified.index,
                        Some(&qualified.ignored_documents),
                        &mut contexts,
                        &mut references,
                    )?;
                }
            }
        }
    }
    if contexts.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(format!(
            "compiler semantic context covered {} of {} exact AST methods",
            contexts.len(),
            expected.len(),
        ));
    }
    Ok(CompilerMethodEvidence {
        contexts: contexts
            .into_iter()
            .map(|(key, worlds)| compaction::render(&worlds).map(|context| (key, context)))
            .collect::<Result<_, _>>()?,
        references: references.into_iter().collect(),
    })
}

fn add_variant(
    root: &Path,
    files: &[FileRecord],
    index: &SemanticIndex,
    ignored: Option<&BTreeSet<RepositoryPath>>,
    contexts: &mut BTreeMap<String, Vec<CompilerMethodWorld>>,
    references: &mut BTreeSet<CompilerMethodReference>,
) -> Result<(), String> {
    let index_root = fs::canonicalize(&index.repository_root).map_err(|error| {
        format!("failed to resolve semantic index's declared repository root: {error}")
    })?;
    if index_root != root {
        return Err("compiler semantic index belongs to a different repository root".to_string());
    }
    let mut join = join_methods(root, files, index)?;
    for binding in join.bindings.values_mut() {
        if ignored.is_some_and(|documents| documents.contains(&binding.method.file)) {
            let reason = "document not selected in this compiler variant".to_string();
            binding.coverage = SemanticMethodCoverage::CompilerExcluded {
                reason: reason.clone(),
            };
            binding.symbol = SemanticResolution::Unresolved {
                reason: SemanticUnresolvedReason::MissingIndexerFact,
                raw_target: None,
                detail: reason,
            };
            binding.definition = None;
        }
    }
    join.require_complete()?;
    references.extend(compiler_method_references(root, files, index, &join)?);
    for (key, context) in compiler_method_worlds(root, files, index, &join)? {
        contexts.entry(key).or_default().push(context);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/semantic_method_evidence.rs"]
mod tests;
