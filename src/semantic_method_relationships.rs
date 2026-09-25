use super::{
    SemanticMethodCoverage, SemanticMethodJoin, SemanticMethodKey, method_context_key,
    repository_relative_path,
};
use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticOccurrenceRole, SemanticResolution, SemanticSymbolId,
};
use crate::types::FileRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompilerRelationshipKind {
    Call,
    Reference,
}

/// A compiler-resolved relationship between two uniquely joined methods.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompilerMethodReference {
    pub kind: CompilerRelationshipKind,
    pub source_method: String,
    pub target_method: String,
    pub file: RepositoryPath,
    pub line: u32,
    pub symbol: SemanticSymbolId,
}

pub fn compiler_method_references(
    repository_root: &Path,
    files: &[FileRecord],
    index: &SemanticIndex,
    join: &SemanticMethodJoin,
) -> Result<Vec<CompilerMethodReference>, String> {
    let root = fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve compiler relationship root {}: {error}",
            repository_root.display()
        )
    })?;
    let mut file_paths = BTreeMap::<RepositoryPath, &str>::new();
    for file in files {
        let relative = repository_relative_path(&root, Path::new(&file.file_path))?;
        if file_paths
            .insert(relative.clone(), &file.file_path)
            .is_some()
        {
            return Err(format!(
                "duplicate compiler relationship file {}",
                relative.0
            ));
        }
    }
    let mut targets = BTreeMap::<SemanticSymbolId, Option<SemanticMethodKey>>::new();
    for binding in join.bindings.values() {
        if !matches!(binding.coverage, SemanticMethodCoverage::Indexed) {
            continue;
        }
        let SemanticResolution::Resolved { value } = &binding.symbol else {
            continue;
        };
        file_paths.get(&binding.method.file).ok_or_else(|| {
            format!(
                "semantic method join file disappeared: {}",
                binding.method.file.0
            )
        })?;
        // A symbol joined to multiple AST methods cannot identify one target.
        targets
            .entry(value.clone())
            .and_modify(|target| *target = None)
            .or_insert(Some(binding.method.clone()));
    }
    let mut references = BTreeSet::new();
    for (path, document) in &index.documents {
        let Some(file_path) = file_paths.get(path) else {
            continue;
        };
        let methods = join
            .bindings
            .values()
            .filter(|binding| {
                binding.method.file == *path
                    && matches!(binding.coverage, SemanticMethodCoverage::Indexed)
                    && matches!(binding.symbol, SemanticResolution::Resolved { .. })
            })
            .collect::<Vec<_>>();
        for occurrence in &document.occurrences {
            if occurrence.roles.iter().any(|role| {
                matches!(
                    role,
                    SemanticOccurrenceRole::Definition
                        | SemanticOccurrenceRole::Import
                        | SemanticOccurrenceRole::ForwardDefinition
                )
            }) {
                continue;
            }
            let Some(symbol) = &occurrence.symbol else {
                continue;
            };
            let Some(Some(target_method)) = targets.get(symbol) else {
                continue;
            };
            let Some(line) = occurrence.range.start.line.checked_add(1) else {
                continue;
            };
            let owners = methods
                .iter()
                .filter(|binding| {
                    binding.method.start_line <= line && line <= binding.method.end_line
                })
                .collect::<Vec<_>>();
            // AST method records have line spans, not columns. Overlap cannot
            // identify which nested method owns an occurrence safely.
            let [owner] = owners.as_slice() else {
                continue;
            };
            let source_method = method_context_key(
                file_path,
                &owner.method.name,
                owner.method.start_line as usize,
            );
            let target_path = file_paths.get(&target_method.file).ok_or_else(|| {
                format!("semantic target file disappeared: {}", target_method.file.0)
            })?;
            let target_key = method_context_key(
                target_path,
                &target_method.name,
                target_method.start_line as usize,
            );
            if source_method != target_key {
                references.insert(CompilerMethodReference {
                    kind: CompilerRelationshipKind::Reference,
                    source_method,
                    target_method: target_key,
                    file: path.clone(),
                    line,
                    symbol: symbol.clone(),
                });
            }
        }
    }
    for call in &index.calls {
        if !file_paths.contains_key(&call.callsite.document) {
            continue;
        }
        let SemanticResolution::Resolved { value: callee } = &call.callee else {
            continue;
        };
        let (Some(Some(source_method)), Some(Some(target_method))) =
            (targets.get(&call.caller), targets.get(callee))
        else {
            continue;
        };
        let Some(line) = call.callsite.range.start.line.checked_add(1) else {
            continue;
        };
        if source_method.file != call.callsite.document
            || !(source_method.start_line <= line && line <= source_method.end_line)
        {
            continue;
        }
        if source_method != target_method {
            let source_path = file_paths.get(&source_method.file).ok_or_else(|| {
                format!("semantic caller file disappeared: {}", source_method.file.0)
            })?;
            let target_path = file_paths.get(&target_method.file).ok_or_else(|| {
                format!("semantic target file disappeared: {}", target_method.file.0)
            })?;
            references.insert(CompilerMethodReference {
                kind: CompilerRelationshipKind::Call,
                source_method: method_context_key(
                    source_path,
                    &source_method.name,
                    source_method.start_line as usize,
                ),
                target_method: method_context_key(
                    target_path,
                    &target_method.name,
                    target_method.start_line as usize,
                ),
                file: call.callsite.document.clone(),
                line,
                symbol: callee.clone(),
            });
        }
    }
    Ok(references.into_iter().collect())
}
