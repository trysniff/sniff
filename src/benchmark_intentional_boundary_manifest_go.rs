use super::super::intentional_boundary_inventory::read_intentional_boundary_git_blob;
use super::{compute_manifest_declaration_id, sha256};
use crate::benchmark::release::{
    BoundaryGitEntryKind, IntentionalBoundaryGoGenerateDirective,
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestDocument, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticRange,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

struct GoGenerateSource {
    repository_path: String,
    object_id: String,
    source_sha256: String,
    directives: Vec<IntentionalBoundaryGoGenerateDirective>,
}

pub(super) fn parse_go_generate_sources(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<
    (
        Vec<IntentionalBoundaryManifestDocument>,
        Vec<IntentionalBoundaryManifestDeclaration>,
    ),
    String,
> {
    let mut packages = BTreeMap::<String, Vec<GoGenerateSource>>::new();
    for entry in inventory
        .tracked_entries
        .iter()
        .filter(|entry| entry.repository_path.ends_with(".go"))
    {
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            continue;
        }
        let expected_length = entry.byte_length.ok_or_else(|| {
            format!(
                "Go generator source has no committed byte length: {}",
                entry.repository_path
            )
        })?;
        let bytes = read_intentional_boundary_git_blob(root, &entry.object_id, expected_length)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| {
            format!(
                "Go generator source is not UTF-8: {}",
                entry.repository_path
            )
        })?;
        let directives = directives(&entry.repository_path, source);
        if directives.is_empty() {
            continue;
        }
        packages
            .entry(parent_path(&entry.repository_path).to_string())
            .or_default()
            .push(GoGenerateSource {
                repository_path: entry.repository_path.clone(),
                object_id: entry.object_id.clone(),
                source_sha256: sha256(&bytes),
                directives,
            });
    }

    let module_manifests = inventory
        .tracked_entries
        .iter()
        .filter(|entry| entry.repository_path.rsplit('/').next() == Some("go.mod"))
        .map(|entry| entry.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut documents = Vec::new();
    let mut declarations = Vec::new();
    for (package_repository_path, mut sources) in packages {
        sources.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
        let mut package_directives = sources
            .iter()
            .flat_map(|source| source.directives.iter().cloned())
            .collect::<Vec<_>>();
        package_directives.sort();
        let anchor_path = sources[0].repository_path.clone();
        let anchor_object_id = sources[0].object_id.clone();
        let mut declaration = IntentionalBoundaryManifestDeclaration {
            declaration_id: String::new(),
            provider: IntentionalBoundaryManifestProvider::GoGenerateSource,
            manifest_repository_path: anchor_path.clone(),
            manifest_object_id: anchor_object_id,
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::GeneratorCommand,
            declaration_location: package_directives[0].location.clone(),
            target: IntentionalBoundaryManifestTarget::GoGeneratePackage {
                module_manifest_repository_path: nearest_module_manifest(
                    &package_repository_path,
                    &module_manifests,
                ),
                package_repository_path,
                directives: package_directives,
            },
        };
        declaration.declaration_id = compute_manifest_declaration_id(&declaration)?;
        for source in sources {
            documents.push(IntentionalBoundaryManifestDocument {
                provider: IntentionalBoundaryManifestProvider::GoGenerateSource,
                repository_path: source.repository_path.clone(),
                object_id: source.object_id,
                source_sha256: source.source_sha256,
                declaration_count: usize::from(source.repository_path == anchor_path),
            });
        }
        declarations.push(declaration);
    }
    Ok((documents, declarations))
}

fn directives(repository_path: &str, source: &str) -> Vec<IntentionalBoundaryGoGenerateDirective> {
    source
        .lines()
        .enumerate()
        .filter_map(|(line, raw_text)| {
            let text = raw_text.strip_suffix('\r').unwrap_or(raw_text);
            (text.starts_with("//go:generate ") || text.starts_with("//go:generate\t")).then(|| {
                IntentionalBoundaryGoGenerateDirective {
                    location: IntentionalBoundarySemanticRange {
                        repository_path: repository_path.to_string(),
                        start_line_zero_based: line as u32,
                        start_character_zero_based: 0,
                        end_line_zero_based: line as u32,
                        end_character_zero_based: text.len() as u32,
                    },
                    source_text: text.to_string(),
                }
            })
        })
        .collect()
}

fn nearest_module_manifest(
    package_repository_path: &str,
    manifests: &BTreeSet<&str>,
) -> Option<String> {
    let mut directory = package_repository_path;
    loop {
        let candidate = if directory.is_empty() {
            "go.mod".to_string()
        } else {
            format!("{directory}/go.mod")
        };
        if manifests.contains(candidate.as_str()) {
            return Some(candidate);
        }
        let Some((parent, _)) = directory.rsplit_once('/') else {
            if directory.is_empty() {
                return None;
            }
            directory = "";
            continue;
        };
        directory = parent;
    }
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_manifest_go_tests.rs"]
mod tests;
