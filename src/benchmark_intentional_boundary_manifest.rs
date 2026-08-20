use super::intentional_boundary_inventory::read_intentional_boundary_git_blob;
use super::{
    BoundaryGitEntryKind, INTENTIONAL_BOUNDARY_MANIFEST_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryManifestCensus, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestDocument,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticRange,
    validate_intentional_boundary_repository_inventory,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const MANIFEST_CONTRACT: &str = "sniffbench-intentional-boundary-manifest-declarations-v4";

#[path = "benchmark_intentional_boundary_manifest_node.rs"]
mod node;
#[path = "benchmark_intentional_boundary_manifest_toml.rs"]
mod toml;

#[derive(Debug)]
pub(super) struct ParsedManifestDeclaration {
    pub(super) declaration_kind: IntentionalBoundaryManifestDeclarationKind,
    pub(super) span: std::ops::Range<usize>,
    pub(super) target: IntentionalBoundaryManifestTarget,
}

pub fn census_intentional_boundary_manifests(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryManifestCensus, String> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    let mut documents = Vec::new();
    let mut declarations = Vec::new();
    for entry in &inventory.tracked_entries {
        let Some(provider) = provider_for_path(&entry.repository_path) else {
            continue;
        };
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            return Err(format!(
                "intentional-boundary recognized manifest is not a regular Git blob: {}",
                entry.repository_path
            ));
        }
        let expected_length = entry.byte_length.ok_or_else(|| {
            format!(
                "intentional-boundary manifest has no committed byte length: {}",
                entry.repository_path
            )
        })?;
        let bytes = read_intentional_boundary_git_blob(root, &entry.object_id, expected_length)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| {
            format!(
                "intentional-boundary manifest is not UTF-8: {}",
                entry.repository_path
            )
        })?;
        let parsed = match provider {
            IntentionalBoundaryManifestProvider::CargoManifest
            | IntentionalBoundaryManifestProvider::PythonProjectManifest => {
                toml::parse_manifest(provider, &entry.repository_path, source)
            }
            IntentionalBoundaryManifestProvider::NodePackageManifest => {
                node::parse_package_json(&entry.repository_path, source)
            }
            IntentionalBoundaryManifestProvider::GoPackageMetadata
            | IntentionalBoundaryManifestProvider::GradleProjectModel => {
                unreachable!("command-backed providers have no static manifest path")
            }
        }?;
        documents.push(IntentionalBoundaryManifestDocument {
            provider,
            repository_path: entry.repository_path.clone(),
            object_id: entry.object_id.clone(),
            source_sha256: sha256(&bytes),
            declaration_count: parsed.len(),
        });
        for declaration in parsed {
            let mut declaration = IntentionalBoundaryManifestDeclaration {
                declaration_id: String::new(),
                provider,
                manifest_repository_path: entry.repository_path.clone(),
                manifest_object_id: entry.object_id.clone(),
                declaration_kind: declaration.declaration_kind,
                declaration_location: span_range(&entry.repository_path, source, declaration.span),
                target: declaration.target,
            };
            declaration.declaration_id = compute_manifest_declaration_id(&declaration)?;
            declarations.push(declaration);
        }
    }
    documents.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    declarations.sort();
    let document_count_by_provider =
        documents
            .iter()
            .fold(BTreeMap::new(), |mut counts, document| {
                *counts.entry(document.provider).or_insert(0) += 1;
                counts
            });
    let declaration_count_by_kind =
        declarations
            .iter()
            .fold(BTreeMap::new(), |mut counts, declaration| {
                *counts.entry(declaration.declaration_kind).or_insert(0) += 1;
                counts
            });
    let mut census = IntentionalBoundaryManifestCensus {
        schema_version: INTENTIONAL_BOUNDARY_MANIFEST_CENSUS_SCHEMA_VERSION,
        manifest_contract: MANIFEST_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        documents,
        document_count_by_provider,
        declarations,
        declaration_count_by_kind,
        manifest_census_sha256: String::new(),
    };
    census.manifest_census_sha256 = compute_manifest_census_sha256(&census)?;
    Ok(census)
}

pub fn validate_intentional_boundary_manifest_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundaryManifestCensus,
) -> Result<(), String> {
    let expected = census_intentional_boundary_manifests(repository, revision, root, inventory)?;
    if census != &expected {
        return Err("intentional-boundary manifest census changed".to_string());
    }
    Ok(())
}

pub(super) fn validate_manifest_census_commitment(
    inventory_sha256: &str,
    census: &IntentionalBoundaryManifestCensus,
) -> Result<(), String> {
    if census.schema_version != INTENTIONAL_BOUNDARY_MANIFEST_CENSUS_SCHEMA_VERSION
        || census.manifest_contract != MANIFEST_CONTRACT
        || census.inventory_sha256 != inventory_sha256
        || census.repository.trim().is_empty()
        || census.revision.trim().is_empty()
    {
        return Err("intentional-boundary manifest census identity changed".to_string());
    }
    if census
        .documents
        .windows(2)
        .any(|pair| pair[0].repository_path >= pair[1].repository_path)
        || census
            .declarations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("intentional-boundary manifest census ordering changed".to_string());
    }
    for declaration in &census.declarations {
        if declaration.declaration_id != compute_manifest_declaration_id(declaration)?
            || !census.documents.iter().any(|document| {
                document.provider == declaration.provider
                    && document.repository_path == declaration.manifest_repository_path
                    && document.object_id == declaration.manifest_object_id
            })
        {
            return Err("intentional-boundary manifest declaration identity changed".to_string());
        }
    }
    let document_count_by_provider =
        census
            .documents
            .iter()
            .fold(BTreeMap::new(), |mut counts, document| {
                *counts.entry(document.provider).or_insert(0) += 1;
                counts
            });
    let declaration_count_by_kind =
        census
            .declarations
            .iter()
            .fold(BTreeMap::new(), |mut counts, declaration| {
                *counts.entry(declaration.declaration_kind).or_insert(0) += 1;
                counts
            });
    if census.document_count_by_provider != document_count_by_provider
        || census.declaration_count_by_kind != declaration_count_by_kind
        || census.documents.iter().any(|document| {
            document.declaration_count
                != census
                    .declarations
                    .iter()
                    .filter(|declaration| {
                        declaration.provider == document.provider
                            && declaration.manifest_repository_path == document.repository_path
                            && declaration.manifest_object_id == document.object_id
                    })
                    .count()
        })
        || compute_manifest_census_sha256(census)? != census.manifest_census_sha256
    {
        return Err("intentional-boundary manifest census commitment changed".to_string());
    }
    Ok(())
}

fn provider_for_path(path: &str) -> Option<IntentionalBoundaryManifestProvider> {
    match path.rsplit('/').next()? {
        "Cargo.toml" => Some(IntentionalBoundaryManifestProvider::CargoManifest),
        "package.json" => Some(IntentionalBoundaryManifestProvider::NodePackageManifest),
        "pyproject.toml" => Some(IntentionalBoundaryManifestProvider::PythonProjectManifest),
        _ => None,
    }
}

pub(super) fn resolve_manifest_path(manifest_path: &str, target: &str) -> Result<String, String> {
    let normalized = target.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.ends_with('/')
        || normalized.contains(':')
    {
        return Err(format!("manifest target path is unsafe: {target}"));
    }
    let mut parts = manifest_path.split('/').collect::<Vec<_>>();
    parts.pop();
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!("manifest target escapes the repository: {target}"));
                }
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        return Err(format!("manifest target path is empty: {target}"));
    }
    Ok(parts.join("/"))
}

fn span_range(
    repository_path: &str,
    source: &str,
    span: std::ops::Range<usize>,
) -> IntentionalBoundarySemanticRange {
    let starts = std::iter::once(0)
        .chain(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        )
        .collect::<Vec<_>>();
    let start = span.start.min(source.len());
    let end = span.end.min(source.len());
    let start_line = starts.partition_point(|offset| *offset <= start) - 1;
    let end_line = starts.partition_point(|offset| *offset <= end) - 1;
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: start_line as u32,
        start_character_zero_based: start.saturating_sub(starts[start_line]) as u32,
        end_line_zero_based: end_line as u32,
        end_character_zero_based: end.saturating_sub(starts[end_line]) as u32,
    }
}

pub(super) fn compute_manifest_census_sha256(
    census: &IntentionalBoundaryManifestCensus,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.manifest_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.documents,
        &census.document_count_by_provider,
        &census.declarations,
        &census.declaration_count_by_kind,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary manifest census: {error}"))?;
    Ok(sha256(&bytes))
}

pub(super) fn compute_manifest_declaration_id(
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        "sniffbench-intentional-boundary-manifest-declaration-v1",
        declaration.provider,
        &declaration.manifest_repository_path,
        &declaration.manifest_object_id,
        declaration.declaration_kind,
        &declaration.declaration_location,
        &declaration.target,
    ))
    .map_err(|error| format!("failed to commit manifest declaration identity: {error}"))?;
    Ok(format!("ibmd-v1:{}", sha256(&bytes)))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_manifest_tests.rs"]
mod tests;
