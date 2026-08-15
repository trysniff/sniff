use super::*;
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub(super) fn materialize_bundle(
    root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    materials: &[IntentionalBoundarySourceMaterial<'_>],
) -> Result<(), String> {
    let material_map = materials
        .iter()
        .map(|material| {
            (
                (
                    material.inventory.repository.as_str(),
                    material.inventory.revision.as_str(),
                ),
                material,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for repository in &bundle.repositories {
        let material = material_map
            .get(&(repository.repository.as_str(), repository.revision.as_str()))
            .ok_or_else(|| {
                format!(
                    "intentional-boundary source material disappeared: {}@{}",
                    repository.repository, repository.revision
                )
            })?;
        for artifact in &repository.artifacts {
            let Some(relative) = &artifact.artifact_path else {
                continue;
            };
            let expected_length = artifact.byte_length.ok_or_else(|| {
                format!(
                    "intentional-boundary source artifact has no length: {}",
                    artifact.repository_path
                )
            })?;
            let bytes = read_intentional_boundary_git_blob(
                material.root,
                &artifact.object_id,
                expected_length,
            )?;
            let actual_sha256 = sha256(&bytes);
            if artifact.content_sha256.as_deref() != Some(actual_sha256.as_str()) {
                return Err(format!(
                    "intentional-boundary source changed during materialization: {}",
                    artifact.repository_path
                ));
            }
            let path = safe_artifact_path(root, relative)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!("failed to create source artifact directory: {error}")
                })?;
            }
            write_create_new(&path, &bytes, "intentional-boundary source artifact")?;
        }
    }
    let manifest = pretty_json(bundle, "intentional-boundary source manifest")?;
    write_create_new(
        &root.join(MANIFEST_NAME),
        &manifest,
        "intentional-boundary source manifest",
    )
}

pub(super) fn validate_persisted_bundle(
    root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
) -> Result<(), String> {
    validate_manifest_contract(bundle)?;
    let manifest_bytes = fs::read(root.join(MANIFEST_NAME))
        .map_err(|error| format!("failed to read intentional-boundary source manifest: {error}"))?;
    let persisted: IntentionalBoundarySourceBundle = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid intentional-boundary source manifest: {error}"))?;
    if &persisted != bundle {
        return Err("intentional-boundary persisted source manifest changed".to_string());
    }

    let mut expected_files = BTreeSet::from([MANIFEST_NAME.to_string()]);
    let mut repositories = BTreeMap::new();
    for repository in &bundle.repositories {
        if repositories
            .insert(repository.source_repository_id.as_str(), repository)
            .is_some()
            || repository.tracked_entry_count != repository.artifacts.len()
            || !prefixed_sha256(&repository.source_repository_id, "ibr-v1:")
            || !is_sha256(&repository.inventory_sha256)
            || !is_sha256(&repository.source_census_sha256)
            || !is_git_revision(&repository.revision)
            || repository.repository.trim().is_empty()
            || repository
                .artifacts
                .windows(2)
                .any(|pair| pair[0].repository_path >= pair[1].repository_path)
        {
            return Err("intentional-boundary source repository census changed".to_string());
        }
        let mut repository_paths = BTreeSet::new();
        for artifact in &repository.artifacts {
            if !repository_paths.insert(artifact.repository_path.as_str()) {
                return Err(format!(
                    "intentional-boundary source repository repeats path {}",
                    artifact.repository_path
                ));
            }
            if artifact.repository_path.trim().is_empty()
                || !is_git_object_id(&artifact.object_id)
                || artifact.mode.trim().is_empty()
            {
                return Err("intentional-boundary source artifact metadata changed".to_string());
            }
            match (&artifact.artifact_path, &artifact.content_sha256) {
                (Some(relative), Some(expected_sha256)) => {
                    if !is_sha256(expected_sha256) || !expected_files.insert(relative.clone()) {
                        return Err(
                            "intentional-boundary source artifact identity changed".to_string()
                        );
                    }
                    let path = safe_artifact_path(root, relative)?;
                    let bytes = fs::read(&path).map_err(|error| {
                        format!(
                            "failed to read intentional-boundary source artifact {}: {error}",
                            artifact.repository_path
                        )
                    })?;
                    if sha256(&bytes) != *expected_sha256
                        || Some(bytes.len() as u64) != artifact.byte_length
                    {
                        return Err(format!(
                            "intentional-boundary source artifact changed: {}",
                            artifact.repository_path
                        ));
                    }
                }
                (None, None) if artifact.kind == BoundaryGitEntryKind::Gitlink => {}
                _ => {
                    return Err(format!(
                        "intentional-boundary source artifact binding is incomplete: {}",
                        artifact.repository_path
                    ));
                }
            }
        }
    }
    validate_review_items(root, bundle, &repositories)?;
    if collect_bundle_files(root)? != expected_files {
        return Err(
            "intentional-boundary source bundle contains unexpected or missing files".to_string(),
        );
    }
    Ok(())
}

fn validate_manifest_contract(bundle: &IntentionalBoundarySourceBundle) -> Result<(), String> {
    if bundle.schema_version != INTENTIONAL_BOUNDARY_SOURCE_BUNDLE_SCHEMA_VERSION
        || bundle.bundle_contract != SOURCE_BUNDLE_CONTRACT
        || bundle.bundle_sha256 != bundle_sha256(bundle)?
        || bundle.selected_slot_count != bundle.review_items.len()
        || bundle.selected_slot_count + bundle.unfilled_slot_count != SOURCE_BUNDLE_TOTAL_SLOTS
        || bundle
            .repositories
            .windows(2)
            .any(|pair| pair[0].source_repository_id >= pair[1].source_repository_id)
        || bundle
            .review_items
            .windows(2)
            .any(|pair| pair[0].review_item_id >= pair[1].review_item_id)
        || ![
            &bundle.protocol_sha256,
            &bundle.policy_sha256,
            &bundle.frame_task_sha256,
            &bundle.candidate_frame_sha256,
            &bundle.selection_sha256,
        ]
        .into_iter()
        .all(|value| is_sha256(value))
    {
        return Err("intentional-boundary source bundle commitment changed".to_string());
    }
    Ok(())
}

fn validate_review_items(
    root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    repositories: &BTreeMap<&str, &IntentionalBoundarySourceRepository>,
) -> Result<(), String> {
    for item in &bundle.review_items {
        if !prefixed_sha256(&item.review_item_id, "ibi-v1:")
            || !is_sha256(&item.source_sha256)
            || item.repository.trim().is_empty()
            || item.repository_path.trim().is_empty()
            || item.language.trim().is_empty()
            || item.symbol_name.trim().is_empty()
            || !is_git_revision(&item.revision)
            || item.start_line == 0
            || item.end_line < item.start_line
        {
            return Err("intentional-boundary source review item identity changed".to_string());
        }
        let repository = repositories
            .get(item.source_repository_id.as_str())
            .ok_or_else(|| {
                format!(
                    "intentional-boundary review item names unknown repository {}",
                    item.source_repository_id
                )
            })?;
        if !prefixed_sha256(&repository.source_repository_id, "ibr-v1:")
            || repository.repository != item.repository
            || repository.revision != item.revision
        {
            return Err("intentional-boundary review item repository changed".to_string());
        }
        let artifact = repository
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.repository_path == item.repository_path
                    && artifact.artifact_path.as_deref() == Some(&item.source_artifact_path)
            })
            .ok_or_else(|| {
                format!(
                    "intentional-boundary review item source disappeared: {}",
                    item.repository_path
                )
            })?;
        let relative = artifact
            .artifact_path
            .as_deref()
            .expect("matched source artifact path");
        let bytes = fs::read(safe_artifact_path(root, relative)?).map_err(|error| {
            format!(
                "failed to read intentional-boundary review source {}: {error}",
                item.repository_path
            )
        })?;
        let parsed = crate::parser::parse_source_checked(&item.repository_path, &bytes)?;
        let exact_method = parsed.methods.iter().any(|method| {
            method.name == item.symbol_name
                && method.start_line == item.start_line
                && method.end_line == item.end_line
                && sha256(method.source.as_bytes()) == item.source_sha256
        });
        if parsed.language != item.language || !exact_method {
            return Err(format!(
                "intentional-boundary review item method changed: {}",
                item.review_item_id
            ));
        }
    }
    Ok(())
}

fn collect_bundle_files(root: &Path) -> Result<BTreeSet<String>, String> {
    fn visit(root: &Path, current: &Path, files: &mut BTreeSet<String>) -> Result<(), String> {
        for entry in fs::read_dir(current)
            .map_err(|error| format!("failed to inspect source bundle: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("failed to inspect source bundle: {error}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("failed to inspect source bundle entry: {error}"))?;
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                return Err(
                    "intentional-boundary source bundle contains an unsafe entry".to_string(),
                );
            }
            if file_type.is_dir() {
                visit(root, &entry.path(), files)?;
            } else {
                let path = entry.path();
                let relative = path.strip_prefix(root).map_err(|_| {
                    "intentional-boundary source bundle path escaped its root".to_string()
                })?;
                let portable = relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                if !files.insert(portable) {
                    return Err("intentional-boundary source bundle repeats a file".to_string());
                }
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

pub(super) fn safe_artifact_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "intentional-boundary bundle artifact path is unsafe: {relative}"
        ));
    }
    Ok(root.join(path))
}

pub(super) fn temporary_bundle_root(output_root: &Path) -> Result<PathBuf, String> {
    let parent = output_root.parent().ok_or_else(|| {
        "intentional-boundary source bundle output has no parent directory".to_string()
    })?;
    if !parent.exists() {
        return Err(format!(
            "intentional-boundary source bundle parent does not exist: {}",
            parent.display()
        ));
    }
    let name = output_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "intentional-boundary source bundle name is not UTF-8".to_string())?;
    Ok(parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system time is before the Unix epoch".to_string())?
            .as_nanos()
    )))
}

fn write_create_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create {label}: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {label}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("failed to persist {label}: {error}"))
}

fn pretty_json(value: &impl Serialize, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_sha256)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_git_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
