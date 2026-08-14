use super::*;
use std::collections::HashSet;
use std::path::Path;

pub fn validate_source_seal(seal: &BenchmarkSourceSeal, seal_root: &Path) -> Result<(), String> {
    require_text("source seal selection_id", &seal.selection_id)?;
    require_text("source seal selected_at", &seal.selected_at)?;
    require_text(
        "source seal selection_methodology",
        &seal.selection_methodology,
    )?;
    require_text(
        "source seal selection_attestation",
        &seal.selection_attestation,
    )?;
    require_sha256(
        "source seal selection audit SHA-256",
        &seal.selection_audit_sha256,
    )?;
    validate_artifact(
        seal_root,
        &seal.selection_audit_artifact_path,
        &seal.selection_audit_artifact_sha256,
        "source selection audit",
    )?;
    validate_artifact(
        seal_root,
        &seal.selection_frame_artifact_path,
        &seal.selection_frame_sha256,
        "source selection frame",
    )?;
    let audit_bytes = read_artifact(seal_root, &seal.selection_audit_artifact_path)?;
    let frame_bytes = read_artifact(seal_root, &seal.selection_frame_artifact_path)?;
    let selected_repositories = if seal.selection_components.is_empty() {
        let audit: SourceSelectionAudit = serde_json::from_slice(&audit_bytes)
            .map_err(|error| format!("failed to parse sealed source-selection audit: {error}"))?;
        validate_source_selection_against_frame(&audit, &frame_bytes)?;
        if audit.audit_sha256 != seal.selection_audit_sha256
            || audit.frame_sha256 != seal.selection_frame_sha256
            || audit.policy.selection_id != seal.selection_id
            || audit.policy.selected_at != seal.selected_at
            || audit.policy.attestation != seal.selection_attestation
        {
            return Err("source seal metadata does not match its selection audit".to_string());
        }
        audit.selected_repositories
    } else {
        validate_composite_selection_artifacts(seal, seal_root, &audit_bytes, &frame_bytes)?
    };
    if seal.schema_version != SOURCE_SEAL_SCHEMA_VERSION {
        return Err(format!(
            "source seal schema_version must be {SOURCE_SEAL_SCHEMA_VERSION}"
        ));
    }
    if seal.census_contract_version != SOURCE_CENSUS_CONTRACT_VERSION {
        return Err(format!(
            "source seal census_contract_version must be {SOURCE_CENSUS_CONTRACT_VERSION}"
        ));
    }
    if seal.sources.is_empty() || seal.methods.is_empty() || seal.licenses.is_empty() {
        return Err("source seal requires sources, eligible methods, and licenses".to_string());
    }
    let mut source_keys = HashSet::new();
    let mut source_identities = HashSet::new();
    for source in &seal.sources {
        validate_source_identity(source, "source seal source")?;
        validate_artifact(
            seal_root,
            &source.artifact_path,
            &source.sha256,
            "source seal source",
        )?;
        if !source_keys.insert((
            source.repository.as_str(),
            source.revision.as_str(),
            source.repository_path.as_str(),
            source.artifact_path.as_str(),
        )) {
            return Err(format!(
                "source seal repeats source {} at {}",
                source.repository, source.repository_path
            ));
        }
        source_identities.insert((
            source.repository.as_str(),
            source.revision.as_str(),
            source.repository_path.as_str(),
        ));
    }
    let mut context_keys = HashSet::new();
    for source in &seal.context_sources {
        validate_source_identity(source, "source seal review context")?;
        validate_artifact(
            seal_root,
            &source.artifact_path,
            &source.sha256,
            "source seal review context",
        )?;
        let key = (
            source.repository.as_str(),
            source.revision.as_str(),
            source.repository_path.as_str(),
        );
        if source_identities.contains(&key) || !context_keys.insert(key) {
            return Err(format!(
                "source seal repeats review context {} at {}",
                source.repository, source.repository_path
            ));
        }
    }
    let source_artifacts = seal
        .sources
        .iter()
        .map(|source| (source.artifact_path.as_str(), source))
        .collect::<std::collections::HashMap<_, _>>();
    let mut method_ids = HashSet::new();
    for method in &seal.methods {
        require_text("sealed method repository", &method.repository)?;
        require_revision(&method.revision)?;
        safe_relative_path(&method.repository_path)?;
        safe_relative_path(&method.artifact_path)?;
        require_sha256("sealed method_id", &method.method_id)?;
        require_sha256("sealed method source_sha256", &method.source_sha256)?;
        require_text("sealed method language", &method.language)?;
        require_text("sealed method name", &method.name)?;
        if method.start_line == 0 || method.end_line < method.start_line {
            return Err(format!(
                "sealed method {} has an invalid range",
                method.method_id
            ));
        }
        let Some(source) = source_artifacts.get(method.artifact_path.as_str()) else {
            return Err(format!(
                "sealed method {} references an unknown source artifact",
                method.method_id
            ));
        };
        if method.repository != source.repository
            || method.revision != source.revision
            || method.repository_path != source.repository_path
        {
            return Err(format!(
                "sealed method {} does not match its source identity",
                method.method_id
            ));
        }
        if !method_ids.insert(method.method_id.as_str()) {
            return Err(format!("source seal repeats method {}", method.method_id));
        }
    }
    let mut parsed_methods = Vec::new();
    for source in &seal.sources {
        let artifact = seal_root.join(safe_relative_path(&source.artifact_path)?);
        let record = crate::parser::parse_file_checked(&artifact.to_string_lossy())?;
        if record.language.is_empty() {
            return Err(format!(
                "sealed source is no longer supported by the census contract: {}",
                source.artifact_path
            ));
        }
        for method in record.methods {
            let method_source_hash = sha256(method.source.as_bytes());
            parsed_methods.push(SealedMethod {
                method_id: sealed_method_identity(
                    &source.repository,
                    &source.revision,
                    &source.repository_path,
                    &method.name,
                    method.start_line,
                    method.end_line,
                    &method_source_hash,
                )?,
                repository: source.repository.clone(),
                revision: source.revision.clone(),
                repository_path: source.repository_path.clone(),
                artifact_path: source.artifact_path.clone(),
                language: method.language,
                name: method.name,
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: method_source_hash,
            });
        }
    }
    parsed_methods.sort_by(|left, right| left.method_id.cmp(&right.method_id));
    if parsed_methods != seal.methods {
        return Err(
            "source seal eligible-method census does not match its sealed sources".to_string(),
        );
    }
    let mut license_repositories = HashSet::new();
    for license in &seal.licenses {
        require_text("sealed license repository", &license.repository)?;
        require_revision(&license.revision)?;
        safe_relative_path(&license.repository_path)?;
        validate_artifact(
            seal_root,
            &license.artifact_path,
            &license.sha256,
            "source seal license",
        )?;
        if !license_repositories.insert((license.repository.as_str(), license.revision.as_str())) {
            return Err(format!(
                "source seal repeats license evidence for {} at {}",
                license.repository, license.revision
            ));
        }
    }
    let repositories = seal
        .sources
        .iter()
        .map(|source| (source.repository.as_str(), source.revision.as_str()))
        .collect::<HashSet<_>>();
    if repositories != license_repositories {
        return Err("source seal does not provide one license for every repository".to_string());
    }
    validate_selection_census(&selected_repositories, seal)?;
    let expected = seal.computed_seal_sha256()?;
    if !seal.seal_sha256.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "source seal commitment does not match its contents; expected {expected}"
        ));
    }
    Ok(())
}

fn validate_composite_selection_artifacts(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    audit_bytes: &[u8],
    frame_manifest_bytes: &[u8],
) -> Result<Vec<SourceRepositoryDraft>, String> {
    let audit: SourceSelectionCompositeAudit = serde_json::from_slice(audit_bytes)
        .map_err(|error| format!("failed to parse sealed composite selection audit: {error}"))?;
    validate_source_selection_composite_audit(&audit)?;
    let manifest: CompositeSourceFrameManifest = serde_json::from_slice(frame_manifest_bytes)
        .map_err(|error| format!("failed to parse sealed composite frame manifest: {error}"))?;
    if manifest.schema_version != 1
        || manifest.components.len() != audit.components.len()
        || seal.selection_components.len() != audit.components.len()
    {
        return Err(
            "source seal composite frame manifest does not contain every component".to_string(),
        );
    }
    for ((component, sealed), committed) in audit
        .components
        .iter()
        .zip(&seal.selection_components)
        .zip(&manifest.components)
    {
        if sealed.selection_id != component.policy.selection_id
            || sealed.component_audit_sha256 != component.component_audit_sha256
            || sealed.frame_sha256 != component.frame_sha256
            || committed.selection_id != component.policy.selection_id
            || committed.component_audit_sha256 != component.component_audit_sha256
            || committed.frame_sha256 != component.frame_sha256
        {
            return Err(
                "source seal composite component ledger does not match its audit".to_string(),
            );
        }
        validate_artifact(
            seal_root,
            &sealed.frame_artifact_path,
            &sealed.frame_sha256,
            "source selection component frame",
        )?;
        let frame = read_artifact(seal_root, &sealed.frame_artifact_path)?;
        validate_source_selection_component_against_frame(component, &frame)?;
    }
    if audit.composite_audit_sha256 != seal.selection_audit_sha256
        || sha256(frame_manifest_bytes) != seal.selection_frame_sha256
        || audit.policy.selection_id != seal.selection_id
        || audit.policy.selected_at != seal.selected_at
        || audit.policy.attestation != seal.selection_attestation
    {
        return Err(
            "source seal metadata does not match its composite selection audit".to_string(),
        );
    }
    Ok(audit.selected_repositories)
}

fn validate_source_identity(source: &SourceSnapshot, label: &str) -> Result<(), String> {
    require_text(&format!("{label} repository"), &source.repository)?;
    require_revision(&source.revision)?;
    safe_relative_path(&source.repository_path)?;
    safe_relative_path(&source.artifact_path)?;
    Ok(())
}

fn validate_selection_census(
    selected_repositories: &[SourceRepositoryDraft],
    seal: &BenchmarkSourceSeal,
) -> Result<(), String> {
    let selected = selected_repositories
        .iter()
        .map(|repository| (repository.repository.as_str(), repository.revision.as_str()))
        .collect::<HashSet<_>>();
    let sealed = seal
        .sources
        .iter()
        .map(|source| (source.repository.as_str(), source.revision.as_str()))
        .collect::<HashSet<_>>();
    if selected != sealed {
        return Err("source seal repository census does not match its selection audit".to_string());
    }
    for repository in selected_repositories {
        let methods = seal
            .methods
            .iter()
            .filter(|method| {
                method.repository == repository.repository && method.revision == repository.revision
            })
            .collect::<Vec<_>>();
        if methods.len() != repository.observed_method_count {
            return Err(format!(
                "sealed repository {} has {} methods but its selection audit records {}",
                repository.repository,
                methods.len(),
                repository.observed_method_count
            ));
        }
        let dominant_language =
            dominant_method_language(methods.iter().map(|method| method.language.as_str()))
                .expect("the audited positive method census has a dominant language");
        if dominant_language != repository.selection_language.to_ascii_lowercase() {
            return Err(format!(
                "sealed repository {} has dominant eligible-method language {dominant_language}, not its assessed {} quota language",
                repository.repository, repository.selection_language,
            ));
        }
        let license = seal.licenses.iter().find(|license| {
            license.repository == repository.repository && license.revision == repository.revision
        });
        if license.map(|license| license.repository_path.as_str())
            != Some(repository.license_path.as_str())
        {
            return Err(format!(
                "sealed repository {} does not preserve its declared license path",
                repository.repository
            ));
        }
        for context_path in &repository.context_paths {
            if !seal.context_sources.iter().any(|source| {
                source.repository == repository.repository
                    && source.revision == repository.revision
                    && source.repository_path == *context_path
            }) {
                return Err(format!(
                    "sealed repository {} is missing declared context {}",
                    repository.repository, context_path
                ));
            }
        }
    }
    Ok(())
}
