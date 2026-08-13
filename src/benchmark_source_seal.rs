use super::{
    SourceSelectionAudit, SourceSelectionCompositeAudit, SourceSnapshot,
    validate_source_selection_against_frame, validate_source_selection_component_against_frame,
    validate_source_selection_composite_audit,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[path = "benchmark_source_seal_validation.rs"]
mod validation;

pub use validation::validate_source_seal;

pub const SOURCE_SEAL_SCHEMA_VERSION: u32 = 3;
pub const SOURCE_CENSUS_CONTRACT_VERSION: &str = "sniff-source-census-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionDraft {
    pub schema_version: u32,
    pub selection_id: String,
    pub selected_at: String,
    pub selection_methodology: String,
    pub selection_attestation: String,
    pub selection_audit_sha256: String,
    pub selection_frame_sha256: String,
    pub repositories: Vec<SourceRepositoryDraft>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRepositoryDraft {
    pub repository: String,
    pub revision: String,
    pub license_path: String,
    pub selection_language: String,
    pub observed_method_count: usize,
    #[serde(default)]
    pub context_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealedMethod {
    pub method_id: String,
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub artifact_path: String,
    pub language: String,
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealedLicense {
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub artifact_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSourceSelectionComponent {
    pub selection_id: String,
    pub component_audit_sha256: String,
    pub frame_artifact_path: String,
    pub frame_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CompositeSourceFrameManifest {
    pub schema_version: u32,
    pub components: Vec<CompositeSourceFrameCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CompositeSourceFrameCommitment {
    pub selection_id: String,
    pub component_audit_sha256: String,
    pub frame_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSourceSeal {
    pub schema_version: u32,
    pub census_contract_version: String,
    pub selection_id: String,
    pub selected_at: String,
    pub selection_methodology: String,
    pub selection_attestation: String,
    pub selection_audit_sha256: String,
    pub selection_audit_artifact_path: String,
    pub selection_audit_artifact_sha256: String,
    pub selection_frame_artifact_path: String,
    pub selection_frame_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selection_components: Vec<SealedSourceSelectionComponent>,
    pub sources: Vec<SourceSnapshot>,
    pub context_sources: Vec<SourceSnapshot>,
    pub methods: Vec<SealedMethod>,
    pub licenses: Vec<SealedLicense>,
    pub seal_sha256: String,
}

impl BenchmarkSourceSeal {
    pub fn computed_seal_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            census_contract_version: &'a str,
            selection_id: &'a str,
            selected_at: &'a str,
            selection_methodology: &'a str,
            selection_attestation: &'a str,
            selection_audit_sha256: &'a str,
            selection_audit_artifact_path: &'a str,
            selection_audit_artifact_sha256: &'a str,
            selection_frame_artifact_path: &'a str,
            selection_frame_sha256: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            selection_components: Option<&'a [SealedSourceSelectionComponent]>,
            sources: &'a [SourceSnapshot],
            context_sources: &'a [SourceSnapshot],
            methods: &'a [SealedMethod],
            licenses: &'a [SealedLicense],
        }
        let bytes = serde_json::to_vec(&Commitment {
            schema_version: self.schema_version,
            census_contract_version: &self.census_contract_version,
            selection_id: &self.selection_id,
            selected_at: &self.selected_at,
            selection_methodology: &self.selection_methodology,
            selection_attestation: &self.selection_attestation,
            selection_audit_sha256: &self.selection_audit_sha256,
            selection_audit_artifact_path: &self.selection_audit_artifact_path,
            selection_audit_artifact_sha256: &self.selection_audit_artifact_sha256,
            selection_frame_artifact_path: &self.selection_frame_artifact_path,
            selection_frame_sha256: &self.selection_frame_sha256,
            selection_components: (!self.selection_components.is_empty())
                .then_some(self.selection_components.as_slice()),
            sources: &self.sources,
            context_sources: &self.context_sources,
            methods: &self.methods,
            licenses: &self.licenses,
        })
        .map_err(|error| format!("failed to serialize source-seal commitment: {error}"))?;
        Ok(sha256(&bytes))
    }
}

pub fn create_source_seal(
    draft: SourceSelectionDraft,
    selection_audit_bytes: &[u8],
    selection_frame_bytes: &[u8],
    checkout_root: &Path,
    output_path: &Path,
) -> Result<BenchmarkSourceSeal, String> {
    validate_draft(&draft)?;
    let audit: SourceSelectionAudit = serde_json::from_slice(selection_audit_bytes)
        .map_err(|error| format!("failed to parse source-selection audit: {error}"))?;
    validate_source_selection_against_frame(&audit, selection_frame_bytes)?;
    if audit.audit_sha256 != draft.selection_audit_sha256
        || audit.frame_sha256 != draft.selection_frame_sha256
        || audit.selected_repositories != draft.repositories
    {
        return Err("source-selection draft does not match its audited artifacts".to_string());
    }
    create_prevalidated_source_seal(
        draft,
        PendingSelectionArtifacts {
            audit_bytes: selection_audit_bytes,
            frame_bytes: selection_frame_bytes,
            frame_filename: "source-selection-frame.csv",
            components: Vec::new(),
        },
        checkout_root,
        output_path,
    )
}

struct PendingSelectionComponent<'a> {
    selection_id: String,
    component_audit_sha256: String,
    frame_sha256: String,
    frame_bytes: &'a [u8],
}

struct PendingSelectionArtifacts<'a> {
    audit_bytes: &'a [u8],
    frame_bytes: &'a [u8],
    frame_filename: &'a str,
    components: Vec<PendingSelectionComponent<'a>>,
}

pub fn create_composite_source_seal(
    selection_audit_bytes: &[u8],
    selection_frames: &[Vec<u8>],
    checkout_root: &Path,
    output_path: &Path,
) -> Result<BenchmarkSourceSeal, String> {
    let audit: SourceSelectionCompositeAudit = serde_json::from_slice(selection_audit_bytes)
        .map_err(|error| format!("failed to parse composite source-selection audit: {error}"))?;
    validate_source_selection_composite_audit(&audit)?;
    if selection_frames.len() != audit.components.len() {
        return Err(
            "composite source seal requires one ordered frame for every selection component"
                .to_string(),
        );
    }
    let mut pending = Vec::new();
    let mut manifest = CompositeSourceFrameManifest {
        schema_version: 1,
        components: Vec::new(),
    };
    for (component, frame) in audit.components.iter().zip(selection_frames) {
        validate_source_selection_component_against_frame(component, frame)?;
        manifest.components.push(CompositeSourceFrameCommitment {
            selection_id: component.policy.selection_id.clone(),
            component_audit_sha256: component.component_audit_sha256.clone(),
            frame_sha256: component.frame_sha256.clone(),
        });
        pending.push(PendingSelectionComponent {
            selection_id: component.policy.selection_id.clone(),
            component_audit_sha256: component.component_audit_sha256.clone(),
            frame_sha256: component.frame_sha256.clone(),
            frame_bytes: frame,
        });
    }
    let mut frame_manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("failed to serialize composite frame manifest: {error}"))?;
    frame_manifest_bytes.push(b'\n');
    let draft = SourceSelectionDraft {
        schema_version: SOURCE_SEAL_SCHEMA_VERSION,
        selection_id: audit.policy.selection_id.clone(),
        selected_at: audit.policy.selected_at.clone(),
        selection_methodology: format!(
            "Combined {} precommitted, independently ranked source-selection components.",
            audit.components.len()
        ),
        selection_attestation: audit.policy.attestation.clone(),
        selection_audit_sha256: audit.composite_audit_sha256.clone(),
        selection_frame_sha256: sha256(&frame_manifest_bytes),
        repositories: audit.selected_repositories.clone(),
    };
    create_prevalidated_source_seal(
        draft,
        PendingSelectionArtifacts {
            audit_bytes: selection_audit_bytes,
            frame_bytes: &frame_manifest_bytes,
            frame_filename: "source-selection-frames.json",
            components: pending,
        },
        checkout_root,
        output_path,
    )
}

fn create_prevalidated_source_seal(
    draft: SourceSelectionDraft,
    selection: PendingSelectionArtifacts<'_>,
    checkout_root: &Path,
    output_path: &Path,
) -> Result<BenchmarkSourceSeal, String> {
    validate_draft(&draft)?;
    if output_path.exists() {
        return Err(format!(
            "source-seal output already exists: {}",
            output_path.display()
        ));
    }
    let output_parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    if !output_parent.is_dir() {
        return Err(format!(
            "source-seal output parent does not exist: {}",
            output_parent.display()
        ));
    }
    let stem = output_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "source-seal output requires a file name".to_string())?;
    let artifact_directory = output_parent.join(format!("{stem}.sources"));
    fs::create_dir(&artifact_directory).map_err(|error| {
        format!(
            "failed to create source-seal artifact directory {}: {error}",
            artifact_directory.display()
        )
    })?;
    let mut manifest_created = false;
    let result = build_source_seal(
        draft,
        &selection,
        checkout_root,
        output_parent,
        &artifact_directory,
    )
    .and_then(|seal| {
        let mut bytes = serde_json::to_vec_pretty(&seal)
            .map_err(|error| format!("failed to serialize source seal: {error}"))?;
        bytes.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .map_err(|error| {
                format!(
                    "failed to create source-seal manifest {}: {error}",
                    output_path.display()
                )
            })?;
        manifest_created = true;
        use std::io::Write;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("failed to persist source seal: {error}"))?;
        Ok(seal)
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&artifact_directory);
        if manifest_created {
            let _ = fs::remove_file(output_path);
        }
    }
    result
}

fn build_source_seal(
    draft: SourceSelectionDraft,
    selection: &PendingSelectionArtifacts<'_>,
    checkout_root: &Path,
    output_parent: &Path,
    artifact_directory: &Path,
) -> Result<BenchmarkSourceSeal, String> {
    let selection_directory = artifact_directory.join("selection");
    let selection_audit_destination = selection_directory.join("source-selection-audit.json");
    let selection_frame_destination = selection_directory.join(selection.frame_filename);
    write_new_artifact(
        &selection_audit_destination,
        selection.audit_bytes,
        "source-selection audit",
    )?;
    let mut sealed_selection_components = Vec::new();
    for (index, component) in selection.components.iter().enumerate() {
        let destination = selection_directory.join(format!("component-{index}-frame.csv"));
        write_new_artifact(
            &destination,
            component.frame_bytes,
            "source-selection component frame",
        )?;
        sealed_selection_components.push(SealedSourceSelectionComponent {
            selection_id: component.selection_id.clone(),
            component_audit_sha256: component.component_audit_sha256.clone(),
            frame_artifact_path: portable_relative(output_parent, &destination)?,
            frame_sha256: component.frame_sha256.clone(),
        });
    }
    write_new_artifact(
        &selection_frame_destination,
        selection.frame_bytes,
        "source-selection frame",
    )?;
    let mut sources = Vec::new();
    let mut context_sources = Vec::new();
    let mut methods = Vec::new();
    let mut licenses = Vec::new();
    for (index, repository) in draft.repositories.iter().enumerate() {
        let local_root = resolve_checkout_root(checkout_root, &repository.repository)?;
        verify_git_revision(&local_root, &repository.revision)?;
        let destination_root = artifact_directory.join(format!("repository-{index}"));
        let source_destination = destination_root.join("source");
        let paths = crate::walker::walk(
            local_root
                .to_str()
                .ok_or_else(|| "source repository path is not UTF-8".to_string())?,
            &crate::config::ResolvedConfig::default(),
        )?;
        if paths.is_empty() {
            return Err(format!(
                "source repository {} has no supported source files",
                repository.repository
            ));
        }
        let method_start = methods.len();
        for path in paths {
            let path = PathBuf::from(path);
            reject_symlink(&path, "source file")?;
            let relative = repository_relative(&local_root, &path)?;
            let destination = source_destination.join(&relative);
            copy_committed_file(
                &local_root,
                &repository.revision,
                &relative,
                &destination,
                "source file",
            )?;
            let record = crate::parser::parse_file_checked(&destination.to_string_lossy())?;
            if record.language.is_empty() {
                return Err(format!(
                    "committed source is not supported by the census contract: {}",
                    relative.display()
                ));
            }
            let artifact_path = portable_relative(output_parent, &destination)?;
            let repository_path = portable_path(&relative)?;
            let source_hash = sha256(record.source.as_bytes());
            sources.push(SourceSnapshot {
                repository: repository.repository.clone(),
                revision: repository.revision.clone(),
                repository_path: repository_path.clone(),
                artifact_path: artifact_path.clone(),
                sha256: source_hash,
            });
            for method in record.methods {
                let method_source_hash = sha256(method.source.as_bytes());
                let method_id = sealed_method_identity(
                    &repository.repository,
                    &repository.revision,
                    &repository_path,
                    &method.name,
                    method.start_line,
                    method.end_line,
                    &method_source_hash,
                )?;
                methods.push(SealedMethod {
                    method_id,
                    repository: repository.repository.clone(),
                    revision: repository.revision.clone(),
                    repository_path: repository_path.clone(),
                    artifact_path: artifact_path.clone(),
                    language: method.language,
                    name: method.name,
                    start_line: method.start_line,
                    end_line: method.end_line,
                    source_sha256: method_source_hash,
                });
            }
        }
        let repository_methods = &methods[method_start..];
        if repository_methods.len() != repository.observed_method_count {
            return Err(format!(
                "source repository {} declared {} methods but the committed census found {}",
                repository.repository,
                repository.observed_method_count,
                repository_methods.len()
            ));
        }
        let dominant_language = dominant_method_language(
            repository_methods
                .iter()
                .map(|method| method.language.as_str()),
        )
        .expect("a positive repository method census has a dominant language");
        if dominant_language != repository.selection_language.to_ascii_lowercase() {
            return Err(format!(
                "source repository {} was assigned to {} but its dominant eligible-method language is {dominant_language}",
                repository.repository, repository.selection_language,
            ));
        }
        let context_paths = selected_context_paths(&local_root, &repository.context_paths)?;
        let context_destination = destination_root.join("context");
        for path in context_paths {
            reject_symlink(&path, "context file")?;
            let relative = repository_relative(&local_root, &path)?;
            let destination = context_destination.join(&relative);
            copy_committed_file(
                &local_root,
                &repository.revision,
                &relative,
                &destination,
                "context file",
            )?;
            let bytes = fs::read(&destination)
                .map_err(|error| format!("failed to read sealed context file: {error}"))?;
            String::from_utf8(bytes.clone()).map_err(|_| {
                format!(
                    "declared review context must be UTF-8 text: {}",
                    relative.display()
                )
            })?;
            context_sources.push(SourceSnapshot {
                repository: repository.repository.clone(),
                revision: repository.revision.clone(),
                repository_path: portable_path(&relative)?,
                artifact_path: portable_relative(output_parent, &destination)?,
                sha256: sha256(&bytes),
            });
        }
        let license_relative = safe_relative_path(&repository.license_path)?;
        let license_source = local_root.join(&license_relative);
        reject_symlink(&license_source, "license file")?;
        if !license_source.is_file() {
            return Err(format!(
                "declared license file does not exist: {}",
                license_source.display()
            ));
        }
        let license_destination = destination_root.join("license").join(
            license_relative
                .file_name()
                .ok_or_else(|| "license path has no file name".to_string())?,
        );
        copy_committed_file(
            &local_root,
            &repository.revision,
            &license_relative,
            &license_destination,
            "license file",
        )?;
        licenses.push(SealedLicense {
            repository: repository.repository.clone(),
            revision: repository.revision.clone(),
            repository_path: portable_path(&license_relative)?,
            artifact_path: portable_relative(output_parent, &license_destination)?,
            sha256: sha256(
                &fs::read(&license_destination)
                    .map_err(|error| format!("failed to read sealed license: {error}"))?,
            ),
        });
        // Catch checkout or index changes that happen while the repository is copied.
        verify_git_revision(&local_root, &repository.revision)?;
    }
    sources.sort_by(|left, right| {
        (&left.repository, &left.revision, &left.repository_path).cmp(&(
            &right.repository,
            &right.revision,
            &right.repository_path,
        ))
    });
    context_sources.sort_by(|left, right| {
        (&left.repository, &left.revision, &left.repository_path).cmp(&(
            &right.repository,
            &right.revision,
            &right.repository_path,
        ))
    });
    methods.sort_by(|left, right| left.method_id.cmp(&right.method_id));
    licenses.sort_by(|left, right| {
        (&left.repository, &left.revision).cmp(&(&right.repository, &right.revision))
    });
    let mut seal = BenchmarkSourceSeal {
        schema_version: SOURCE_SEAL_SCHEMA_VERSION,
        census_contract_version: SOURCE_CENSUS_CONTRACT_VERSION.to_string(),
        selection_id: draft.selection_id,
        selected_at: draft.selected_at,
        selection_methodology: draft.selection_methodology,
        selection_attestation: draft.selection_attestation,
        selection_audit_sha256: draft.selection_audit_sha256,
        selection_audit_artifact_path: portable_relative(
            output_parent,
            &selection_audit_destination,
        )?,
        selection_audit_artifact_sha256: sha256(selection.audit_bytes),
        selection_frame_artifact_path: portable_relative(
            output_parent,
            &selection_frame_destination,
        )?,
        selection_frame_sha256: draft.selection_frame_sha256,
        selection_components: sealed_selection_components,
        sources,
        context_sources,
        methods,
        licenses,
        seal_sha256: String::new(),
    };
    seal.seal_sha256 = seal.computed_seal_sha256()?;
    validate_source_seal(&seal, output_parent)?;
    Ok(seal)
}

fn validate_draft(draft: &SourceSelectionDraft) -> Result<(), String> {
    if draft.schema_version != SOURCE_SEAL_SCHEMA_VERSION {
        return Err(format!(
            "source selection schema_version must be {SOURCE_SEAL_SCHEMA_VERSION}"
        ));
    }
    require_text("selection_id", &draft.selection_id)?;
    require_text("selected_at", &draft.selected_at)?;
    require_text("selection_methodology", &draft.selection_methodology)?;
    require_text("selection_attestation", &draft.selection_attestation)?;
    require_sha256("selection audit SHA-256", &draft.selection_audit_sha256)?;
    require_sha256("selection frame SHA-256", &draft.selection_frame_sha256)?;
    if draft.repositories.is_empty() {
        return Err("source selection requires at least one repository".to_string());
    }
    let mut identities = HashSet::new();
    for repository in &draft.repositories {
        require_text("repository", &repository.repository)?;
        require_revision(&repository.revision)?;
        safe_relative_path(&repository.license_path)?;
        require_supported_language(&repository.selection_language)?;
        if repository.observed_method_count == 0 {
            return Err("selected repository method count must be positive".to_string());
        }
        let mut context_paths = HashSet::new();
        for path in &repository.context_paths {
            let path = safe_relative_path(path)?;
            if !context_paths.insert(path) {
                return Err(format!(
                    "source selection repeats context path in {}",
                    repository.repository
                ));
            }
        }
        if !identities.insert((repository.repository.as_str(), repository.revision.as_str())) {
            return Err(format!(
                "source selection repeats {} at {}",
                repository.repository, repository.revision
            ));
        }
    }
    Ok(())
}

fn require_supported_language(value: &str) -> Result<(), String> {
    if ["go", "javascript", "kotlin", "python", "rust", "typescript"]
        .contains(&value.trim().to_ascii_lowercase().as_str())
    {
        Ok(())
    } else {
        Err(format!("unsupported selected repository language: {value}"))
    }
}

fn selected_context_paths(root: &Path, declared: &[String]) -> Result<Vec<PathBuf>, String> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        format!(
            "failed to resolve review-context repository root {}: {error}",
            root.display()
        )
    })?;
    let mut paths = crate::walker::walk_evidence(
        root.to_str()
            .ok_or_else(|| "source repository path is not UTF-8".to_string())?,
        &crate::config::ResolvedConfig::default(),
    )?
    .into_iter()
    .map(PathBuf::from)
    .collect::<Vec<_>>();
    for name in [
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "go.mod",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "pom.xml",
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
    ] {
        let path = root.join(name);
        if path.is_file() {
            paths.push(path);
        }
    }
    for value in declared {
        let relative = safe_relative_path(value)?;
        let path = root.join(&relative);
        if !path.is_file() {
            return Err(format!(
                "declared review context does not exist: {}",
                path.display()
            ));
        }
        paths.push(path);
    }
    let mut unique = BTreeMap::new();
    for path in paths {
        let canonical = fs::canonicalize(&path).map_err(|error| {
            format!(
                "failed to resolve review context {}: {error}",
                path.display()
            )
        })?;
        let relative = repository_relative(&canonical_root, &canonical)?;
        let identity = portable_path(&relative)?;
        unique.entry(identity).or_insert(canonical);
    }
    Ok(unique.into_values().collect())
}

fn verify_git_revision(root: &Path, expected_revision: &str) -> Result<(), String> {
    let top = git(root, &["rev-parse", "--show-toplevel"])?;
    let canonical_top = fs::canonicalize(top.trim())
        .map_err(|error| format!("failed to resolve Git repository root: {error}"))?;
    if canonical_top != root {
        return Err(format!(
            "selected checkout must be the Git repository root: {}",
            root.display()
        ));
    }
    let actual = git(root, &["rev-parse", "HEAD"])?;
    if !actual.trim().eq_ignore_ascii_case(expected_revision) {
        return Err(format!(
            "source repository revision mismatch: expected {expected_revision}, found {}",
            actual.trim()
        ));
    }
    let status = git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if !status.trim().is_empty() {
        return Err(format!(
            "source repository must be clean before sealing: {}",
            root.display()
        ));
    }
    let sparse_checkout = git(
        root,
        &[
            "config",
            "--bool",
            "--default",
            "false",
            "core.sparseCheckout",
        ],
    )?;
    if sparse_checkout.trim().eq_ignore_ascii_case("true") {
        return Err(format!(
            "source repository must not use sparse checkout when sealing: {}",
            root.display()
        ));
    }
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("source sealing requires git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed for {}: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_string())
}

fn copy_committed_file(
    root: &Path,
    revision: &str,
    repository_path: &Path,
    destination: &Path,
    label: &str,
) -> Result<(), String> {
    let repository_path = portable_path(repository_path)?;
    let object = format!("{revision}:{repository_path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "blob", &object])
        .output()
        .map_err(|error| format!("source sealing requires git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "declared revision does not contain {label} {repository_path}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create sealed source directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "failed to create sealed {label} {}: {error}",
                destination.display()
            )
        })?;
    use std::io::Write;
    file.write_all(&output.stdout)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist sealed {label}: {error}"))
}

pub(crate) fn sealed_method_identity(
    repository: &str,
    revision: &str,
    repository_path: &str,
    name: &str,
    start_line: usize,
    end_line: usize,
    source_sha256: &str,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        repository,
        revision,
        repository_path,
        name,
        start_line,
        end_line,
        source_sha256,
    ))
    .map_err(|error| format!("failed to serialize sealed method identity: {error}"))?;
    Ok(sha256(&bytes))
}

pub(crate) fn dominant_method_language<'a>(
    languages: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for language in languages {
        *counts.entry(language.to_ascii_lowercase()).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(
            |(left_language, left_count), (right_language, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_language.cmp(left_language))
            },
        )
        .map(|(language, _)| language)
}

fn resolve_checkout_root(checkout_root: &Path, repository: &str) -> Result<PathBuf, String> {
    let identity = repository
        .strip_prefix("https://github.com/")
        .ok_or_else(|| {
            format!("selected repository is not a canonical GitHub URL: {repository}")
        })?;
    let parts = identity.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(format!(
            "selected repository has an invalid GitHub identity: {repository}"
        ));
    }
    let canonical_checkout_root = fs::canonicalize(checkout_root).map_err(|error| {
        format!(
            "failed to resolve checkout root {}: {error}",
            checkout_root.display()
        )
    })?;
    let joined = canonical_checkout_root.join(parts[0]).join(parts[1]);
    let resolved = fs::canonicalize(&joined).map_err(|error| {
        format!(
            "failed to resolve selected repository {}: {error}",
            joined.display()
        )
    })?;
    if !resolved.starts_with(&canonical_checkout_root) {
        return Err(format!(
            "selected repository checkout escapes the checkout root: {}",
            resolved.display()
        ));
    }
    Ok(resolved)
}

fn repository_relative(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!(
            "failed to resolve selected source {}: {error}",
            path.display()
        )
    })?;
    canonical
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| {
            format!(
                "selected source escapes repository root: {}",
                path.display()
            )
        })
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "source sealing refuses symlinked {label}: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_artifact(root: &Path, path: &str, expected: &str, label: &str) -> Result<(), String> {
    require_sha256(&format!("{label} sha256"), expected)?;
    let relative = safe_relative_path(path)?;
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        format!(
            "failed to resolve source-seal root {}: {error}",
            root.display()
        )
    })?;
    let artifact = fs::canonicalize(root.join(relative))
        .map_err(|error| format!("failed to resolve {label} {path}: {error}"))?;
    if !artifact.starts_with(&canonical_root) {
        return Err(format!("{label} escapes the source-seal bundle: {path}"));
    }
    reject_symlink(&artifact, label)?;
    let bytes = fs::read(&artifact)
        .map_err(|error| format!("failed to read {label} {}: {error}", artifact.display()))?;
    let actual = sha256(&bytes);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "{label} hash mismatch for {path}; expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn read_artifact(root: &Path, path: &str) -> Result<Vec<u8>, String> {
    let relative = safe_relative_path(path)?;
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        format!(
            "failed to resolve source-seal root {}: {error}",
            root.display()
        )
    })?;
    let artifact = fs::canonicalize(root.join(relative))
        .map_err(|error| format!("failed to resolve source-seal artifact {path}: {error}"))?;
    if !artifact.starts_with(&canonical_root) {
        return Err(format!("source-seal artifact escapes its bundle: {path}"));
    }
    reject_symlink(&artifact, "source-seal artifact")?;
    fs::read(&artifact).map_err(|error| format!("failed to read {path}: {error}"))
}

fn write_new_artifact(destination: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create sealed {label} directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "failed to create sealed {label} {}: {error}",
                destination.display()
            )
        })?;
    use std::io::Write;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist sealed {label}: {error}"))
}

fn portable_relative(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("sealed artifact escapes output bundle: {}", path.display()))?;
    portable_path(relative)
}

fn portable_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("benchmark path is not UTF-8: {}", path.display()))?
        .replace('\\', "/");
    safe_relative_path(&value)?;
    Ok(value)
}

fn safe_relative_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "benchmark artifact path must be safe and relative: {value}"
        ));
    }
    Ok(path.to_path_buf())
}

fn require_revision(value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(
            "source revision must be a complete 40- or 64-character Git object ID".to_string(),
        );
    }
    Ok(())
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 64-character SHA-256 digest"));
    }
    Ok(())
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) fn write_test_source_seal(
    root: &Path,
    sources: &[SourceSnapshot],
) -> (
    String,
    String,
    std::collections::HashMap<String, Vec<String>>,
) {
    let mut methods = Vec::new();
    let mut by_artifact = std::collections::HashMap::<String, Vec<String>>::new();
    for source in sources {
        let artifact = root.join(&source.artifact_path);
        let record = crate::parser::parse_file_checked(&artifact.to_string_lossy()).unwrap();
        assert!(!record.language.is_empty());
        for method in record.methods {
            let source_sha256 = sha256(method.source.as_bytes());
            let method_id = sealed_method_identity(
                &source.repository,
                &source.revision,
                &source.repository_path,
                &method.name,
                method.start_line,
                method.end_line,
                &source_sha256,
            )
            .unwrap();
            by_artifact
                .entry(source.artifact_path.clone())
                .or_default()
                .push(method_id.clone());
            methods.push(SealedMethod {
                method_id,
                repository: source.repository.clone(),
                revision: source.revision.clone(),
                repository_path: source.repository_path.clone(),
                artifact_path: source.artifact_path.clone(),
                language: method.language,
                name: method.name,
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256,
            });
        }
    }
    methods.sort_by(|left, right| left.method_id.cmp(&right.method_id));
    let mut repositories = sources
        .iter()
        .map(|source| (source.repository.clone(), source.revision.clone()))
        .collect::<Vec<_>>();
    repositories.sort();
    repositories.dedup();
    let licenses = repositories
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, (repository, revision))| {
            let artifact_path = format!("seal-license-{index}.txt");
            let text = format!("test license for {repository} at {revision}\n");
            fs::write(root.join(&artifact_path), &text).unwrap();
            SealedLicense {
                repository,
                revision,
                repository_path: "LICENSE".to_string(),
                artifact_path,
                sha256: sha256(text.as_bytes()),
            }
        })
        .collect::<Vec<_>>();
    let selected_repositories = repositories
        .into_iter()
        .map(|(repository, revision)| {
            let repository_methods = methods
                .iter()
                .filter(|method| method.repository == repository && method.revision == revision)
                .collect::<Vec<_>>();
            SourceRepositoryDraft {
                repository,
                revision,
                license_path: "LICENSE".to_string(),
                selection_language: dominant_method_language(
                    repository_methods
                        .iter()
                        .map(|method| method.language.as_str()),
                )
                .unwrap(),
                observed_method_count: repository_methods.len(),
                context_paths: Vec::new(),
            }
        })
        .collect::<Vec<_>>();
    let (draft, selection_audit_bytes, selection_frame_bytes) =
        super::source_selection::test_selection_artifacts(selected_repositories);
    let selection_audit_artifact_path = "source-selection-audit.json".to_string();
    let selection_frame_artifact_path = "source-selection-frame.csv".to_string();
    fs::write(
        root.join(&selection_audit_artifact_path),
        &selection_audit_bytes,
    )
    .unwrap();
    fs::write(
        root.join(&selection_frame_artifact_path),
        &selection_frame_bytes,
    )
    .unwrap();
    let mut seal = BenchmarkSourceSeal {
        schema_version: SOURCE_SEAL_SCHEMA_VERSION,
        census_contract_version: SOURCE_CENSUS_CONTRACT_VERSION.to_string(),
        selection_id: draft.selection_id,
        selected_at: draft.selected_at,
        selection_methodology: draft.selection_methodology,
        selection_attestation: draft.selection_attestation,
        selection_audit_sha256: draft.selection_audit_sha256,
        selection_audit_artifact_path,
        selection_audit_artifact_sha256: sha256(&selection_audit_bytes),
        selection_frame_artifact_path,
        selection_frame_sha256: draft.selection_frame_sha256,
        selection_components: Vec::new(),
        sources: sources.to_vec(),
        context_sources: Vec::new(),
        methods,
        licenses,
        seal_sha256: String::new(),
    };
    seal.seal_sha256 = seal.computed_seal_sha256().unwrap();
    validate_source_seal(&seal, root).unwrap();
    let artifact_path = "blind-source-seal.json".to_string();
    let mut bytes = serde_json::to_vec_pretty(&seal).unwrap();
    bytes.push(b'\n');
    fs::write(root.join(&artifact_path), &bytes).unwrap();
    (artifact_path, sha256(&bytes), by_artifact)
}

#[cfg(test)]
#[path = "benchmark_source_seal_tests.rs"]
mod tests;
