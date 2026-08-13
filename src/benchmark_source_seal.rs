use super::SourceSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const SOURCE_SEAL_SCHEMA_VERSION: u32 = 1;
pub const SOURCE_CENSUS_CONTRACT_VERSION: &str = "sniff-source-census-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionDraft {
    pub schema_version: u32,
    pub selection_id: String,
    pub selected_at: String,
    pub selection_methodology: String,
    pub selection_attestation: String,
    pub repositories: Vec<SourceRepositoryDraft>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRepositoryDraft {
    pub repository: String,
    pub revision: String,
    pub local_path: String,
    pub license_path: String,
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
pub struct BenchmarkSourceSeal {
    pub schema_version: u32,
    pub census_contract_version: String,
    pub selection_id: String,
    pub selected_at: String,
    pub selection_methodology: String,
    pub selection_attestation: String,
    pub sources: Vec<SourceSnapshot>,
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
            sources: &'a [SourceSnapshot],
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
            sources: &self.sources,
            methods: &self.methods,
            licenses: &self.licenses,
        })
        .map_err(|error| format!("failed to serialize source-seal commitment: {error}"))?;
        Ok(sha256(&bytes))
    }
}

pub fn create_source_seal(
    draft: SourceSelectionDraft,
    draft_root: &Path,
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
    let result =
        build_source_seal(draft, draft_root, output_parent, &artifact_directory).and_then(|seal| {
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
    for source in &seal.sources {
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
    }
    let source_artifacts = seal
        .sources
        .iter()
        .map(|source| (source.artifact_path.as_str(), source))
        .collect::<std::collections::HashMap<_, _>>();
    let mut method_ids = HashSet::new();
    for method in &seal.methods {
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
    let expected = seal.computed_seal_sha256()?;
    if !seal.seal_sha256.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "source seal commitment does not match its contents; expected {expected}"
        ));
    }
    Ok(())
}

fn build_source_seal(
    draft: SourceSelectionDraft,
    draft_root: &Path,
    output_parent: &Path,
    artifact_directory: &Path,
) -> Result<BenchmarkSourceSeal, String> {
    let mut sources = Vec::new();
    let mut methods = Vec::new();
    let mut licenses = Vec::new();
    for (index, repository) in draft.repositories.iter().enumerate() {
        let local_root = resolve_local_root(draft_root, &repository.local_path)?;
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
        sources,
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
    if draft.repositories.is_empty() {
        return Err("source selection requires at least one repository".to_string());
    }
    let mut identities = HashSet::new();
    for repository in &draft.repositories {
        require_text("repository", &repository.repository)?;
        require_revision(&repository.revision)?;
        require_text("local_path", &repository.local_path)?;
        safe_relative_path(&repository.license_path)?;
        if !identities.insert((repository.repository.as_str(), repository.revision.as_str())) {
            return Err(format!(
                "source selection repeats {} at {}",
                repository.repository, repository.revision
            ));
        }
    }
    Ok(())
}

fn verify_git_revision(root: &Path, expected_revision: &str) -> Result<(), String> {
    let top = git(root, &["rev-parse", "--show-toplevel"])?;
    let canonical_top = fs::canonicalize(top.trim())
        .map_err(|error| format!("failed to resolve Git repository root: {error}"))?;
    if canonical_top != root {
        return Err(format!(
            "source selection local_path must be the Git repository root: {}",
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

fn resolve_local_root(draft_root: &Path, value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        draft_root.join(path)
    };
    fs::canonicalize(&joined).map_err(|error| {
        format!(
            "failed to resolve selected repository {}: {error}",
            joined.display()
        )
    })
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
            "{label} hash mismatch for {path}; expected {actual}"
        ));
    }
    Ok(())
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
        .into_iter()
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
    let mut seal = BenchmarkSourceSeal {
        schema_version: SOURCE_SEAL_SCHEMA_VERSION,
        census_contract_version: SOURCE_CENSUS_CONTRACT_VERSION.to_string(),
        selection_id: "test-selection".to_string(),
        selected_at: "2026-08-12T00:00:00Z".to_string(),
        selection_methodology: "Fixture sources selected before fixture labels.".to_string(),
        selection_attestation: "No fixture output was inspected before selection.".to_string(),
        sources: sources.to_vec(),
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
