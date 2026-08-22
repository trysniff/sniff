use crate::semantic_indexer_installation::{InstalledIndexer, SemanticIndexerStore};
use crate::semantic_indexer_manifest::{
    DownloadArchive, IndexerInstallSource, PinnedIndexer, pinned_indexer,
};
use crate::types::FileRecord;
use flate2::read::GzDecoder;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use zip::ZipArchive;

#[path = "semantic_indexer_go_installer.rs"]
mod go_installer;

#[path = "semantic_indexer_scip_java_patch.rs"]
mod scip_java_patch;

#[path = "semantic_indexer_scip_java_repacker_source.rs"]
mod scip_java_repacker_source;

#[cfg(windows)]
#[path = "semantic_indexer_scip_java_windows.rs"]
mod scip_java_windows;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) async fn install_required_indexers(
    files: &[FileRecord],
    force: bool,
) -> Result<Vec<InstalledIndexer>, String> {
    let store = SemanticIndexerStore::for_user()?;
    let mut installed = Vec::new();
    for kind in crate::semantic_indexer_manifest::required_indexers(files) {
        let spec = pinned_indexer(kind)?;
        installed.push(install_one(&store, spec, force).await?);
    }
    Ok(installed)
}

async fn install_one(
    store: &SemanticIndexerStore,
    spec: PinnedIndexer,
    force: bool,
) -> Result<InstalledIndexer, String> {
    if let Ok(installed) = store.verify(spec) {
        return Ok(installed);
    }
    let final_root = store.installation_root(spec);
    prepare_existing_installation(&final_root, force, spec)?;
    let staging_root = create_staging_directory(&final_root, spec)?;
    let result = async {
        install_source(spec, &staging_root).await?;
        store.seal_at(spec, &staging_root)?;
        store.promote_staged(spec, &staging_root)
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging_root);
    }
    result
}

fn prepare_existing_installation(
    final_root: &Path,
    force: bool,
    spec: PinnedIndexer,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(final_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect existing {} installation {}: {error}",
                spec.display_name,
                final_root.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "refusing to replace non-directory {} installation {}",
            spec.display_name,
            final_root.display()
        ));
    }
    if !force {
        return Err(format!(
            "{} installation exists but is invalid at {}; rerun with --force",
            spec.display_name,
            final_root.display()
        ));
    }
    fs::remove_dir_all(final_root).map_err(|error| {
        format!(
            "failed to remove invalid {} installation {}: {error}",
            spec.display_name,
            final_root.display()
        )
    })
}

fn create_staging_directory(final_root: &Path, spec: PinnedIndexer) -> Result<PathBuf, String> {
    let parent = final_root.parent().ok_or_else(|| {
        format!(
            "semantic indexer installation has no parent: {}",
            final_root.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create semantic indexer directory {}: {error}",
            parent.display()
        )
    })?;
    for sequence in 0..100_u32 {
        let candidate = parent.join(format!(".{}.staging-{sequence}", spec.version));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to create {} staging directory {}: {error}",
                    spec.display_name,
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "could not allocate a staging directory for {}",
        spec.display_name
    ))
}

async fn install_source(spec: PinnedIndexer, root: &Path) -> Result<(), String> {
    match spec.source {
        IndexerInstallSource::Npm { package, .. } => install_npm(spec, root, package).await,
        IndexerInstallSource::GoModule {
            module,
            package,
            commit,
        } => go_installer::install(spec, root, module, package, commit).await,
        IndexerInstallSource::Download(download) => install_download(spec, root, download).await,
    }?;
    if spec.kind == crate::semantic_indexer_manifest::SemanticIndexerKind::Kotlin {
        scip_java_patch::patch_kotlin_annotation_references(root, spec).await?;
    }
    #[cfg(windows)]
    if spec.kind == crate::semantic_indexer_manifest::SemanticIndexerKind::Kotlin {
        scip_java_windows::patch_scip_java_windows(root, spec)?;
    }
    Ok(())
}

async fn install_npm(spec: PinnedIndexer, root: &Path, package: &str) -> Result<(), String> {
    let package_spec = format!("{package}@{}", spec.version);
    let npm = executable_name("npm");
    let mut view_command = Command::new(&npm);
    view_command
        .arg("view")
        .arg(&package_spec)
        .arg("dist.integrity")
        .arg("--json");
    let view = run_command(&mut view_command, "npm package integrity lookup").await?;
    let actual = parse_json_string(&view, "npm integrity")?;
    let expected = format!(
        "sha512-{}",
        match spec.source {
            IndexerInstallSource::Npm {
                integrity_sha512, ..
            } => integrity_sha512,
            _ => unreachable!(),
        }
    );
    if actual.trim() != expected {
        return Err(format!(
            "{} npm integrity mismatch; expected {}, received {}",
            spec.display_name,
            expected,
            actual.trim()
        ));
    }
    let mut install_command = Command::new(&npm);
    install_command
        .arg("install")
        .arg("--prefix")
        .arg(root)
        .args([
            "--ignore-scripts",
            "--no-bin-links",
            "--no-package-lock",
            "--omit=dev",
        ])
        .arg(&package_spec);
    run_command(&mut install_command, "npm package installation")
        .await
        .map(|_| ())
}

async fn install_download(
    spec: PinnedIndexer,
    root: &Path,
    download: crate::semantic_indexer_manifest::IndexerDownload,
) -> Result<(), String> {
    let client = Client::new();
    let response = client
        .get(download.url)
        .send()
        .await
        .map_err(|error| format!("failed to download {}: {error}", spec.display_name))?
        .error_for_status()
        .map_err(|error| format!("download failed for {}: {error}", spec.display_name))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_DOWNLOAD_BYTES)
    {
        return Err(format!(
            "{} download exceeds {} bytes",
            spec.display_name, MAX_DOWNLOAD_BYTES
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("failed to read {} download: {error}", spec.display_name))?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(format!(
            "{} download exceeds {} bytes",
            spec.display_name, MAX_DOWNLOAD_BYTES
        ));
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != download.sha256 {
        return Err(format!(
            "{} download checksum mismatch; expected {}, received {}",
            spec.display_name, download.sha256, actual
        ));
    }
    match download.archive {
        DownloadArchive::Raw => write_binary(root, &spec.entrypoint_relative_path(), &bytes),
        DownloadArchive::Gzip => {
            let mut decoder = GzDecoder::new(Cursor::new(bytes));
            let mut unpacked = Vec::new();
            decoder
                .read_to_end(&mut unpacked)
                .map_err(|error| format!("failed to unpack {}: {error}", spec.display_name))?;
            write_binary(root, &spec.entrypoint_relative_path(), &unpacked)
        }
        DownloadArchive::Zip => unpack_zip(root, spec, &bytes),
    }
}

fn unpack_zip(root: &Path, spec: PinnedIndexer, bytes: &[u8]) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("failed to open {} archive: {error}", spec.display_name))?;
    let mut expected = vec![spec.entrypoint_relative_path()];
    expected.extend(spec.companion_relative_paths());
    let expected = expected
        .into_iter()
        .map(|relative| {
            let name = relative
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("{} has an invalid runtime file name", spec.display_name))?;
            Ok((name.to_string(), relative))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?;
    let mut found = std::collections::BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect {} archive: {error}", spec.display_name))?;
        if entry.is_dir() {
            continue;
        }
        let name = Path::new(entry.name());
        let file_name = name
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                format!(
                    "{} archive contains an invalid entry name",
                    spec.display_name
                )
            })?;
        if name.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(format!(
                "{} archive contains an unsafe entry {}",
                spec.display_name,
                entry.name()
            ));
        }
        let Some(relative) = expected.get(file_name) else {
            continue;
        };
        if !found.insert(file_name.to_string()) {
            return Err(format!(
                "{} archive contains duplicate runtime file {}",
                spec.display_name, file_name
            ));
        }
        let mut unpacked = Vec::new();
        entry
            .read_to_end(&mut unpacked)
            .map_err(|error| format!("failed to unpack {}: {error}", spec.display_name))?;
        write_binary(root, relative, &unpacked)?;
    }
    let missing = expected
        .keys()
        .filter(|name| !found.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        Err(format!(
            "{} archive did not contain required runtime files: {}",
            spec.display_name,
            missing.join(", ")
        ))
    } else {
        Ok(())
    }
}

fn write_binary(root: &Path, relative: &Path, bytes: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| format!("binary path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create binary directory {}: {error}",
            parent.display()
        )
    })?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(unix)]
    options.mode(0o755);
    let mut file = options
        .open(&path)
        .map_err(|error| format!("failed to write binary {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to sync binary {}: {error}", path.display()))
}

async fn run_command(command: &mut Command, label: &str) -> Result<Vec<u8>, String> {
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "{label} timed out after {} seconds",
                COMMAND_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("{label} could not start: {error}"))?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "{label} failed with {}; output: {}",
            output.status,
            compact_output(&combined)
        ))
    }
}

async fn run_json_command(command: &mut Command, label: &str) -> Result<Vec<u8>, String> {
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "{label} timed out after {} seconds",
                COMMAND_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("{label} could not start: {error}"))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    Err(format!(
        "{label} failed with {}; output: {}",
        output.status,
        compact_output(&combined)
    ))
}

fn parse_json_string(bytes: &[u8], label: &str) -> Result<String, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("{label} returned invalid JSON: {error}"))?;
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{label} did not return a JSON string"))
}

fn compact_output(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() > 400 {
        format!("{}...", &compact[..400])
    } else {
        compact
    }
}

fn executable_name(name: &str) -> OsString {
    if cfg!(windows) {
        OsString::from(format!("{name}.cmd"))
    } else {
        OsString::from(name)
    }
}

#[cfg(test)]
#[path = "tests/semantic_indexer_installer.rs"]
mod tests;
