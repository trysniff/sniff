use crate::semantic_indexer_installation::{InstalledIndexer, SemanticIndexerStore};
use crate::semantic_indexer_manifest::{
    DownloadArchive, IndexerInstallSource, PinnedIndexer, pinned_indexer,
};
use crate::types::FileRecord;
use flate2::read::GzDecoder;
use reqwest::Client;
use serde_json::{Deserializer, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use zip::ZipArchive;

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
        } => install_go(spec, root, module, package, commit).await,
        IndexerInstallSource::Download(download) => install_download(spec, root, download).await,
    }?;
    #[cfg(windows)]
    if spec.kind == crate::semantic_indexer_manifest::SemanticIndexerKind::Kotlin {
        patch_scip_java_windows(root, spec)?;
    }
    Ok(())
}

#[cfg(windows)]
const WINDOWS_SCIP_JAVA_WRITER: &str = r#"package org.scip_code.scip_java.aggregator;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.scip_code.scip.Index;

public class ScipWriter implements AutoCloseable {
  private final Path tmp;
  private final ScipOutputStream output;
  private final ScipAggregatorOptions options;

  public ScipWriter(ScipAggregatorOptions options) throws IOException {
    this.tmp = Files.createTempFile("scip-aggregator", "index.scip");
    this.output = new ScipOutputStream(new BufferedOutputStream(Files.newOutputStream(tmp)));
    this.options = options;
  }

  public void emitTyped(Index index) {
    this.output.write(index.toByteArray());
  }

  public void build() throws IOException {
    close();
    Files.move(tmp, options.output(), StandardCopyOption.REPLACE_EXISTING);
  }

  @Override
  public void close() throws IOException {
    output.flush();
  }

  public void flush() {
    try {
      output.flush();
    } catch (IOException e) {
      options.reporter().error(e);
    }
  }
}
"#;

#[cfg(windows)]
fn patch_scip_java_windows(root: &Path, spec: PinnedIndexer) -> Result<(), String> {
    let entrypoint = root.join(spec.entrypoint_relative_path());
    let patch_root = std::env::temp_dir().join(format!(
        "sniff-scip-java-patch-{}-{}",
        std::process::id(),
        unique_patch_suffix()
    ));
    fs::create_dir_all(&patch_root).map_err(|error| {
        format!(
            "failed to create temporary scip-java patch directory {}: {error}",
            patch_root.display()
        )
    })?;
    let result: Result<(), String> = (|| {
        let source = patch_root.join("ScipWriter.java");
        fs::write(&source, WINDOWS_SCIP_JAVA_WRITER).map_err(|error| {
            format!("failed to write the Windows scip-java compatibility source: {error}")
        })?;

        let aggregator_relative =
            Path::new("coursier/bootstrap/launcher/jars/scip-aggregator-0.13.1.jar");
        let bindings_relative =
            Path::new("coursier/bootstrap/launcher/jars/scip-java-bindings-0.9.0.jar");
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&patch_root)
                .arg("xf")
                .arg(&entrypoint),
            "extract scip-java runtime jars",
        )?;

        let classes = patch_root.join("classes");
        fs::create_dir_all(&classes).map_err(|error| {
            format!(
                "failed to create scip-java patch classes directory {}: {error}",
                classes.display()
            )
        })?;
        let classpath = format!(
            "{};{};{}",
            patch_root
                .join("coursier/bootstrap/launcher/jars/*")
                .display(),
            patch_root.join(aggregator_relative).display(),
            patch_root.join(bindings_relative).display()
        );
        run_patch_tool(
            std::process::Command::new("javac")
                .current_dir(&patch_root)
                .arg("-cp")
                .arg(&classpath)
                .arg("-d")
                .arg(&classes)
                .arg(&source),
            "compile scip-java Windows compatibility patch",
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&patch_root)
                .arg("uf")
                .arg(aggregator_relative)
                .arg("-C")
                .arg(&classes)
                .arg("org/scip_code/scip_java/aggregator/ScipWriter.class"),
            "update scip-java aggregator jar",
        )?;
        run_patch_tool(
            std::process::Command::new("jar")
                .current_dir(&patch_root)
                .arg("uf")
                .arg(&entrypoint)
                .arg(aggregator_relative),
            "update scip-java runtime jar",
        )?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&patch_root);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.to_string()),
        (Err(patch_error), Err(cleanup_error)) => Err(format!(
            "{patch_error}; additionally failed to remove patch directory {}: {cleanup_error}",
            patch_root.display()
        )),
    }
}

#[cfg(windows)]
fn run_patch_tool(command: &mut std::process::Command, label: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("{label} could not start: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{label} failed with {}: {}",
            output.status,
            compact_output(&output.stderr)
        ))
    }
}

#[cfg(windows)]
fn unique_patch_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
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

async fn install_go(
    spec: PinnedIndexer,
    root: &Path,
    module: &str,
    package: &str,
    commit: &str,
) -> Result<(), String> {
    let module_spec = format!("{module}@v{}", spec.version);
    let mut metadata_command = Command::new(go_executable_name());
    metadata_command
        .args(["mod", "download", "-json"])
        .arg(&module_spec);
    let metadata = run_json_command(&mut metadata_command, "Go module pin verification").await?;
    let origin_hash = parse_go_origin_hash(&metadata, module)?;
    if origin_hash != commit {
        return Err(format!(
            "{} Go commit mismatch; expected {}, received {}",
            spec.display_name, commit, origin_hash
        ));
    }
    let bin = root.join("bin");
    fs::create_dir_all(&bin)
        .map_err(|error| format!("failed to create Go bin directory: {error}"))?;
    let mut command = Command::new(go_executable_name());
    command
        .args(["install"])
        .arg(format!("{package}@v{}", spec.version))
        .env("GOBIN", &bin);
    run_command(&mut command, "Go indexer installation")
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
    let entrypoint_relative = spec.entrypoint_relative_path();
    let expected_name = entrypoint_relative
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has an invalid entrypoint name", spec.display_name))?;
    let mut found = false;
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
        if file_name != expected_name {
            continue;
        }
        let mut unpacked = Vec::new();
        entry
            .read_to_end(&mut unpacked)
            .map_err(|error| format!("failed to unpack {}: {error}", spec.display_name))?;
        write_binary(root, &entrypoint_relative, &unpacked)?;
        found = true;
    }
    if found {
        Ok(())
    } else {
        Err(format!(
            "{} archive did not contain its entrypoint",
            spec.display_name
        ))
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

fn parse_go_origin_hash(bytes: &[u8], module: &str) -> Result<String, String> {
    let values = Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Go module metadata is not valid JSON: {error}"))?;
    values
        .into_iter()
        .find(|value| value.get("Path").and_then(Value::as_str) == Some(module))
        .and_then(|value| {
            value
                .get("Origin")
                .and_then(|origin| origin.get("Hash"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| {
            format!(
                "Go module metadata omitted Origin.Hash for {module}; refusing unverified install"
            )
        })
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

fn go_executable_name() -> OsString {
    if cfg!(windows) {
        OsString::from("go.exe")
    } else {
        OsString::from("go")
    }
}

#[cfg(test)]
#[path = "tests/semantic_indexer_installer.rs"]
mod tests;
