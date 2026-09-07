use crate::semantic_indexer_manifest::PinnedNpmPackage;
use base64::Engine;
use flate2::read::GzDecoder;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 50_000;
const MAX_PACKAGE_JSON_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
struct PackageIdentity {
    name: String,
    version: String,
}

pub(super) async fn install(root: &Path, packages: &[PinnedNpmPackage]) -> Result<(), String> {
    validate_package_set(packages)?;
    let client = Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|error| format!("failed to prepare pinned npm package downloader: {error}"))?;
    for package in packages {
        let bytes = download(&client, package).await?;
        verify_integrity(package, &bytes)?;
        unpack(root, package, &bytes)?;
        validate_package_identity(root, package)?;
    }
    Ok(())
}

fn validate_package_set(packages: &[PinnedNpmPackage]) -> Result<(), String> {
    if packages.is_empty() {
        return Err("pinned npm package set is empty".to_string());
    }
    let mut names = BTreeSet::new();
    for package in packages {
        package_relative_path(package.name)?;
        if package.version.is_empty()
            || package
                .version
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            return Err(format!(
                "pinned npm package {} has an invalid version",
                package.name
            ));
        }
        if !package.url.starts_with("https://registry.npmjs.org/") || !package.url.ends_with(".tgz")
        {
            return Err(format!(
                "pinned npm package {} has an unsupported tarball URL",
                package.name
            ));
        }
        if package.integrity_sha512.is_empty() {
            return Err(format!(
                "pinned npm package {} has no SHA-512 integrity",
                package.name
            ));
        }
        let integrity = base64::engine::general_purpose::STANDARD
            .decode(package.integrity_sha512)
            .map_err(|error| {
                format!(
                    "pinned npm package {} has invalid SHA-512 integrity: {error}",
                    package.name
                )
            })?;
        if integrity.len() != 64 {
            return Err(format!(
                "pinned npm package {} SHA-512 integrity decoded to {} bytes instead of 64",
                package.name,
                integrity.len()
            ));
        }
        if !names.insert(package.name) {
            return Err(format!("pinned npm package set repeats {}", package.name));
        }
    }
    Ok(())
}

async fn download(client: &Client, package: &PinnedNpmPackage) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(package.url)
        .send()
        .await
        .map_err(|error| format!("failed to download npm package {}: {error}", package.name))?
        .error_for_status()
        .map_err(|error| format!("npm package download failed for {}: {error}", package.name))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_ARCHIVE_BYTES)
    {
        return Err(format!(
            "npm package {} exceeds {} compressed bytes",
            package.name, MAX_ARCHIVE_BYTES
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to read npm package {}: {error}", package.name))?
    {
        let next_size = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| format!("npm package {} compressed size overflowed", package.name))?;
        if next_size as u64 > MAX_ARCHIVE_BYTES {
            return Err(format!(
                "npm package {} exceeds {} compressed bytes",
                package.name, MAX_ARCHIVE_BYTES
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn verify_integrity(package: &PinnedNpmPackage, bytes: &[u8]) -> Result<(), String> {
    let actual = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    if actual != package.integrity_sha512 {
        return Err(format!(
            "npm package {}@{} SHA-512 mismatch",
            package.name, package.version
        ));
    }
    Ok(())
}

fn unpack(root: &Path, package: &PinnedNpmPackage, bytes: &[u8]) -> Result<(), String> {
    let package_root = root
        .join("node_modules")
        .join(package_relative_path(package.name)?);
    if package_root.exists() {
        return Err(format!(
            "refusing to overwrite npm package directory {}",
            package_root.display()
        ));
    }
    fs::create_dir_all(&package_root).map_err(|error| {
        format!(
            "failed to create npm package directory {}: {error}",
            package_root.display()
        )
    })?;

    let decoder = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|error| {
        format!(
            "npm package {} has an invalid tar archive: {error}",
            package.name
        )
    })?;
    let mut expanded_bytes = 0_u64;
    let mut entry_count = 0_usize;
    let mut files = BTreeSet::new();
    for entry in entries {
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(format!(
                "npm package {} exceeds {} archive entries",
                package.name, MAX_ARCHIVE_ENTRIES
            ));
        }
        let entry = entry.map_err(|error| {
            format!(
                "npm package {} contains an invalid tar entry: {error}",
                package.name
            )
        })?;
        let entry_type = entry.header().entry_type();
        let path = entry.path().map_err(|error| {
            format!(
                "npm package {} contains an invalid path: {error}",
                package.name
            )
        })?;
        let Some(relative) = npm_entry_relative_path(&path)? else {
            if entry_type.is_dir() {
                continue;
            }
            return Err(format!(
                "npm package {} archive root is not a directory",
                package.name
            ));
        };
        let target = package_root.join(&relative);
        if entry_type.is_dir() {
            fs::create_dir_all(&target).map_err(|error| {
                format!(
                    "failed to create npm package directory {}: {error}",
                    target.display()
                )
            })?;
            continue;
        }
        if !entry_type.is_file() {
            return Err(format!(
                "npm package {} contains unsupported tar entry {}",
                package.name,
                path.display()
            ));
        }
        if !files.insert(relative.clone()) {
            return Err(format!(
                "npm package {} repeats archive entry {}",
                package.name,
                relative.display()
            ));
        }
        let size = entry.size();
        expanded_bytes = expanded_bytes
            .checked_add(size)
            .ok_or_else(|| format!("npm package {} expanded size overflowed", package.name))?;
        if expanded_bytes > MAX_EXPANDED_BYTES {
            return Err(format!(
                "npm package {} exceeds {} expanded bytes",
                package.name, MAX_EXPANDED_BYTES
            ));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create npm package directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|error| {
                format!(
                    "failed to create npm package file {}: {error}",
                    target.display()
                )
            })?;
        let copied = std::io::copy(&mut entry.take(size + 1), &mut output).map_err(|error| {
            format!(
                "failed to extract npm package file {}: {error}",
                target.display()
            )
        })?;
        if copied != size {
            return Err(format!(
                "npm package {} entry {} declared {size} bytes but yielded {copied}",
                package.name,
                relative.display()
            ));
        }
        output.flush().map_err(|error| {
            format!(
                "failed to flush npm package file {}: {error}",
                target.display()
            )
        })?;
    }
    if files.is_empty() {
        return Err(format!("npm package {} contains no files", package.name));
    }
    Ok(())
}

fn package_relative_path(name: &str) -> Result<PathBuf, String> {
    let segments = name.split('/').collect::<Vec<_>>();
    let valid = match segments.as_slice() {
        [plain] => valid_package_segment(plain),
        [scope, package] => {
            scope.starts_with('@')
                && valid_package_segment(scope.trim_start_matches('@'))
                && valid_package_segment(package)
        }
        _ => false,
    };
    if !valid {
        return Err(format!("invalid pinned npm package name {name:?}"));
    }
    Ok(segments.into_iter().collect())
}

fn valid_package_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn npm_entry_relative_path(path: &Path) -> Result<Option<PathBuf>, String> {
    if path.to_string_lossy().contains('\\') {
        return Err(format!(
            "npm tar entry uses a non-portable path separator: {}",
            path.display()
        ));
    }
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(component)) if component == "package" => {}
        _ => {
            return Err(format!(
                "npm tar entry is outside the package root: {}",
                path.display()
            ));
        }
    }
    let mut relative = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(component) => relative.push(component),
            _ => {
                return Err(format!(
                    "npm tar entry contains an unsafe path: {}",
                    path.display()
                ));
            }
        }
    }
    Ok((!relative.as_os_str().is_empty()).then_some(relative))
}

fn validate_package_identity(root: &Path, package: &PinnedNpmPackage) -> Result<(), String> {
    let package_json = root
        .join("node_modules")
        .join(package_relative_path(package.name)?)
        .join("package.json");
    let metadata = fs::symlink_metadata(&package_json)
        .map_err(|error| format!("npm package {} has no package.json: {error}", package.name))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "npm package {} package.json is not a regular file",
            package.name
        ));
    }
    if metadata.len() > MAX_PACKAGE_JSON_BYTES {
        return Err(format!(
            "npm package {} package.json exceeds {} bytes",
            package.name, MAX_PACKAGE_JSON_BYTES
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(&package_json)
        .and_then(|file| {
            file.take(MAX_PACKAGE_JSON_BYTES + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| {
            format!(
                "failed to read npm package {} identity: {error}",
                package.name
            )
        })?;
    let identity: PackageIdentity = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "npm package {} has invalid package.json: {error}",
            package.name
        )
    })?;
    if identity.name != package.name || identity.version != package.version {
        return Err(format!(
            "npm package identity mismatch: expected {}@{}, received {}@{}",
            package.name, package.version, identity.name, identity.version
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/semantic_indexer_npm.rs"]
mod tests;
