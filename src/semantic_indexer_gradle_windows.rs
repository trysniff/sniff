use super::strip_windows_verbatim_prefix;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const OVERLAY_DIR: &str = "sniff-gradle-runtime-overlay";
pub(crate) const TEMP_CLASS: &str = "org/gradle/api/internal/file/temp/TempFiles.class";

pub(crate) fn prepare_child_classpath(
    workspace_directory: &Path,
    launcher: &Path,
    main_class: &str,
    scip_java_entrypoint: &Path,
) -> Result<String, String> {
    let patch_dir = scip_java_entrypoint
        .parent()
        .ok_or_else(|| "scip-java entrypoint has no parent directory".to_string())?
        .join("scip-java-v0.13.1-patch");
    if main_class == "org.gradle.wrapper.GradleWrapperMain" {
        return Ok(java_classpath(&patch_dir, launcher));
    }
    if main_class != "org.gradle.launcher.GradleMain" {
        return Err(format!(
            "unsupported Windows Gradle main class {main_class}"
        ));
    }

    prepare_system_overlay(workspace_directory, launcher, &patch_dir)
}

pub(crate) fn prepare_system_overlay(
    workspace_directory: &Path,
    launcher: &Path,
    patch_dir: &Path,
) -> Result<String, String> {
    let launcher = fs::canonicalize(launcher).map_err(|error| {
        format!(
            "failed to resolve the Windows Gradle launcher {}: {error}",
            launcher.display()
        )
    })?;
    let gradle_lib = launcher.parent().ok_or_else(|| {
        format!(
            "Windows Gradle launcher has no distribution lib directory: {}",
            launcher.display()
        )
    })?;
    let gradle_plugins = gradle_lib.join("plugins");
    if gradle_lib.file_name().and_then(|name| name.to_str()) != Some("lib")
        || !gradle_plugins.is_dir()
    {
        return Err(format!(
            "Windows Gradle launcher is not inside a complete distribution: {}",
            launcher.display()
        ));
    }

    let file_temp = unique_distribution_jar(gradle_lib, "gradle-file-temp-")?;
    let version = versioned_jar(&file_temp, "gradle-file-temp-")?;
    let beacon = gradle_lib.join(format!("gradle-installation-beacon-{version}.jar"));
    if !beacon.is_file() {
        return Err(format!(
            "Windows Gradle {} is missing its installation beacon {}",
            version,
            beacon.display()
        ));
    }
    let launcher_name = launcher
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "Windows Gradle launcher name is not UTF-8: {}",
                launcher.display()
            )
        })?;
    if !launcher_name.ends_with(&format!("-{version}.jar")) {
        return Err(format!(
            "Windows Gradle launcher {} does not match runtime version {}",
            launcher.display(),
            version
        ));
    }

    let replacement = patch_dir.join("sniff-gradle-patch/TempFiles.class");
    if !replacement.is_file() {
        return Err(format!(
            "sealed scip-java installation is missing the Gradle temp patch {}",
            replacement.display()
        ));
    }
    let overlay = workspace_directory.join(OVERLAY_DIR);
    if overlay.exists() {
        return Err(format!(
            "refusing to reuse an unexpected Windows Gradle runtime overlay {}",
            overlay.display()
        ));
    }
    let overlay_lib = overlay.join("lib");
    fs::create_dir_all(overlay_lib.join("plugins")).map_err(|error| {
        format!(
            "failed to create private Windows Gradle runtime overlay {}: {error}",
            overlay.display()
        )
    })?;
    let overlay_beacon = overlay_lib.join(
        beacon
            .file_name()
            .ok_or_else(|| format!("Gradle beacon has no filename: {}", beacon.display()))?,
    );
    fs::copy(&beacon, &overlay_beacon).map_err(|error| {
        format!("failed to copy the Gradle installation beacon into the private overlay: {error}")
    })?;
    let overlay_file_temp = overlay_lib.join(file_temp.file_name().ok_or_else(|| {
        format!(
            "Gradle file-temp jar has no filename: {}",
            file_temp.display()
        )
    })?);
    rebuild_file_temp_jar(&file_temp, &overlay_file_temp, &replacement)?;

    let classpath = std::env::join_paths([
        strip_windows_verbatim_prefix(overlay_beacon),
        strip_windows_verbatim_prefix(overlay_file_temp),
        strip_windows_verbatim_prefix(gradle_lib.join("*")),
        strip_windows_verbatim_prefix(gradle_plugins.join("*")),
    ])
    .map_err(|error| format!("failed to build private Windows Gradle classpath: {error}"))?;
    Ok(classpath.to_string_lossy().into_owned())
}

fn unique_distribution_jar(directory: &Path, prefix: &str) -> Result<PathBuf, String> {
    let mut matches = fs::read_dir(directory)
        .map_err(|error| {
            format!(
                "failed to inspect Gradle distribution directory {}: {error}",
                directory.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(prefix) && name.ends_with(".jar"))
        })
        .collect::<Vec<_>>();
    matches.sort();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(format!(
            "Gradle distribution {} has no {}*.jar runtime",
            directory.display(),
            prefix
        )),
        _ => Err(format!(
            "Gradle distribution {} has multiple {}*.jar runtimes; refusing an ambiguous patch target",
            directory.display(),
            prefix
        )),
    }
}

fn versioned_jar(path: &Path, prefix: &str) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("Gradle runtime name is not UTF-8: {}", path.display()))?;
    let version = name
        .strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(".jar"))
        .filter(|version| !version.is_empty())
        .ok_or_else(|| format!("unsupported Gradle runtime filename: {name}"))?;
    Ok(version.to_string())
}

fn rebuild_file_temp_jar(
    source: &Path,
    destination: &Path,
    replacement_class: &Path,
) -> Result<(), String> {
    let replacement = fs::read(replacement_class).map_err(|error| {
        format!(
            "failed to read sealed Gradle temp replacement {}: {error}",
            replacement_class.display()
        )
    })?;
    if replacement.is_empty() {
        return Err(format!(
            "sealed Gradle temp replacement is empty: {}",
            replacement_class.display()
        ));
    }
    let input = fs::File::open(source).map_err(|error| {
        format!(
            "failed to open Gradle runtime {}: {error}",
            source.display()
        )
    })?;
    let mut archive = zip::ZipArchive::new(input).map_err(|error| {
        format!(
            "failed to parse Gradle runtime {}: {error}",
            source.display()
        )
    })?;
    if archive.offset() != 0 {
        return Err(format!(
            "Gradle runtime is not a plain jar archive: {}",
            source.display()
        ));
    }
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "failed to create private Gradle runtime {}: {error}",
                destination.display()
            )
        })?;
    let mut rebuilt = zip::ZipWriter::new(output);
    rebuilt.set_raw_comment(archive.comment().to_vec().into_boxed_slice());
    let mut replacements = 0usize;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect Gradle runtime entry {index}: {error}"))?;
        if entry.name() == TEMP_CLASS {
            let compression = entry.compression();
            drop(entry);
            rebuilt
                .start_file(
                    TEMP_CLASS,
                    zip::write::SimpleFileOptions::default().compression_method(compression),
                )
                .map_err(|error| format!("failed to replace Gradle temp class: {error}"))?;
            rebuilt
                .write_all(&replacement)
                .map_err(|error| format!("failed to write Gradle temp replacement: {error}"))?;
            replacements += 1;
        } else {
            rebuilt.raw_copy_file(entry).map_err(|error| {
                format!("failed to preserve Gradle runtime entry {index}: {error}")
            })?;
        }
    }
    if replacements != 1 {
        return Err(format!(
            "Gradle runtime {} contained {} copies of {}; expected exactly one",
            source.display(),
            replacements,
            TEMP_CLASS
        ));
    }
    let output = rebuilt
        .finish()
        .map_err(|error| format!("failed to finish private Gradle runtime: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("failed to sync private Gradle runtime: {error}"))?;
    drop(archive);

    let input = fs::File::open(destination).map_err(|error| {
        format!(
            "failed to reopen private Gradle runtime {}: {error}",
            destination.display()
        )
    })?;
    let mut validation = zip::ZipArchive::new(input)
        .map_err(|error| format!("private Gradle runtime is invalid: {error}"))?;
    for required in [
        "gradle-file-temp-classpath.properties",
        "org/gradle/api/internal/file/temp/DefaultTemporaryFileProvider.class",
    ] {
        validation.by_name(required).map_err(|error| {
            format!("private Gradle runtime is missing required entry {required}: {error}")
        })?;
    }
    let mut installed = Vec::new();
    validation
        .by_name(TEMP_CLASS)
        .map_err(|error| format!("private Gradle runtime is missing its temp patch: {error}"))?
        .read_to_end(&mut installed)
        .map_err(|error| format!("failed to verify private Gradle temp patch: {error}"))?;
    if installed != replacement {
        return Err(
            "private Gradle runtime did not preserve the exact sealed temp patch".to_string(),
        );
    }
    Ok(())
}

pub(crate) fn java_classpath(patch_dir: &Path, launcher: &Path) -> String {
    let patch_dir = strip_windows_verbatim_prefix(patch_dir.to_path_buf());
    let launcher = strip_windows_verbatim_prefix(launcher.to_path_buf());
    format!("{};{}", patch_dir.display(), launcher.display())
}
