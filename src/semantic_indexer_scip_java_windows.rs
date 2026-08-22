use super::{compact_output, scip_java_repacker_source};
use crate::semantic_indexer_manifest::PinnedIndexer;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use zip::ZipArchive;

#[path = "semantic_indexer_scip_java_windows_sources.rs"]
mod sources;

use sources::WINDOWS_SCIP_JAVA_WRITER;
pub(super) use sources::{WINDOWS_GRADLE_TEMP_FILES, WINDOWS_SCIP_JAVA_PROCESS_RUNNER};

pub(super) fn patch_scip_java_windows(root: &Path, spec: PinnedIndexer) -> Result<(), String> {
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
        let launcher_root = patch_root.join("launcher");
        fs::create_dir_all(&launcher_root).map_err(|error| {
            format!(
                "failed to create scip-java launcher extraction directory {}: {error}",
                launcher_root.display()
            )
        })?;
        let writer_source = patch_root.join("ScipWriter.java");
        fs::write(&writer_source, WINDOWS_SCIP_JAVA_WRITER).map_err(|error| {
            format!("failed to write the Windows scip-java compatibility source: {error}")
        })?;
        let runner_source = patch_root.join("ProcessRunner.java");
        fs::write(&runner_source, WINDOWS_SCIP_JAVA_PROCESS_RUNNER).map_err(|error| {
            format!("failed to write the Windows scip-java process patch source: {error}")
        })?;
        let gradle_temp_source = patch_root.join("TempFiles.java");
        fs::write(&gradle_temp_source, WINDOWS_GRADLE_TEMP_FILES).map_err(|error| {
            format!("failed to write the Windows Gradle temp compatibility source: {error}")
        })?;
        let repacker_source = patch_root.join("LauncherRepacker.java");
        fs::write(
            &repacker_source,
            scip_java_repacker_source::LAUNCHER_REPACKER,
        )
        .map_err(|error| {
            format!("failed to write the Windows scip-java launcher repacker source: {error}")
        })?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("jar")?)
                .current_dir(&launcher_root)
                .arg("xf")
                .arg(&entrypoint)
                .args([
                    "coursier/bootstrap/launcher/jars/scip-aggregator-0.13.1.jar",
                    "coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar",
                    "coursier/bootstrap/launcher/jars/scip-java-bindings-0.9.0.jar",
                    "coursier/bootstrap/launcher/jars/protobuf-java-4.34.2.jar",
                    "coursier/bootstrap/launcher/jars/kotlin-stdlib-2.3.20.jar",
                ]),
            "extract scip-java Windows compatibility patch dependencies",
        )?;
        let jars = launcher_root.join("coursier/bootstrap/launcher/jars");
        let aggregator = jars.join("scip-aggregator-0.13.1.jar");
        let scip_java = jars.join("scip-java-0.13.1.jar");
        let bindings = jars.join("scip-java-bindings-0.9.0.jar");
        let protobuf = jars.join("protobuf-java-4.34.2.jar");
        let kotlin_stdlib = jars.join("kotlin-stdlib-2.3.20.jar");
        for path in [
            &aggregator,
            &scip_java,
            &bindings,
            &protobuf,
            &kotlin_stdlib,
        ] {
            if !path.is_file() {
                return Err(format!(
                    "scip-java runtime is missing patch dependency {}",
                    path.display()
                ));
            }
        }

        let classes = patch_root.join("classes");
        fs::create_dir_all(&classes).map_err(|error| {
            format!(
                "failed to create scip-java patch classes directory {}: {error}",
                classes.display()
            )
        })?;
        let classpath = std::env::join_paths([
            &aggregator,
            &scip_java,
            &bindings,
            &protobuf,
            &kotlin_stdlib,
        ])
        .map_err(|error| format!("failed to build scip-java patch classpath: {error}"))?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("javac")?)
                .current_dir(&patch_root)
                .arg("-cp")
                .arg(&classpath)
                .arg("-d")
                .arg(&classes)
                .arg(&writer_source)
                .arg(&runner_source)
                .arg(&gradle_temp_source)
                .arg(&repacker_source),
            "compile scip-java Windows compatibility patch",
        )?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("jar")?)
                .arg("uf")
                .arg(&scip_java)
                .arg("-C")
                .arg(&classes)
                .arg("org/scip_code/scip_java/buildtools/ProcessRunner.class"),
            "patch scip-java Windows process runner",
        )?;
        let rebuilt_zip = patch_root.join("scip-java-rebuilt.zip");
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("java")?)
                .arg("-cp")
                .arg(&classes)
                .arg("LauncherRepacker")
                .arg(&entrypoint)
                .arg(&scip_java)
                .arg(&rebuilt_zip)
                .arg("coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar"),
            "stream-rebuild patched scip-java launcher",
        )?;
        install_rebuilt_zip_preserving_prefix(
            &entrypoint,
            &rebuilt_zip,
            &[
                "coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar",
                "coursier/bootstrap/launcher/ResourcesLauncher.class",
                "coursier/bootstrap/launcher/y.class",
                "coursier/bootstrap/launcher/Y.class",
            ],
        )?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("jar")?)
                .current_dir(&classes)
                .arg("xf")
                .arg(&aggregator)
                .arg("org/scip_code/scip_java/aggregator/ScipOutputStream.class"),
            "extract scip-java Windows compatibility runtime class",
        )?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("jar")?)
                .current_dir(&classes)
                .arg("xf")
                .arg(&aggregator)
                .arg("org/scip_code/scip_java/aggregator/ScipAggregatorOptions.class"),
            "extract scip-java Windows aggregator options class",
        )?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("jar")?)
                .current_dir(&classes)
                .arg("xf")
                .arg(&bindings)
                .arg("org/scip_code/scip"),
            "extract scip-java Windows compatibility SCIP bindings",
        )?;
        run_patch_tool(
            std::process::Command::new(super::scip_java_patch::jdk_executable("jar")?)
                .current_dir(&classes)
                .arg("xf")
                .arg(&protobuf)
                .arg("com/google/protobuf"),
            "extract scip-java Windows compatibility protobuf runtime",
        )?;
        let patch_dir = root.join("bin/scip-java-v0.13.1-patch");
        let patch_package = patch_dir.join("org/scip_code/scip_java/aggregator");
        let gradle_patch_package = patch_dir.join("sniff-gradle-patch");
        let scip_package = patch_dir.join("org/scip_code/scip");
        let protobuf_package = patch_dir.join("com/google/protobuf");
        if patch_package.exists() {
            return Err(format!(
                "scip-java compatibility patch directory already exists: {}",
                patch_dir.display()
            ));
        }
        fs::create_dir_all(&patch_package)
            .map_err(|error| format!("failed to create scip-java patch directory: {error}"))?;
        fs::create_dir_all(&gradle_patch_package)
            .map_err(|error| format!("failed to create Gradle temp patch directory: {error}"))?;
        fs::create_dir_all(&scip_package)
            .map_err(|error| format!("failed to create scip-java bindings directory: {error}"))?;
        for class_name in [
            "ScipWriter.class",
            "ScipOutputStream.class",
            "ScipAggregatorOptions.class",
        ] {
            let source_class = classes
                .join("org/scip_code/scip_java/aggregator")
                .join(class_name);
            let patch_class = patch_package.join(class_name);
            if !source_class.is_file() {
                return Err(format!(
                    "scip-java compatibility class is missing: {}",
                    source_class.display()
                ));
            }
            fs::copy(&source_class, &patch_class).map_err(|error| {
                format!(
                    "failed to write scip-java compatibility class {}: {error}",
                    patch_class.display()
                )
            })?;
        }
        let gradle_temp_class = classes.join("org/gradle/api/internal/file/temp/TempFiles.class");
        if !gradle_temp_class.is_file() {
            return Err(format!(
                "Gradle temp compatibility class is missing: {}",
                gradle_temp_class.display()
            ));
        }
        fs::copy(
            &gradle_temp_class,
            gradle_patch_package.join("TempFiles.class"),
        )
        .map_err(|error| format!("failed to install Gradle temp compatibility class: {error}"))?;
        copy_patch_tree(
            &classes.join("org/scip_code/scip"),
            &scip_package,
            "scip-java bindings",
        )?;
        copy_patch_tree(
            &classes.join("com/google/protobuf"),
            &protobuf_package,
            "protobuf runtime",
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

pub(super) fn install_rebuilt_zip_preserving_prefix(
    launcher_path: &Path,
    rebuilt_zip_path: &Path,
    required_entries: &[&str],
) -> Result<(), String> {
    const MAX_EXECUTABLE_PREFIX_BYTES: usize = 1024 * 1024;
    const LOCAL_ZIP_HEADER: &[u8; 4] = b"PK\x03\x04";

    let launcher_bytes = fs::read(launcher_path).map_err(|error| {
        format!(
            "failed to read scip-java launcher {} for rebuilding: {error}",
            launcher_path.display()
        )
    })?;
    if !launcher_bytes.starts_with(b"#!") {
        return Err(format!(
            "scip-java launcher {} does not have the expected executable script prefix",
            launcher_path.display()
        ));
    }
    let search_end = launcher_bytes.len().min(MAX_EXECUTABLE_PREFIX_BYTES);
    let prefix_len = launcher_bytes[..search_end]
        .windows(LOCAL_ZIP_HEADER.len())
        .position(|bytes| bytes == LOCAL_ZIP_HEADER)
        .ok_or_else(|| {
            format!(
                "scip-java launcher {} has no ZIP header within its first {} bytes",
                launcher_path.display(),
                MAX_EXECUTABLE_PREFIX_BYTES
            )
        })?;
    if prefix_len == 0 {
        return Err(format!(
            "scip-java launcher {} has no executable prefix to preserve",
            launcher_path.display()
        ));
    }
    let input = File::open(rebuilt_zip_path).map_err(|error| {
        format!(
            "failed to open rebuilt scip-java ZIP {}: {error}",
            rebuilt_zip_path.display()
        )
    })?;
    let mut archive = ZipArchive::new(input)
        .map_err(|error| format!("failed to parse rebuilt scip-java ZIP: {error}"))?;
    if archive.offset() != 0 {
        return Err(format!(
            "rebuilt scip-java launcher {} is not a plain ZIP archive",
            rebuilt_zip_path.display()
        ));
    }
    let archive_comment = archive.comment().to_vec().into_boxed_slice();
    let output_path = launcher_path.with_extension("sniff-rebuilt");
    if output_path.exists() {
        fs::remove_file(&output_path).map_err(|error| {
            format!(
                "failed to clear stale scip-java rebuild output {}: {error}",
                output_path.display()
            )
        })?;
    }
    let mut output = File::create(&output_path).map_err(|error| {
        format!(
            "failed to create scip-java rebuild output {}: {error}",
            output_path.display()
        )
    })?;
    output
        .write_all(&launcher_bytes[..prefix_len])
        .map_err(|error| format!("failed to preserve scip-java executable prefix: {error}"))?;
    let mut rebuilt = zip::ZipWriter::new(output);
    rebuilt.set_raw_comment(archive_comment);
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            format!("failed to inspect rebuilt scip-java ZIP entry {index}: {error}")
        })?;
        rebuilt.raw_copy_file(entry).map_err(|error| {
            format!("failed to preserve rebuilt scip-java ZIP entry {index}: {error}")
        })?;
    }
    let rebuilt_file = rebuilt
        .finish()
        .map_err(|error| format!("failed to finish rebuilt scip-java launcher: {error}"))?;
    rebuilt_file
        .sync_all()
        .map_err(|error| format!("failed to sync rebuilt scip-java launcher: {error}"))?;
    drop(archive);

    let assembled = fs::read(&output_path)
        .map_err(|error| format!("failed to validate rebuilt scip-java launcher: {error}"))?;
    if !assembled.starts_with(&launcher_bytes[..prefix_len])
        || assembled.get(prefix_len..prefix_len + LOCAL_ZIP_HEADER.len()) != Some(LOCAL_ZIP_HEADER)
    {
        return Err(
            "patched scip-java launcher did not preserve its executable prefix".to_string(),
        );
    }
    let mut validation = File::open(&output_path)
        .map_err(|error| error.to_string())
        .and_then(|file| ZipArchive::new(file).map_err(|error| error.to_string()))?;
    for required_entry in required_entries {
        let entry = validation.by_name(required_entry).map_err(|error| {
            format!(
                "rebuilt scip-java launcher is missing required entry {required_entry}: {error}"
            )
        })?;
        if required_entry.ends_with(".jar") && entry.compression() != zip::CompressionMethod::Stored
        {
            return Err(format!(
                "rebuilt scip-java nested runtime {required_entry} must remain stored without compression"
            ));
        }
    }
    validation
        .by_name("META-INF/MANIFEST.MF")
        .map_err(|error| format!("rebuilt scip-java launcher is missing its manifest: {error}"))?;
    drop(validation);
    fs::copy(&output_path, launcher_path).map_err(|error| {
        format!(
            "failed to install patched scip-java launcher {}: {error}",
            launcher_path.display()
        )
    })?;
    fs::remove_file(&output_path).map_err(|error| {
        format!(
            "failed to remove scip-java repack output {}: {error}",
            output_path.display()
        )
    })?;
    Ok(())
}

fn copy_patch_tree(source: &Path, target: &Path, label: &str) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!(
            "extracted {label} directory is missing: {}",
            source.display()
        ));
    }
    fs::create_dir_all(target).map_err(|error| {
        format!(
            "failed to create {label} directory {}: {error}",
            target.display()
        )
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "failed to read {label} directory {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to enumerate {label} directory {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if source_path.is_dir() {
            copy_patch_tree(&source_path, &target_path, label)?;
        } else if source_path.is_file() {
            fs::copy(&source_path, &target_path).map_err(|error| {
                format!(
                    "failed to write {label} class {}: {error}",
                    target_path.display()
                )
            })?;
        }
    }
    Ok(())
}

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

fn unique_patch_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}
