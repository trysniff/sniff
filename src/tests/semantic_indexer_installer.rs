#[cfg(windows)]
use super::unpack_zip;
#[cfg(windows)]
use super::{
    WINDOWS_GRADLE_TEMP_FILES, WINDOWS_SCIP_JAVA_PROCESS_RUNNER,
    install_rebuilt_zip_preserving_prefix, patch_scip_java_windows,
};
use super::{compact_output, parse_json_string};

#[test]
fn json_integrity_values_must_be_strings() {
    assert_eq!(
        parse_json_string(br#""sha512-example""#, "integrity").unwrap(),
        "sha512-example"
    );
    assert!(parse_json_string(br#"{"integrity":"wrong-shape"}"#, "integrity").is_err());
}

#[test]
fn command_output_is_bounded_and_compacted() {
    let output = compact_output(b"one\n two\tthree");
    assert_eq!(output, "one two three");
    let long = compact_output(&vec![b'x'; 500]);
    assert_eq!(long.len(), 403);
    assert!(long.ends_with("..."));
}

#[cfg(windows)]
#[test]
fn windows_rust_bundle_requires_and_extracts_one_runtime_pair() {
    use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn archive(include_cargo: bool, duplicate_cargo: bool) -> Vec<u8> {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut bytes);
            writer
                .start_file("payload/rust-analyzer.exe", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"rust-analyzer").unwrap();
            if include_cargo {
                writer
                    .start_file("payload/cargo.exe", SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(b"cargo").unwrap();
            }
            if duplicate_cargo {
                writer
                    .start_file("other/cargo.exe", SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(b"duplicate").unwrap();
            }
            writer.finish().unwrap();
        }
        bytes.into_inner()
    }

    let spec = pinned_indexer(SemanticIndexerKind::Rust).unwrap();
    let missing = tempfile::tempdir().unwrap();
    let error = unpack_zip(missing.path(), spec, &archive(false, false)).unwrap_err();
    assert!(error.contains("cargo.exe"), "{error}");

    let duplicate = tempfile::tempdir().unwrap();
    let error = unpack_zip(duplicate.path(), spec, &archive(true, true)).unwrap_err();
    assert!(
        error.contains("duplicate runtime file cargo.exe"),
        "{error}"
    );

    let installed = tempfile::tempdir().unwrap();
    unpack_zip(installed.path(), spec, &archive(true, false)).unwrap();
    assert_eq!(
        std::fs::read(installed.path().join(spec.entrypoint_relative_path())).unwrap(),
        b"rust-analyzer"
    );
    assert_eq!(
        std::fs::read(installed.path().join("bin/cargo.exe")).unwrap(),
        b"cargo"
    );
}

#[cfg(windows)]
#[test]
fn rebuilt_launcher_preserves_executable_prefix_and_required_entries() {
    use std::io::{Read, Write};
    use zip::write::SimpleFileOptions;

    let temp = tempfile::tempdir().unwrap();
    let launcher = temp.path().join("launcher");
    let original_zip = temp.path().join("launcher.zip");
    let rebuilt_zip = temp.path().join("rebuilt.zip");

    let file = std::fs::File::create(&original_zip).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"Main-Class: example.Main\n").unwrap();
    writer
        .start_file(
            "nested/runtime.jar",
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"original runtime").unwrap();
    writer
        .start_file("launcher/y.class", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"lowercase class").unwrap();
    writer
        .start_file("launcher/Y.class", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"uppercase class").unwrap();
    writer.finish().unwrap();
    let mut launcher_file = std::fs::File::create(&launcher).unwrap();
    launcher_file
        .write_all(b"#!/usr/bin/env sh\nexec java -jar \"$0\" \"$@\"\n")
        .unwrap();
    std::io::copy(
        &mut std::fs::File::open(&original_zip).unwrap(),
        &mut launcher_file,
    )
    .unwrap();
    drop(launcher_file);

    let file = std::fs::File::create(&rebuilt_zip).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"Main-Class: example.Main\n").unwrap();
    writer
        .start_file(
            "nested/runtime.jar",
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"patched runtime").unwrap();
    writer
        .start_file("launcher/y.class", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"lowercase class").unwrap();
    writer
        .start_file("launcher/Y.class", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"uppercase class").unwrap();
    writer.finish().unwrap();

    install_rebuilt_zip_preserving_prefix(
        &launcher,
        &rebuilt_zip,
        &["nested/runtime.jar", "launcher/y.class", "launcher/Y.class"],
    )
    .unwrap();

    let bytes = std::fs::read(&launcher).unwrap();
    assert!(bytes.starts_with(b"#!/usr/bin/env sh\n"));
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&launcher).unwrap()).unwrap();
    let mut manifest = String::new();
    archive
        .by_name("META-INF/MANIFEST.MF")
        .unwrap()
        .read_to_string(&mut manifest)
        .unwrap();
    assert_eq!(manifest, "Main-Class: example.Main\n");
    let mut runtime_entry = archive.by_name("nested/runtime.jar").unwrap();
    assert_eq!(runtime_entry.compression(), zip::CompressionMethod::Stored);
    let mut runtime = String::new();
    runtime_entry.read_to_string(&mut runtime).unwrap();
    assert_eq!(runtime, "patched runtime");
    drop(runtime_entry);
    let mut lowercase = String::new();
    archive
        .by_name("launcher/y.class")
        .unwrap()
        .read_to_string(&mut lowercase)
        .unwrap();
    assert_eq!(lowercase, "lowercase class");
    let mut uppercase = String::new();
    archive
        .by_name("launcher/Y.class")
        .unwrap()
        .read_to_string(&mut uppercase)
        .unwrap();
    assert_eq!(uppercase, "uppercase class");

    let java_listing = std::process::Command::new("jar")
        .arg("tf")
        .arg(&launcher)
        .output()
        .unwrap();
    assert!(
        java_listing.status.success(),
        "JDK rejected rebuilt launcher: {}",
        String::from_utf8_lossy(&java_listing.stderr)
    );
    let java_listing = String::from_utf8(java_listing.stdout).unwrap();
    assert!(
        java_listing
            .lines()
            .any(|line| line == "nested/runtime.jar")
    );
    assert!(java_listing.lines().any(|line| line == "launcher/y.class"));
    assert!(java_listing.lines().any(|line| line == "launcher/Y.class"));
}

#[cfg(windows)]
#[test]
#[ignore = "requires the 86 MB upstream scip-java v0.13.1 launcher"]
fn rebuilt_launcher_accepts_the_verified_upstream_scip_java_polyglot() {
    use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
    use sha2::{Digest, Sha256};

    const TARGET: &str = "coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar";
    const EXPECTED_SHA256: &str =
        "a694cae143c32c5b6226362fb4bd268a8d13d3cd9b482819b3b0029a9a97b8fe";
    let source = std::path::PathBuf::from(
        std::env::var_os("SNIFF_TEST_SCIP_JAVA_LAUNCHER")
            .expect("set SNIFF_TEST_SCIP_JAVA_LAUNCHER to the upstream launcher"),
    );
    let source_bytes = std::fs::read(&source).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&source_bytes)),
        EXPECTED_SHA256
    );

    let temp = tempfile::tempdir().unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::Kotlin).unwrap();
    let launcher = temp.path().join(spec.entrypoint_relative_path());
    std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
    std::fs::write(&launcher, source_bytes).unwrap();
    patch_scip_java_windows(temp.path(), spec).unwrap();

    let version = std::process::Command::new("java")
        .arg("-jar")
        .arg(&launcher)
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "patched launcher failed to execute: {}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        "scip-java version 0.0.0-SNAPSHOT"
    );

    let listing = std::process::Command::new("jar")
        .arg("tf")
        .arg(&launcher)
        .output()
        .unwrap();
    assert!(
        listing.status.success(),
        "JDK rejected rebuilt upstream launcher: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    assert_eq!(
        String::from_utf8(listing.stdout)
            .unwrap()
            .lines()
            .filter(|line| *line == TARGET)
            .count(),
        1
    );
}

#[cfg(windows)]
#[test]
fn windows_gradle_patch_uses_private_project_cache_and_explicit_offline_mode() {
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("SNIFF_GRADLE_CLASSPATH"));
    assert!(!WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("SNIFF_GRADLE_LAUNCHER_JAR"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("SNIFF_GRADLE_PROJECT_CACHE"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("SNIFF_GRADLE_USER_HOME"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("SNIFF_GRADLE_TEMP"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("-Djava.io.tmpdir="));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("-Dgradle.user.home="));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("Files.createTempFile"));
    assert!(WINDOWS_GRADLE_TEMP_FILES.contains("Files.createTempFile"));
    assert!(!WINDOWS_GRADLE_TEMP_FILES.contains("File.createTempFile"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("--gradle-user-home"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("--project-cache-dir"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("--no-watch-fs"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("--stacktrace"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("SNIFF_GRADLE_OFFLINE"));
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("--offline"));
    assert!(
        WINDOWS_SCIP_JAVA_PROCESS_RUNNER
            .contains("-Pkotlin.compiler.execution.strategy=out-of-process")
    );
    assert!(WINDOWS_SCIP_JAVA_PROCESS_RUNNER.contains("replacements != 1"));
}
