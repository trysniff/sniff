#[cfg(windows)]
use super::{WINDOWS_SCIP_JAVA_LAUNCHER_REPACKER, install_rebuilt_zip_preserving_prefix};
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
fn rebuilt_launcher_preserves_executable_prefix_and_required_entries() {
    use std::io::{Read, Write};
    use zip::write::SimpleFileOptions;

    let temp = tempfile::tempdir().unwrap();
    let launcher = temp.path().join("launcher");
    let original_zip = temp.path().join("launcher.zip");
    let rebuilt_zip = temp.path().join("rebuilt.zip");
    let replacement = temp.path().join("replacement.jar");
    let source = temp.path().join("LauncherRepacker.java");
    let classes = temp.path().join("classes");

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

    std::fs::write(&replacement, b"patched runtime").unwrap();
    std::fs::write(&source, WINDOWS_SCIP_JAVA_LAUNCHER_REPACKER).unwrap();
    std::fs::create_dir(&classes).unwrap();
    let compile = std::process::Command::new("javac")
        .arg("-d")
        .arg(&classes)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "launcher repacker failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let repack = std::process::Command::new("java")
        .arg("-cp")
        .arg(&classes)
        .arg("LauncherRepacker")
        .arg(&launcher)
        .arg(&replacement)
        .arg(&rebuilt_zip)
        .arg("nested/runtime.jar")
        .output()
        .unwrap();
    assert!(
        repack.status.success(),
        "launcher repacker failed: {}",
        String::from_utf8_lossy(&repack.stderr)
    );

    install_rebuilt_zip_preserving_prefix(
        &launcher,
        &rebuilt_zip,
        &["nested/runtime.jar", "launcher/y.class", "launcher/Y.class"],
    )
    .unwrap();

    let bytes = std::fs::read(&launcher).unwrap();
    assert!(bytes.starts_with(b"#!/usr/bin/env sh\n"));
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&launcher).unwrap()).unwrap();
    assert!(archive.offset() > 0);
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
}
