#[cfg(windows)]
use super::replace_zip_entry_preserving_prefix;
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
fn replacing_nested_runtime_preserves_launcher_prefix_and_other_entries() {
    use std::io::{Read, Write};
    use zip::write::SimpleFileOptions;

    let temp = tempfile::tempdir().unwrap();
    let launcher = temp.path().join("launcher");
    let original_zip = temp.path().join("launcher.zip");
    let replacement = temp.path().join("replacement.jar");
    std::fs::write(&replacement, b"patched runtime").unwrap();

    let file = std::fs::File::create(&original_zip).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    writer
        .start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"Main-Class: example.Main\n").unwrap();
    writer
        .start_file("nested/runtime.jar", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"original runtime").unwrap();
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

    replace_zip_entry_preserving_prefix(&launcher, "nested/runtime.jar", &replacement).unwrap();

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
    let mut runtime = String::new();
    archive
        .by_name("nested/runtime.jar")
        .unwrap()
        .read_to_string(&mut runtime)
        .unwrap();
    assert_eq!(runtime, "patched runtime");
}
