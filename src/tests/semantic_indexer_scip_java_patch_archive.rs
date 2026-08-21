use super::*;
use std::io::{Cursor, Read, Write};

fn zip_bytes(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut archive = ZipWriter::new(&mut output);
        for (name, bytes, compression) in entries {
            archive
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(*compression),
                )
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap();
    }
    output.into_inner()
}

fn class_entries() -> Vec<(String, Vec<u8>)> {
    COMPILED_CLASSES
        .into_iter()
        .map(|name| {
            (
                format!("{CLASS_PACKAGE}/{name}"),
                vec![0xca, 0xfe, 0xba, 0xbe, 1],
            )
        })
        .collect()
}

#[test]
fn rebuilds_kotlinc_by_replacing_exact_registrar_classes() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.jar");
    let destination = temp.path().join("patched.jar");
    let registrar = format!("{CLASS_PACKAGE}/AnalyzerFirExtensionRegistrar.class");
    let closure = format!("{CLASS_PACKAGE}/AnalyzerFirExtensionRegistrar$configurePlugin$1.class");
    fs::write(
        &source,
        zip_bytes(&[
            (&registrar, b"old-main", CompressionMethod::Deflated),
            (&closure, b"old-closure", CompressionMethod::Deflated),
            ("kept.class", b"kept", CompressionMethod::Stored),
        ]),
    )
    .unwrap();

    rebuild_kotlinc_jar(&source, &destination, &class_entries()).unwrap();

    let mut archive = open_zip(&destination, "fixture patched jar").unwrap();
    assert_eq!(archive.len(), 8);
    let mut kept = String::new();
    archive
        .by_name("kept.class")
        .unwrap()
        .read_to_string(&mut kept)
        .unwrap();
    assert_eq!(kept, "kept");
    for name in COMPILED_CLASSES {
        let path = format!("{CLASS_PACKAGE}/{name}");
        let mut bytes = Vec::new();
        archive
            .by_name(&path)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]));
    }
}

#[test]
fn refuses_stale_or_incompatible_kotlinc_layouts() {
    let temp = tempfile::tempdir().unwrap();
    let stale = temp.path().join("stale.jar");
    let stale_class = format!("{CLASS_PACKAGE}/SniffAnnotationCheckers.class");
    fs::write(
        &stale,
        zip_bytes(&[
            (
                &format!("{CLASS_PACKAGE}/AnalyzerFirExtensionRegistrar.class"),
                b"old-main",
                CompressionMethod::Deflated,
            ),
            (
                &format!("{CLASS_PACKAGE}/AnalyzerFirExtensionRegistrar$configurePlugin$1.class"),
                b"old-closure",
                CompressionMethod::Deflated,
            ),
            (&stale_class, b"stale", CompressionMethod::Deflated),
        ]),
    )
    .unwrap();
    let error = rebuild_kotlinc_jar(
        &stale,
        &temp.path().join("stale-output.jar"),
        &class_entries(),
    )
    .unwrap_err();
    assert!(error.contains("already contains Sniff annotation classes"));

    let missing = temp.path().join("missing.jar");
    fs::write(
        &missing,
        zip_bytes(&[("kept.class", b"kept", CompressionMethod::Deflated)]),
    )
    .unwrap();
    let error = rebuild_kotlinc_jar(
        &missing,
        &temp.path().join("missing-output.jar"),
        &class_entries(),
    )
    .unwrap_err();
    assert!(error.contains("expected 2"));
}

#[test]
fn rebuilt_install_preserves_launcher_prefix_and_requires_one_stored_entry() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("launcher");
    let destination = temp.path().join("patched-launcher");
    let prefix = b"#!/usr/bin/env sh\nexec java -jar \"$0\" \"$@\"\n";
    let mut launcher = prefix.to_vec();
    launcher.extend(zip_bytes(&[
        (SCIP_JAVA_ENTRY, b"original", CompressionMethod::Stored),
        ("kept", b"kept", CompressionMethod::Deflated),
    ]));
    fs::write(&source, launcher).unwrap();
    let rebuilt = temp.path().join("rebuilt.zip");
    fs::write(
        &rebuilt,
        zip_bytes(&[
            (SCIP_JAVA_ENTRY, b"replacement", CompressionMethod::Stored),
            ("kept", b"kept", CompressionMethod::Deflated),
        ]),
    )
    .unwrap();

    install_rebuilt_launcher(&source, &rebuilt, &destination, SCIP_JAVA_ENTRY).unwrap();

    let bytes = fs::read(&destination).unwrap();
    assert!(bytes.starts_with(prefix));
    let mut archive = open_zip(&destination, "fixture launcher").unwrap();
    let mut replaced = String::new();
    let mut entry = archive.by_name(SCIP_JAVA_ENTRY).unwrap();
    assert_eq!(entry.compression(), CompressionMethod::Stored);
    entry.read_to_string(&mut replaced).unwrap();
    assert_eq!(replaced, "replacement");
    drop(entry);
    assert_eq!(read_entry(&mut archive, "kept").unwrap(), b"kept");

    let wrong = temp.path().join("wrong.zip");
    fs::write(
        &wrong,
        zip_bytes(&[(SCIP_JAVA_ENTRY, b"original", CompressionMethod::Deflated)]),
    )
    .unwrap();
    let error = install_rebuilt_launcher(
        &source,
        &wrong,
        &temp.path().join("wrong-output"),
        SCIP_JAVA_ENTRY,
    )
    .unwrap_err();
    assert!(error.contains("is not stored"));
}

#[test]
fn validates_all_nested_patch_classes_and_rejects_corruption() {
    let temp = tempfile::tempdir().unwrap();
    for corrupt in [false, true] {
        let mut classes = class_entries();
        if corrupt {
            classes[0].1 = b"broken".to_vec();
        }
        let class_views = classes
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice(), CompressionMethod::Deflated))
            .collect::<Vec<_>>();
        let kotlinc = zip_bytes(&class_views);
        let java = zip_bytes(&[(SCIP_KOTLINC_ENTRY, &kotlinc, CompressionMethod::Stored)]);
        let path = temp.path().join(if corrupt { "corrupt" } else { "valid" });
        fs::write(&path, java).unwrap();
        if corrupt {
            assert!(validate_patched_scip_java(&path).is_err());
        } else {
            validate_patched_scip_java(&path).unwrap();
        }
    }
}
