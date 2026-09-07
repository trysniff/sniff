use super::*;
use flate2::{Compression, write::GzEncoder};
use std::io::Cursor;

fn package() -> PinnedNpmPackage {
    PinnedNpmPackage {
        name: "@scope/example",
        version: "1.2.3",
        url: "https://registry.npmjs.org/@scope/example/-/example-1.2.3.tgz",
        integrity_sha512: "fixture",
    }
}

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(*bytes))
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn installs_regular_files_and_validates_package_identity() {
    let root = tempfile::tempdir().unwrap();
    let bytes = archive(&[
        (
            "package/package.json",
            br#"{"name":"@scope/example","version":"1.2.3"}"#,
        ),
        ("package/index.js", b"module.exports = 1;"),
    ]);

    unpack(root.path(), &package(), &bytes).unwrap();
    validate_package_identity(root.path(), &package()).unwrap();

    assert_eq!(
        fs::read(root.path().join("node_modules/@scope/example/index.js")).unwrap(),
        b"module.exports = 1;"
    );
}

#[test]
fn rejects_paths_outside_the_single_npm_package_root() {
    assert!(npm_entry_relative_path(Path::new("../escape")).is_err());
    assert!(npm_entry_relative_path(Path::new("other/file")).is_err());
    assert!(npm_entry_relative_path(Path::new("package/../escape")).is_err());
    assert!(npm_entry_relative_path(Path::new("package\\..\\escape")).is_err());
    assert_eq!(npm_entry_relative_path(Path::new("package")).unwrap(), None);
}

#[test]
fn rejects_duplicate_package_names_and_untrusted_urls() {
    let duplicate = package();
    assert!(validate_package_set(&[duplicate, duplicate]).is_err());
    let mut untrusted = package();
    untrusted.url = "https://example.test/package.tgz";
    assert!(validate_package_set(&[untrusted]).is_err());

    let mut invalid_integrity = package();
    invalid_integrity.integrity_sha512 = "not-base64";
    assert!(validate_package_set(&[invalid_integrity]).is_err());
}

#[test]
fn rejects_integrity_and_identity_drift() {
    let bytes = b"archive";
    assert!(verify_integrity(&package(), bytes).is_err());

    let root = tempfile::tempdir().unwrap();
    let archive = archive(&[(
        "package/package.json",
        br#"{"name":"@scope/example","version":"9.9.9"}"#,
    )]);
    unpack(root.path(), &package(), &archive).unwrap();
    assert!(validate_package_identity(root.path(), &package()).is_err());
}

#[test]
fn rejects_non_file_tar_entries() {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_link_name("outside").unwrap();
    header.set_cksum();
    builder
        .append_data(&mut header, "package/link", Cursor::new([]))
        .unwrap();
    let bytes = builder.into_inner().unwrap().finish().unwrap();

    let root = tempfile::tempdir().unwrap();
    assert!(unpack(root.path(), &package(), &bytes).is_err());
}
