use super::*;
use std::fs;
use std::io::Cursor;

#[test]
fn bounded_reader_accepts_exact_and_empty_bytes() {
    assert_eq!(read_bounded(&b"frame"[..], 5, "fixture").unwrap(), b"frame");
    assert!(read_bounded(&b""[..], 0, "fixture").unwrap().is_empty());
}

#[test]
fn bounded_reader_stops_at_sentinel_for_grown_or_nonterminating_input() {
    let mut reader = Cursor::new(b"frame grew beyond metadata");
    assert!(read_bounded(&mut reader, 5, "fixture").is_err());
    assert_eq!(reader.position(), 6);
    assert!(read_bounded(std::io::repeat(b'x'), 5, "fixture").is_err());
}

#[test]
fn bounded_reader_rejects_overflow_without_reading() {
    let mut reader = Cursor::new(b"unread");
    assert!(read_bounded(&mut reader, u64::MAX, "fixture").is_err());
    assert_eq!(reader.position(), 0);
}

#[test]
fn bounded_reader_does_not_downgrade_io_failure() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture failure"))
        }
    }
    assert!(
        read_bounded(Broken, 5, "fixture")
            .unwrap_err()
            .contains("fixture failure")
    );
}

#[test]
fn plain_reader_rejects_missing_directory_and_oversized_input() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frame.json");
    fs::write(&path, b"frame").unwrap();
    assert_eq!(read_plain_file(&path, 5, "fixture").unwrap(), b"frame");
    assert!(read_plain_file(&path, 4, "fixture").is_err());
    assert!(read_plain_file(root.path(), 5, "fixture").is_err());
    assert!(read_plain_file(&root.path().join("missing"), 5, "fixture").is_err());
}

#[test]
fn artifact_reader_rejects_absolute_and_parent_paths() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frame.json");
    fs::write(&path, b"frame").unwrap();
    assert_eq!(read_artifact(root.path(), "frame.json").unwrap(), b"frame");
    assert!(read_artifact(root.path(), &path.to_string_lossy()).is_err());
    assert!(read_artifact(root.path(), "../frame.json").is_err());
}

#[test]
fn binding_rejects_replaced_file_even_when_bytes_match() {
    let root = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(root.path()).unwrap();
    let relative = Path::new("frame.json");
    let path = root.join(relative);
    fs::write(&path, b"frame").unwrap();
    let directory = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
    let file = File::open(&path).unwrap();
    let identity = Handle::from_file(file).unwrap();
    fs::rename(&path, root.join("old-frame.json")).unwrap();
    fs::write(&path, b"frame").unwrap();
    assert!(
        verify_binding(&directory, relative, &identity)
            .unwrap_err()
            .contains("changed its file identity")
    );
}

#[test]
#[cfg(any(unix, windows))]
fn plain_reader_rejects_file_symlink_with_matching_bytes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frame.json");
    let link = root.path().join("alias.json");
    fs::write(&path, b"frame").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&path, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&path, &link).unwrap();
    assert!(read_plain_file(&link, 5, "fixture").is_err());
    assert!(read_artifact(root.path(), "alias.json").is_err());
}

#[test]
#[cfg(any(unix, windows))]
fn artifact_reader_rejects_parent_alias_escape_but_accepts_in_root_alias() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let internal = root.path().join("internal");
    fs::create_dir(&internal).unwrap();
    fs::write(internal.join("frame.json"), b"internal").unwrap();
    fs::write(outside.path().join("frame.json"), b"outside").unwrap();
    for (target, alias) in [(outside.path(), "escape"), (Path::new("internal"), "alias")] {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, root.path().join(alias)).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target, root.path().join(alias)).unwrap();
    }
    assert!(
        read_artifact(root.path(), "escape/frame.json")
            .unwrap_err()
            .contains("escapes the source-seal bundle")
    );
    assert_eq!(
        read_artifact(root.path(), "alias/frame.json").unwrap(),
        b"internal"
    );
}

#[test]
#[cfg(any(unix, windows))]
fn artifact_reader_rejects_absolute_parent_alias_even_inside_root() {
    let root = tempfile::tempdir().unwrap();
    let internal = root.path().join("internal");
    fs::create_dir(&internal).unwrap();
    fs::write(internal.join("frame.json"), b"internal").unwrap();
    let alias = root.path().join("absolute-alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&internal, &alias).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&internal, &alias).unwrap();
    assert!(read_artifact(root.path(), "absolute-alias/frame.json").is_err());
}

#[test]
#[cfg(any(unix, windows))]
fn parent_alias_retargeted_after_inspection_cannot_escape_open_directory() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let internal = root.path().join("internal");
    fs::create_dir(&internal).unwrap();
    fs::write(internal.join("frame.json"), b"trusted").unwrap();
    fs::write(outside.path().join("frame.json"), b"outside").unwrap();
    let alias = root.path().join("alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink("internal", &alias).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir("internal", &alias).unwrap();
    let directory = Dir::open_ambient_dir(root.path(), ambient_authority()).unwrap();
    let result = open_plain_file_after_inspection(
        &directory,
        Path::new("alias/frame.json"),
        7,
        "fixture",
        || {
            #[cfg(unix)]
            fs::remove_file(&alias).unwrap();
            #[cfg(windows)]
            fs::remove_dir(&alias).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(outside.path(), &alias).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(outside.path(), &alias).unwrap();
        },
    );
    assert!(result.is_err(), "retargeted alias opened an outside file");
}
