use super::*;

const SOURCES: [(&str, &str); 6] = [
    ("demo.rs", "fn value() -> i32 { 1 }\n"),
    ("demo.py", "def value():\n    return 1\n"),
    ("demo.js", "export function value() { return 1; }\n"),
    ("demo.ts", "export function value(): number { return 1; }\n"),
    ("demo.go", "package demo\nfunc value() int { return 1 }\n"),
    ("demo.kt", "fun value(): Int = 1\n"),
];

#[test]
fn compiler_source_snapshot_accepts_exact_parsed_bytes_in_every_language() {
    let root = tempfile::tempdir().unwrap();
    for (name, source) in SOURCES {
        let path = root.path().join(name);
        fs::write(&path, source).unwrap();
        let file = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
        assert_eq!(file.methods.len(), 1, "{name}");
        source_integrity_digest_at(root.path(), root.path(), &[file]).unwrap();
    }
}

#[test]
fn compiler_source_snapshot_rejects_pre_baseline_edits_with_unchanged_method_identity() {
    let root = tempfile::tempdir().unwrap();
    for (name, source) in SOURCES {
        let path = root.path().join(name);
        fs::write(&path, source).unwrap();
        let original = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
        let edited_source = source.replace('1', "2");
        fs::write(&path, &edited_source).unwrap();
        let edited = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
        let identity = |file: &FileRecord| {
            file.methods
                .iter()
                .map(|method| (method.name.clone(), method.start_line, method.end_line))
                .collect::<Vec<_>>()
        };
        assert_eq!(identity(&original), identity(&edited), "{name}");
        let error = source_integrity_digest_at(root.path(), root.path(), &[original]).unwrap_err();
        assert!(
            error.contains("differs from parsed source snapshot"),
            "{name}"
        );
        source_integrity_digest_at(root.path(), root.path(), &[edited]).unwrap();
    }
}

#[test]
fn compiler_source_snapshot_checks_staged_bytes_not_only_the_live_repository() {
    let root = tempfile::tempdir().unwrap();
    let staged = tempfile::tempdir().unwrap();
    let (name, source) = SOURCES[0];
    let path = root.path().join(name);
    fs::write(&path, source).unwrap();
    fs::write(staged.path().join(name), source).unwrap();
    let file = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
    let expected = source_integrity_digest_at(root.path(), root.path(), &[file.clone()]).unwrap();
    assert_eq!(
        expected,
        source_integrity_digest_at(root.path(), staged.path(), &[file.clone()]).unwrap()
    );
    fs::write(staged.path().join(name), source.replace('1', "2")).unwrap();
    assert!(source_integrity_digest_at(root.path(), staged.path(), &[file.clone()]).is_err());
    fs::write(staged.path().join(name), source).unwrap();
    fs::write(&path, source.replace('1', "2")).unwrap();
    assert_eq!(
        expected,
        source_integrity_digest_at(root.path(), staged.path(), &[file]).unwrap()
    );
}

#[test]
fn compiler_source_snapshot_rejects_duplicate_and_missing_documents() {
    let root = tempfile::tempdir().unwrap();
    let staged = tempfile::tempdir().unwrap();
    let (name, source) = SOURCES[0];
    let path = root.path().join(name);
    fs::write(&path, source).unwrap();
    let file = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
    let error = source_integrity_digest_at(root.path(), root.path(), &[file.clone(), file.clone()])
        .unwrap_err();
    assert!(error.contains("repeats document"));
    assert!(source_integrity_digest_at(root.path(), staged.path(), &[file]).is_err());
}

#[tokio::test]
async fn compiler_source_snapshot_rejects_stale_ast_before_installation_or_execution() {
    use super::super::{SemanticIndexerRunFailureKind, SemanticIndexerRunPhase};
    let root = tempfile::tempdir().unwrap();
    for (name, source) in SOURCES {
        let path = root.path().join(name);
        fs::write(&path, source).unwrap();
        let original = crate::parser::parse_file_checked(path.to_str().unwrap()).unwrap();
        fs::write(&path, source.replace('1', "2")).unwrap();
        let files = [original];
        let result = super::super::run_required_indexers_exhaustive_typed_scoped_with_variants(
            root.path(),
            &files,
            &files,
            &BTreeMap::new(),
        )
        .await;
        let Err(failure) = result else {
            panic!("stale AST source was accepted for {name}");
        };
        assert_eq!(failure.kind, SemanticIndexerRunFailureKind::InvalidInput);
        assert_eq!(
            failure.phase,
            SemanticIndexerRunPhase::IntegrityVerification
        );
        assert!(
            failure
                .detail
                .contains("differs from parsed source snapshot")
        );
    }
}
