use super::*;
use tempfile::TempDir;

fn write(root: &Path, path: &str) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, "fixture\n").unwrap();
}

fn paths(paths: &[&str]) -> BTreeSet<RepositoryPath> {
    paths
        .iter()
        .map(|path| RepositoryPath((*path).to_string()))
        .collect()
}

#[test]
fn census_owns_nested_modules_and_tests_without_git_or_scan_scope() {
    let root = TempDir::new().unwrap();
    for path in [
        "go.mod",
        "main.go",
        "main_test.go",
        "feature/tagged.go",
        "nested/go.mod",
        "nested/nested.go",
    ] {
        write(root.path(), path);
    }
    let scope = discover(root.path()).unwrap();
    assert_eq!(scope.modules.len(), 2);
    assert_eq!(
        scope.modules[&RepositoryPath("go.mod".to_string())],
        paths(&["main.go", "main_test.go", "feature/tagged.go"])
    );
    assert_eq!(
        scope.modules[&RepositoryPath("nested/go.mod".to_string())],
        paths(&["nested/nested.go"])
    );
    scope.require_source_owners(&paths(&["main.go"])).unwrap();
    assert!(!root.path().join(".git").exists());
}

#[test]
fn compiler_pattern_exclusions_are_not_claimed_as_owned_sources() {
    let root = TempDir::new().unwrap();
    for path in [
        "go.mod",
        "main.go",
        "vendor/lib/a.go",
        "testdata/a.go",
        ".hidden/a.go",
        "_hidden/a.go",
        "_ignored.go",
        ".ignored.go",
        "build/a.go",
        "examples/a.go",
    ] {
        write(root.path(), path);
    }
    let scope = discover(root.path()).unwrap();
    assert_eq!(
        scope.modules[&RepositoryPath("go.mod".to_string())],
        paths(&["main.go", "build/a.go", "examples/a.go"])
    );
    assert!(
        scope
            .require_source_owners(&paths(&["testdata/a.go"]))
            .unwrap_err()
            .contains("no plain module/package-pattern owner")
    );
}

#[test]
fn malformed_manifest_and_nested_workspace_fail_closed() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("go.mod")).unwrap();
    assert!(
        discover(root.path())
            .unwrap_err()
            .contains("not a plain file")
    );
    let root = TempDir::new().unwrap();
    write(root.path(), "go.mod");
    write(root.path(), "nested/go.work");
    discover(root.path()).unwrap();
    write(root.path(), "nested/go.mod");
    assert!(
        discover(root.path())
            .unwrap_err()
            .contains("module closure")
    );
}

#[test]
fn workspace_scope_is_inherited_by_modules_not_unrelated_siblings() {
    let root = TempDir::new().unwrap();
    for path in [
        "go.mod",
        "main.go",
        "docs/go.work",
        "sibling/go.mod",
        "sibling/pkg.go",
    ] {
        write(root.path(), path);
    }
    let scope = discover(root.path()).unwrap();
    scope
        .require_source_owners(&paths(&["main.go", "sibling/pkg.go"]))
        .unwrap();
    write(root.path(), "docs/intermediate/nested/go.mod");
    assert!(
        discover(root.path())
            .unwrap_err()
            .contains("module closure")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_assets_are_irrelevant_but_non_utf8_go_sources_are_rejected() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let root = TempDir::new().unwrap();
    write(root.path(), "go.mod");
    write(root.path(), "main.go");
    fs::write(
        root.path()
            .join(OsString::from_vec(vec![0xff, b'.', b'p', b'n', b'g'])),
        "asset",
    )
    .unwrap();
    let directory = root.path().join(OsString::from_vec(vec![0xff]));
    fs::create_dir(&directory).unwrap();
    discover(root.path())
        .unwrap()
        .require_source_owners(&paths(&["main.go"]))
        .unwrap();
    fs::write(directory.join("invalid.go"), "source").unwrap();
    assert!(discover(root.path()).unwrap_err().contains("not UTF-8"));
}

#[cfg(unix)]
#[test]
fn normal_guard_rejects_selected_internal_symlink_before_owner_normalization() {
    let root = TempDir::new().unwrap();
    write(root.path(), "go.mod");
    fs::create_dir(root.path().join("real")).unwrap();
    fs::write(
        root.path().join("real/pkg.go"),
        "package main\nfunc main() {}\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(root.path().join("real"), root.path().join("alias")).unwrap();
    let source = root.path().join("alias/pkg.go");
    let file = crate::parser::parse_file_checked(source.to_str().unwrap()).unwrap();
    assert!(
        require_normal_source_scope(root.path(), &[file])
            .unwrap_err()
            .detail
            .contains("passes through a symlink")
    );
}

#[cfg(unix)]
#[test]
fn normal_guard_rejects_external_alias_to_repository_root() {
    let root = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    write(root.path(), "go.mod");
    fs::write(root.path().join("pkg.go"), "package main\nfunc main() {}\n").unwrap();
    let alias = external.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias).unwrap();
    let source = alias.join("pkg.go");
    let file = crate::parser::parse_file_checked(source.to_str().unwrap()).unwrap();
    assert!(
        require_normal_source_scope(root.path(), &[file])
            .unwrap_err()
            .detail
            .contains("passes through a symlink")
    );
}

#[cfg(unix)]
#[test]
fn normal_guard_preserves_aliases_above_but_not_inside_repository_root() {
    let parent = TempDir::new().unwrap();
    let root = parent.path().join("real/project");
    write(&root, "go.mod");
    fs::write(root.join("pkg.go"), "package main\nfunc main() {}\n").unwrap();
    let alias = parent.path().join("alias");
    std::os::unix::fs::symlink(parent.path().join("real"), &alias).unwrap();
    let source = alias.join("project/pkg.go");
    let file = crate::parser::parse_file_checked(source.to_str().unwrap()).unwrap();
    require_normal_source_scope(&root, &[file]).unwrap();

    std::os::unix::fs::symlink(&root, root.join("back-to-root")).unwrap();
    let source = root.join("back-to-root/pkg.go");
    let file = crate::parser::parse_file_checked(source.to_str().unwrap()).unwrap();
    assert!(
        require_normal_source_scope(&root, &[file])
            .unwrap_err()
            .detail
            .contains("passes through a symlink")
    );
}

#[test]
fn source_outside_every_module_is_not_silently_dropped() {
    let root = TempDir::new().unwrap();
    write(root.path(), "main.go");
    assert!(
        discover(root.path())
            .unwrap_err()
            .contains("no module owner")
    );
}

#[test]
fn normal_guard_checks_the_actual_parsed_source_scope() {
    let root = TempDir::new().unwrap();
    write(root.path(), "go.mod");
    let source = root.path().join("testdata/main.go");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, "package main\nfunc main() {}\n").unwrap();
    let file = crate::parser::parse_file_checked(source.to_str().unwrap()).unwrap();
    let failure = require_normal_source_scope(root.path(), &[file]).unwrap_err();
    assert_eq!(
        failure.phase,
        super::super::SemanticIndexerRunPhase::RepositoryValidation
    );
    assert!(failure.detail.contains("testdata/main.go"));
}

#[cfg(unix)]
#[test]
fn symbolic_manifest_and_source_are_not_followed() {
    for path in ["go.mod", "alias.go"] {
        let root = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        write(external.path(), "external.go");
        if path != "go.mod" {
            write(root.path(), "go.mod");
        }
        let target = external.path().join("external.go");
        std::os::unix::fs::symlink(target, root.path().join(path)).unwrap();
        assert!(discover(root.path()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn unrelated_symlink_does_not_reject_a_module_or_create_source_ownership() {
    let root = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    write(root.path(), "go.mod");
    write(root.path(), "main.go");
    write(external.path(), "external.go");
    std::os::unix::fs::symlink(external.path(), root.path().join("alias")).unwrap();
    std::os::unix::fs::symlink(
        external.path().join("missing"),
        root.path().join("readme-link"),
    )
    .unwrap();
    let scope = discover(root.path()).unwrap();
    scope.require_source_owners(&paths(&["main.go"])).unwrap();
    assert!(
        scope
            .require_source_owners(&paths(&["alias/external.go"]))
            .is_err()
    );
}
