use super::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn repository(files: &[(&str, &str)]) -> (TempDir, String, IntentionalBoundaryRepositoryInventory) {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "SniffBench"]);
    git(
        root.path(),
        &["config", "user.email", "bench@example.invalid"],
    );
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/manifests.git",
        ],
    );
    for (path, source) in files {
        let target = root.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(target, source).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/manifests",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, revision, inventory)
}

fn range_text<'a>(source: &'a str, range: &IntentionalBoundarySemanticRange) -> &'a str {
    let starts = std::iter::once(0)
        .chain(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        )
        .collect::<Vec<_>>();
    let start =
        starts[range.start_line_zero_based as usize] + range.start_character_zero_based as usize;
    let end = starts[range.end_line_zero_based as usize] + range.end_character_zero_based as usize;
    &source[start..end]
}

#[test]
fn censuses_typed_cargo_node_and_python_declarations_with_exact_spans() {
    let cargo = "[package]\nname='sample'\nversion='1.0.0'\nbuild='build.rs'\n[lib]\npath='rust/lib.rs'\n[[bin]]\nname='sample'\npath='rust/main.rs'\n";
    let package = r#"{"exports":{".":"./js/index.js","./feature":["./js/feature.js",null]},"main":"./js/legacy.js","bin":{"tool":"./js/cli.js"}}"#;
    let pyproject = "[project]\nname='sample'\n[project.scripts]\ndemo='demo.cli:main'\n[project.entry-points.\"demo.plugins\"]\nsample='demo.plugin:Plugin.create'\n";
    let (root, revision, inventory) = repository(&[
        ("Cargo.toml", cargo),
        ("package.json", package),
        ("pyproject.toml", pyproject),
    ]);

    let census = census_intentional_boundary_manifests(
        "github.com/example/manifests",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();

    assert_eq!(census.documents.len(), 3);
    assert_eq!(census.declarations.len(), 9);
    assert!(
        census
            .declarations
            .iter()
            .all(|declaration| declaration.declaration_id.starts_with("ibmd-v1:"))
    );
    assert_eq!(
        census
            .declaration_count_by_kind
            .get(&IntentionalBoundaryManifestDeclarationKind::PublishedModule),
        Some(&4)
    );
    assert_eq!(
        census
            .declaration_count_by_kind
            .get(&IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint),
        Some(&4)
    );
    assert_eq!(
        census
            .declaration_count_by_kind
            .get(&IntentionalBoundaryManifestDeclarationKind::BuildScript),
        Some(&1)
    );
    let node_export = census
        .declarations
        .iter()
        .find(|declaration| {
            declaration.manifest_repository_path == "package.json"
                && declaration.target
                    == (IntentionalBoundaryManifestTarget::RepositoryPath {
                        repository_path: "js/index.js".to_string(),
                    })
        })
        .unwrap();
    assert_eq!(
        range_text(package, &node_export.declaration_location),
        "\"./js/index.js\""
    );
    assert!(census.declarations.iter().any(|declaration| {
        declaration.target
            == (IntentionalBoundaryManifestTarget::PythonObject {
                module: vec!["demo".to_string(), "plugin".to_string()],
                qualname: vec!["Plugin".to_string(), "create".to_string()],
            })
    }));
    assert_eq!(census.manifest_census_sha256.len(), 64);
    validate_intentional_boundary_manifest_census(
        "github.com/example/manifests",
        &revision,
        root.path(),
        &inventory,
        &census,
    )
    .unwrap();
}

#[test]
fn commits_recognized_manifests_that_have_no_target_declarations() {
    let (root, revision, inventory) = repository(&[
        ("Cargo.toml", "[package]\nname='sample'\nversion='1.0.0'\n"),
        ("package.json", "{\"name\":\"sample\"}"),
        ("pyproject.toml", "[project]\nname='sample'\n"),
    ]);

    let census = census_intentional_boundary_manifests(
        "github.com/example/manifests",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();

    assert_eq!(census.documents.len(), 3);
    assert!(census.declarations.is_empty());
    assert!(
        census
            .documents
            .iter()
            .all(|document| document.declaration_count == 0)
    );
}

#[test]
fn package_scripts_are_typed_with_exact_names_commands_and_spans() {
    let package = r#"{"name":"sample","packageManager":"pnpm@10.15.0","scripts":{"generate":"node tools/generate.js","test":"node --test"}}"#;
    let (root, revision, inventory) = repository(&[("package.json", package)]);

    let census = census_intentional_boundary_manifests(
        "github.com/example/manifests",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();

    let scripts = census
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.declaration_kind
                == IntentionalBoundaryManifestDeclarationKind::PackageScript
        })
        .collect::<Vec<_>>();
    assert_eq!(scripts.len(), 2);
    let generate = scripts
        .iter()
        .find(|declaration| {
            matches!(
                &declaration.target,
                IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                    if script_name == "generate"
            )
        })
        .unwrap();
    assert_eq!(
        generate.target,
        IntentionalBoundaryManifestTarget::PackageScript {
            script_name: "generate".to_string(),
            command: "node tools/generate.js".to_string(),
            package_manager: Some("pnpm@10.15.0".to_string()),
        }
    );
    assert_eq!(
        range_text(package, &generate.declaration_location),
        "\"node tools/generate.js\""
    );
}

#[test]
fn package_scripts_reject_non_string_commands() {
    let (root, revision, inventory) = repository(&[(
        "package.json",
        r#"{"name":"sample","scripts":{"generate":["node","generate.js"]}}"#,
    )]);

    assert!(
        census_intentional_boundary_manifests(
            "github.com/example/manifests",
            &revision,
            root.path(),
            &inventory,
        )
        .unwrap_err()
        .contains("package script must be a string")
    );
}

#[test]
fn rejects_duplicate_json_keys_and_targets_that_escape_the_repository() {
    let (duplicate, revision, inventory) = repository(&[(
        "package.json",
        "{\"main\":\"./one.js\",\"main\":\"./two.js\"}",
    )]);
    assert!(
        census_intentional_boundary_manifests(
            "github.com/example/manifests",
            &revision,
            duplicate.path(),
            &inventory,
        )
        .unwrap_err()
        .contains("repeats JSON key")
    );

    let (escape, revision, inventory) =
        repository(&[("package.json", "{\"main\":\"../outside.js\"}")]);
    assert!(
        census_intentional_boundary_manifests(
            "github.com/example/manifests",
            &revision,
            escape.path(),
            &inventory,
        )
        .unwrap_err()
        .contains("escapes the repository")
    );
}

#[test]
fn replay_validation_rejects_manifest_census_tampering() {
    let (root, revision, inventory) = repository(&[(
        "pyproject.toml",
        "[project]\nname='sample'\n[project.scripts]\ndemo='demo:main'\n",
    )]);
    let mut census = census_intentional_boundary_manifests(
        "github.com/example/manifests",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();
    census.declarations.clear();

    assert!(
        validate_intentional_boundary_manifest_census(
            "github.com/example/manifests",
            &revision,
            root.path(),
            &inventory,
            &census,
        )
        .unwrap_err()
        .contains("changed")
    );
}
