use super::*;
use std::fs;
use std::io::Write;
use std::process::Command;
use zip::write::SimpleFileOptions;

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

fn repository(
    pyproject: &str,
) -> (
    tempfile::TempDir,
    String,
    IntentionalBoundaryRepositoryInventory,
) {
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
            "https://github.com/example/python-surfaces.git",
        ],
    );
    fs::write(root.path().join("pyproject.toml"), pyproject).unwrap();
    fs::create_dir_all(root.path().join("src/pkg")).unwrap();
    fs::write(
        root.path().join("src/pkg/__init__.py"),
        "from .api import run\n",
    )
    .unwrap();
    fs::write(
        root.path().join("src/pkg/api.py"),
        "def run():\n    return 1\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, revision, inventory)
}

fn valid_pyproject() -> &'static str {
    r#"[build-system]
requires = ["hatchling==1.27.0"]
build-backend = "hatchling.build"

[project]
name = "Example_Package"
version = "1.2.3"
"#
}

fn wheel_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "example_package-1.2.3.dist-info/METADATA".to_string(),
            b"Metadata-Version: 2.4\nName: Example_Package\nVersion: 1.2.3\n\n".to_vec(),
        ),
        (
            "example_package-1.2.3.dist-info/WHEEL".to_string(),
            b"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
                .to_vec(),
        ),
        (
            "pkg/__init__.py".to_string(),
            b"from .api import run\n".to_vec(),
        ),
        (
            "pkg/api.py".to_string(),
            b"def run():\n    return 1\n".to_vec(),
        ),
        (
            "pkg/api.pyi".to_string(),
            b"def run() -> int: ...\n".to_vec(),
        ),
        ("namespace/child.py".to_string(), b"VALUE = 1\n".to_vec()),
        ("single.py".to_string(), b"VALUE = 2\n".to_vec()),
        (
            "example_package-1.2.3.data/purelib/extra.py".to_string(),
            b"VALUE = 3\n".to_vec(),
        ),
    ])
}

fn build_wheel(mut files: BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let dist_info = files
        .keys()
        .filter_map(|path| path.strip_suffix("/METADATA"))
        .collect::<Vec<_>>();
    let [dist_info] = dist_info.as_slice() else {
        panic!("fixture must contain exactly one METADATA member");
    };
    let record_path = format!("{dist_info}/RECORD");
    let mut record = String::new();
    for (path, contents) in &files {
        let digest =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(contents));
        record.push_str(&format!("{path},sha256={digest},{}\n", contents.len()));
    }
    record.push_str(&format!("{record_path},,\n"));
    files.insert(record_path, record.into_bytes());

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (path, contents) in files {
        writer.start_file(path, options).unwrap();
        writer.write_all(&contents).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn python_distribution_census_commits_verified_wheel_modules() {
    let (root, revision, inventory) = repository(valid_pyproject());
    let wheel = build_wheel(wheel_files());

    let census = census_historical_v2_python_distribution_surfaces_with_executor(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
        &inventory,
        |_, manifest| {
            assert_eq!(manifest, "pyproject.toml");
            Ok(PythonWheelBuildOutput {
                toolchain_identity_sha256: "a".repeat(64),
                wheel_filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
                wheel_bytes: wheel.clone(),
            })
        },
    )
    .unwrap();

    assert_eq!(census.distributions.len(), 1);
    let distribution = &census.distributions[0];
    assert_eq!(distribution.distribution_name, "Example_Package");
    assert_eq!(distribution.normalized_distribution_name, "example-package");
    assert_eq!(distribution.distribution_version, "1.2.3");
    assert_eq!(
        distribution.wheel_root,
        HistoricalV2PythonWheelRoot::Purelib
    );
    assert_eq!(distribution.module_count, 7);
    assert_eq!(census.modules.len(), 7);
    assert!(census.modules.iter().any(|module| {
        module.import_name == "pkg"
            && module.kind == HistoricalV2PythonModuleKind::SourcePackageInit
            && module.is_distribution_root
    }));
    assert!(census.modules.iter().any(|module| {
        module.import_name == "pkg.api"
            && module.kind == HistoricalV2PythonModuleKind::StubModule
            && !module.is_distribution_root
    }));
    assert!(census.modules.iter().any(|module| {
        module.import_name == "namespace"
            && module.kind == HistoricalV2PythonModuleKind::NamespacePackage
            && module.archive_member_path.is_none()
            && module.is_distribution_root
    }));
    assert!(census.modules.iter().any(|module| {
        module.import_name == "extra"
            && module.installed_path.as_deref() == Some("extra.py")
            && module.is_distribution_root
    }));

    validate_historical_v2_python_distribution_surface_census_with_executor(
        root.path(),
        &inventory,
        &census,
        |_, _| {
            Ok(PythonWheelBuildOutput {
                toolchain_identity_sha256: "a".repeat(64),
                wheel_filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
                wheel_bytes: wheel.clone(),
            })
        },
    )
    .unwrap();

    let mut tampered = census.clone();
    tampered.modules[0].import_name = "invented".to_string();
    tampered.census_sha256 = python_distribution_surface_census_sha256(&tampered).unwrap();
    let error = validate_historical_v2_python_distribution_surface_census_with_executor(
        root.path(),
        &inventory,
        &tampered,
        |_, _| {
            Ok(PythonWheelBuildOutput {
                toolchain_identity_sha256: "a".repeat(64),
                wheel_filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
                wheel_bytes: wheel.clone(),
            })
        },
    )
    .unwrap_err();
    assert!(error.contains("census changed"), "{error}");
}

#[test]
fn python_distribution_census_ignores_tooling_only_pyproject() {
    let (root, revision, inventory) = repository("[tool.ruff]\nline-length = 88\n");
    let census = census_historical_v2_python_distribution_surfaces_with_executor(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
        &inventory,
        |_, _| panic!("tooling-only pyproject must not be built"),
    )
    .unwrap();

    assert!(census.distributions.is_empty());
    assert!(census.modules.is_empty());
}

#[test]
fn python_distribution_census_requires_explicit_pep517_backend() {
    let pyproject = "[build-system]\nrequires = ['setuptools==80.0.0']\n";
    let (root, revision, inventory) = repository(pyproject);
    let error = census_historical_v2_python_distribution_surfaces_with_executor(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
        &inventory,
        |_, _| unreachable!(),
    )
    .unwrap_err();

    assert!(error.contains("build-system.build-backend"), "{error}");
}

#[test]
fn python_distribution_census_rejects_record_hash_mismatch() {
    let (root, revision, inventory) = repository(valid_pyproject());
    let record_path = "example_package-1.2.3.dist-info/RECORD";
    let mut mismatched = wheel_files();
    let record_source = build_wheel(mismatched.clone());
    let mut parsed = zip::ZipArchive::new(Cursor::new(record_source)).unwrap();
    let mut record = Vec::new();
    parsed
        .by_name(record_path)
        .unwrap()
        .read_to_end(&mut record)
        .unwrap();
    mismatched.insert("pkg/api.py".to_string(), b"different\n".to_vec());
    mismatched.insert(record_path.to_string(), record);
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    for (path, contents) in mismatched {
        writer.start_file(path, options).unwrap();
        writer.write_all(&contents).unwrap();
    }
    let wheel = writer.finish().unwrap().into_inner();

    let error = census_historical_v2_python_distribution_surfaces_with_executor(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
        &inventory,
        |_, _| {
            Ok(PythonWheelBuildOutput {
                toolchain_identity_sha256: "a".repeat(64),
                wheel_filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
                wheel_bytes: wheel.clone(),
            })
        },
    )
    .unwrap_err();

    assert!(
        error.contains("RECORD hash mismatch for pkg/api.py"),
        "{error}"
    );
}

#[test]
fn python_wheel_rejects_dynamic_import_paths_and_module_package_collisions() {
    let mut with_pth = wheel_files();
    with_pth.insert("dynamic.pth".to_string(), b"../outside\n".to_vec());
    let error = parse_wheel(
        "example_package-1.2.3-py3-none-any.whl",
        &build_wheel(with_pth),
    )
    .unwrap_err();
    assert!(
        error.contains("dynamic or bytecode-only import state"),
        "{error}"
    );

    let mut collision = wheel_files();
    collision.insert("namespace.py".to_string(), b"VALUE = 2\n".to_vec());
    let error = parse_wheel(
        "example_package-1.2.3-py3-none-any.whl",
        &build_wheel(collision),
    )
    .unwrap_err();
    assert!(
        error.contains("both module and package identities"),
        "{error}"
    );
}

#[test]
fn python_wheel_filename_must_match_verified_metadata() {
    let error = parse_wheel(
        "different-1.2.3-py3-none-any.whl",
        &build_wheel(wheel_files()),
    )
    .unwrap_err();

    assert!(error.contains("disagrees with METADATA Name"), "{error}");
}

#[test]
fn python_wheel_accepts_normalized_pep_440_epoch_and_local_version() {
    let dist_info = "example_package-1!2.0+cpu.dist-info";
    let files = BTreeMap::from([
        (
            format!("{dist_info}/METADATA"),
            b"Metadata-Version: 2.4\nName: Example_Package\nVersion: 1!2.0+CPU\n\n".to_vec(),
        ),
        (
            format!("{dist_info}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
                .to_vec(),
        ),
        ("pkg/__init__.py".to_string(), b"VALUE = 1\n".to_vec()),
    ]);

    let wheel = parse_wheel(
        "example_package-1!2.0+cpu-py3-none-any.whl",
        &build_wheel(files),
    )
    .unwrap();

    assert_eq!(wheel.distribution_version, "1!2.0+CPU");
}

#[test]
fn python_wheel_rejects_non_pep_440_metadata_version() {
    let mut files = wheel_files();
    files.insert(
        "example_package-1.2.3.dist-info/METADATA".to_string(),
        b"Metadata-Version: 2.4\nName: Example_Package\nVersion: definitely not a version\n\n"
            .to_vec(),
    );

    let error = parse_wheel(
        "example_package-1.2.3-py3-none-any.whl",
        &build_wheel(files),
    )
    .unwrap_err();

    assert!(error.contains("Version is not PEP 440"), "{error}");
}

#[test]
fn python_distribution_manifest_rejects_escaping_backend_path() {
    let pyproject = r#"[build-system]
requires = ["fixture==1.0.0"]
build-backend = "fixture.build"
backend-path = ["../outside"]
"#;
    let (root, revision, inventory) = repository(pyproject);
    let error = census_historical_v2_python_distribution_surfaces_with_executor(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
        &inventory,
        |_, _| unreachable!(),
    )
    .unwrap_err();

    assert!(error.contains("backend-path escapes"), "{error}");
}

#[test]
fn python_distribution_manifest_accepts_explicit_dependency_free_backend() {
    let pyproject = r#"[build-system]
requires = []
build-backend = "fixture_backend"
backend-path = ["."]
"#;
    let (root, revision, inventory) = repository(pyproject);
    let wheel = build_wheel(wheel_files());
    let census = census_historical_v2_python_distribution_surfaces_with_executor(
        "github.com/example/python-surfaces",
        &revision,
        root.path(),
        &inventory,
        |_, _| {
            Ok(PythonWheelBuildOutput {
                toolchain_identity_sha256: "a".repeat(64),
                wheel_filename: "example_package-1.2.3-py3-none-any.whl".to_string(),
                wheel_bytes: wheel.clone(),
            })
        },
    )
    .unwrap();

    assert!(census.distributions[0].build_requirements.is_empty());
    assert_eq!(census.distributions[0].backend_path, [".".to_string()]);
}

#[test]
fn python_wheel_rejects_unsafe_and_symlink_members() {
    let options = SimpleFileOptions::default();
    let mut unsafe_writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    unsafe_writer.start_file("../escape.py", options).unwrap();
    unsafe_writer.write_all(b"VALUE = 1\n").unwrap();
    let unsafe_wheel = unsafe_writer.finish().unwrap().into_inner();
    let error = parse_wheel("unsafe-1.0.0-py3-none-any.whl", &unsafe_wheel).unwrap_err();
    assert!(error.contains("member path is unsafe"), "{error}");

    let mut symlink_writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    symlink_writer
        .add_symlink("pkg/link.py", "target.py", options)
        .unwrap();
    let symlink_wheel = symlink_writer.finish().unwrap().into_inner();
    let error = parse_wheel("unsafe-1.0.0-py3-none-any.whl", &symlink_wheel).unwrap_err();
    assert!(error.contains("not a regular file or directory"), "{error}");
}
