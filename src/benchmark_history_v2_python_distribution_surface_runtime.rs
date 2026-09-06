use super::super::intentional_boundary_runtime_snapshot::{
    IntentionalBoundaryRuntimeSnapshot, allocate_runtime_directory,
};
use super::super::non_blind_history_runtime::{
    persist_historical_runtime_directories, prepare_historical_runtime,
};
use super::super::python_build_requirement::PYPI_SIMPLE_INDEX;
use super::super::python_build_toolchain_prepare::{
    PythonBuildToolchainMaterialization, materialize_python_build_toolchain,
};
use super::super::python_build_toolchain_store::{
    PythonBuildToolchainStore, python_environment_tree_sha256,
};
use super::*;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const PYTHON_WHEEL_BUILD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PYTHON_WHEEL_BUILD_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const MAX_WHEEL_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const PYTHON_WHEEL_BACKEND_RUNNER: &[u8] =
    include_bytes!("benchmark_python_wheel_backend_runner.py");

struct PythonWheelBuildCallRuntime(PathBuf);

impl PythonWheelBuildCallRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        allocate_runtime_directory(root, ".sniff-python-wheel-call").map(Self)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PythonWheelBuildCallRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(in crate::benchmark::release) fn census_historical_v2_python_distribution_surfaces(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<HistoricalV2PythonDistributionSurfaceCensus, String> {
    validate_intentional_boundary_repository_inventory_typed(repository, revision, root, inventory)
        .map_err(|error| error.detail)?;
    let snapshot =
        IntentionalBoundaryRuntimeSnapshot::create(root, revision, "sniff-python-wheel-snapshot")?;
    census_historical_v2_python_distribution_surfaces_with_executor(
        repository,
        revision,
        root,
        inventory,
        |_, manifest_repository_path| {
            run_python_wheel_build(&snapshot, revision, manifest_repository_path)
        },
    )
}

pub(in crate::benchmark::release) fn validate_historical_v2_python_distribution_surface_census_commitment(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &HistoricalV2PythonDistributionSurfaceCensus,
) -> Result<(), String> {
    validate_intentional_boundary_repository_inventory_typed(
        &inventory.repository,
        &inventory.revision,
        root,
        inventory,
    )
    .map_err(|error| error.detail)?;
    let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
        root,
        &inventory.revision,
        "sniff-python-wheel-validation",
    )?;
    validate_historical_v2_python_distribution_surface_census_with_executor(
        root,
        inventory,
        census,
        |_, manifest_repository_path| {
            run_python_wheel_build(&snapshot, &inventory.revision, manifest_repository_path)
        },
    )
}

fn run_python_wheel_build(
    snapshot: &IntentionalBoundaryRuntimeSnapshot,
    revision: &str,
    manifest_repository_path: &str,
) -> Result<PythonWheelBuildOutput, String> {
    let store = PythonBuildToolchainStore::for_user()?;
    run_python_wheel_build_with_store(snapshot, revision, manifest_repository_path, &store)
}

fn run_python_wheel_build_with_store(
    snapshot: &IntentionalBoundaryRuntimeSnapshot,
    revision: &str,
    manifest_repository_path: &str,
    store: &PythonBuildToolchainStore,
) -> Result<PythonWheelBuildOutput, String> {
    run_python_wheel_build_with_store_and_index(
        snapshot,
        revision,
        manifest_repository_path,
        store,
        PYPI_SIMPLE_INDEX,
    )
}

fn run_python_wheel_build_with_store_and_index(
    snapshot: &IntentionalBoundaryRuntimeSnapshot,
    revision: &str,
    manifest_repository_path: &str,
    store: &PythonBuildToolchainStore,
    package_index: &str,
) -> Result<PythonWheelBuildOutput, String> {
    let manifest = read_python_build_manifest(snapshot.path(), manifest_repository_path)?;
    let root = snapshot.sandbox_root();
    let runtime = PythonWheelBuildCallRuntime::create(root)?;
    let cache = runtime.path().join("cache");
    let output = cache.join("wheel-output");
    let runner = cache.join("pep517_runner.py");
    let requirements_contract = cache.join("requirements-contract.json");
    fs::create_dir(&cache)
        .map_err(|error| format!("failed to create private Python wheel cache: {error}"))?;
    fs::create_dir(&output)
        .map_err(|error| format!("failed to create private Python wheel output: {error}"))?;
    fs::write(&runner, PYTHON_WHEEL_BACKEND_RUNNER)
        .map_err(|error| format!("failed to write Python wheel backend runner: {error}"))?;
    let project_directory = Path::new(manifest_repository_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map_or_else(
            || snapshot.path().to_path_buf(),
            |path| snapshot.path().join(path),
        )
        .strip_prefix(root)
        .map_err(|_| "Python distribution project escaped its sandbox".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    let output_argument = output
        .strip_prefix(root)
        .map_err(|_| "private Python wheel output escaped its snapshot".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    let runner_argument = runner
        .strip_prefix(root)
        .map_err(|_| "Python wheel backend runner escaped its sandbox".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    let requirements_argument = requirements_contract
        .strip_prefix(root)
        .map_err(|_| "Python build requirements escaped its snapshot".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    let toolchain = materialize_python_build_toolchain(PythonBuildToolchainMaterialization {
        snapshot,
        revision,
        cache: &cache,
        runner_argument: &runner_argument,
        project_argument: &project_directory,
        manifest: &manifest,
        store,
        package_index,
    })?;
    if toolchain.requirements_contract != requirements_contract {
        return Err("prepared Python requirements contract path changed".to_string());
    }
    let logical_command = vec![
        "{sniff_private_python}".to_string(),
        "-I".to_string(),
        "-B".to_string(),
        runner_argument.clone(),
        "build".to_string(),
        project_directory.clone(),
        output_argument.clone(),
        requirements_argument.clone(),
    ];
    let mut plan = prepare_historical_runtime(root, &cache, &logical_command)
        .map_err(|error| format!("failed to prepare offline Python wheel build: {error:?}"))?;
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = false;
    }
    plan.command.timeout = PYTHON_WHEEL_BUILD_TIMEOUT;
    plan.command.output_limit = PYTHON_WHEEL_BUILD_OUTPUT_LIMIT;
    persist_historical_runtime_directories(&mut plan);
    let toolchain_identity_sha256 = hash_json(&(
        "sniffbench-python-wheel-prepared-toolchain-v1",
        &toolchain.identity_sha256,
        &plan.runtime_identity,
        sha256(PYTHON_WHEEL_BACKEND_RUNNER),
        PYTHON_WHEEL_BUILD_COMMAND_CONTRACT,
    ))?;
    let process = crate::sandbox::run(&plan.command)
        .map_err(|error| format!("sandboxed offline Python wheel build failed: {error}"))?;
    if process.timed_out {
        return Err(format!(
            "sandboxed offline Python wheel build timed out for {manifest_repository_path}"
        ));
    }
    if process.status_code != Some(0) {
        return Err(format!(
            "sandboxed offline Python wheel build failed for {manifest_repository_path} with status {}: {}",
            process
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string()),
            process.stderr.trim()
        ));
    }
    let actual_environment = python_environment_tree_sha256(&cache.join("python-env"))?;
    if actual_environment != toolchain.environment_tree_sha256 {
        return Err("Python build backend changed its prepared toolchain".to_string());
    }
    let wheels = fs::read_dir(&output)
        .map_err(|error| format!("failed to inspect Python wheel output: {error}"))?
        .map(|entry| {
            entry.map_err(|error| format!("failed to inspect Python wheel output entry: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [wheel] = wheels.as_slice() else {
        return Err(format!(
            "offline Python build produced {} output entries for {manifest_repository_path}; expected exactly one wheel",
            wheels.len()
        ));
    };
    let metadata = fs::symlink_metadata(wheel.path())
        .map_err(|error| format!("failed to inspect Python wheel output file: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_WHEEL_ARCHIVE_BYTES
    {
        return Err(format!(
            "offline Python build output is not one bounded regular wheel for {manifest_repository_path}"
        ));
    }
    let wheel_filename = wheel
        .file_name()
        .into_string()
        .map_err(|_| "Python wheel filename is not UTF-8".to_string())?;
    if !wheel_filename.ends_with(".whl") {
        return Err(format!(
            "offline Python build output is not a wheel: {wheel_filename}"
        ));
    }
    let wheel_bytes = fs::read(wheel.path())
        .map_err(|error| format!("failed to read Python wheel output: {error}"))?;
    Ok(PythonWheelBuildOutput {
        toolchain_identity_sha256,
        wheel_filename,
        wheel_bytes,
    })
}

fn read_python_build_manifest(
    checkout: &Path,
    manifest_repository_path: &str,
) -> Result<ParsedPythonDistributionManifest, String> {
    if manifest_repository_path.contains('\\')
        || Path::new(manifest_repository_path).is_absolute()
        || Path::new(manifest_repository_path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || Path::new(manifest_repository_path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("pyproject.toml")
    {
        return Err(format!(
            "Python distribution manifest path is unsafe: {manifest_repository_path}"
        ));
    }
    let manifest_path = checkout.join(manifest_repository_path);
    let source = fs::read_to_string(&manifest_path).map_err(|error| {
        format!("failed to read Python distribution manifest {manifest_repository_path}: {error}")
    })?;
    let manifest =
        parse_python_distribution_manifest(manifest_repository_path, "runtime-manifest", &source)?
            .ok_or_else(|| {
                format!(
                    "Python distribution manifest has no build-system: {manifest_repository_path}"
                )
            })?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Output};

    const FIXTURE_BACKEND: &str = r#"import base64
import csv
import hashlib
import io
import os
import zipfile

if not os.path.isfile("pyproject.toml"):
    raise RuntimeError("backend was not imported from the project root")


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    filename = "fixture_package-1.0.0-py3-none-any.whl"
    dist_info = "fixture_package-1.0.0.dist-info"
    files = {
        "fixture_package/__init__.py": b"VALUE = 1\n",
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: fixture-package\n"
            b"Version: 1.0.0\n\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: sniff-fixture\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n\n"
        ),
    }
    record_path = f"{dist_info}/RECORD"
    record = io.StringIO(newline="")
    rows = csv.writer(record, lineterminator="\n")
    for path, contents in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
        rows.writerow((path, f"sha256={digest}", len(contents)))
    rows.writerow((record_path, "", ""))
    files[record_path] = record.getvalue().encode()
    output = os.path.join(wheel_directory, filename)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, contents in sorted(files.items()):
            archive.writestr(path, contents)
    return filename
"#;

    fn run_backend_runner(root: &Path) -> Output {
        fs::write(root.join("pep517_runner.py"), PYTHON_WHEEL_BACKEND_RUNNER).unwrap();
        fs::write(
            root.join("requirements-contract.json"),
            r#"{"static_requirements":[],"dynamic_requirements":[]}"#,
        )
        .unwrap();
        fs::create_dir(root.join("output")).unwrap();
        Command::new(if cfg!(windows) { "python" } else { "python3" })
            .args([
                "-I",
                "-S",
                "pep517_runner.py",
                "build",
                "project",
                "output",
                "requirements-contract.json",
            ])
            .current_dir(root)
            .output()
            .unwrap()
    }

    #[test]
    fn backend_runner_rejects_module_outside_declared_backend_path() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("project/backend")).unwrap();
        fs::write(root.path().join("project/outside.py"), "VALUE = 1\n").unwrap();
        fs::write(
            root.path().join("project/pyproject.toml"),
            "[build-system]\nrequires = []\nbuild-backend = 'fixture_backend'\nbackend-path = ['backend']\n",
        )
        .unwrap();
        fs::write(
            root.path().join("project/backend/fixture_backend.py"),
            "from pathlib import Path\n__file__ = str(Path(__file__).parents[1] / 'outside.py')\n",
        )
        .unwrap();

        let output = run_backend_runner(root.path());

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("build backend was not loaded from a declared backend-path"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn backend_runner_rejects_symlinked_backend_path() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("project")).unwrap();
        fs::create_dir(root.path().join("outside")).unwrap();
        symlink(
            root.path().join("outside"),
            root.path().join("project/backend"),
        )
        .unwrap();
        fs::write(
            root.path().join("project/pyproject.toml"),
            "[build-system]\nrequires = []\nbuild-backend = 'fixture_backend'\nbackend-path = ['backend']\n",
        )
        .unwrap();

        let output = run_backend_runner(root.path());

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("backend-path contains an unsupported symbolic link"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn production_runtime_builds_dependency_free_backend_offline() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("pyproject.toml"),
            "[build-system]\nrequires = []\nbuild-backend = 'fixture_backend'\nbackend-path = ['.']\n",
        )
        .unwrap();
        fs::write(root.path().join("fixture_backend.py"), FIXTURE_BACKEND).unwrap();

        let git = |args: &[&str]| {
            let output = Command::new("git")
                .arg("-C")
                .arg(root.path())
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
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.name", "SniffBench"]);
        git(&["config", "user.email", "bench@example.invalid"]);
        git(&["add", "."]);
        git(&["commit", "--quiet", "-m", "fixture"]);
        let revision = git(&["rev-parse", "HEAD"]);
        let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
            root.path(),
            &revision,
            "sniff-python-wheel-test",
        )
        .unwrap();

        let output = run_python_wheel_build(&snapshot, &revision, "pyproject.toml").unwrap();
        assert!(is_sha256(&output.toolchain_identity_sha256));
        assert_eq!(
            output.wheel_filename,
            "fixture_package-1.0.0-py3-none-any.whl"
        );
        let wheel = parse_wheel(&output.wheel_filename, &output.wheel_bytes).unwrap();
        assert_eq!(wheel.normalized_distribution_name, "fixture-package");
        assert_eq!(wheel.modules.len(), 1);
        assert_eq!(wheel.modules[0].import_name, "fixture_package");
    }

    #[test]
    #[ignore = "requires a networked Python package repository"]
    fn production_runtime_builds_with_external_pep517_requirements() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("src/fixture_package")).unwrap();
        fs::write(
            root.path().join("src/fixture_package/__init__.py"),
            "VALUE = 1\n",
        )
        .unwrap();
        fs::write(
            root.path().join("pyproject.toml"),
            "[build-system]\nrequires = ['hatchling==1.27.0']\nbuild-backend = 'hatchling.build'\n\n[project]\nname = 'fixture-package'\nversion = '1.0.0'\n",
        )
        .unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .arg("-C")
                .arg(root.path())
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.name", "SniffBench"]);
        git(&["config", "user.email", "bench@example.invalid"]);
        git(&["add", "."]);
        git(&["commit", "--quiet", "-m", "fixture"]);
        let revision = git(&["rev-parse", "HEAD"]);
        let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
            root.path(),
            &revision,
            "sniff-python-wheel-requires-test",
        )
        .unwrap();

        let store = PythonBuildToolchainStore::at(root.path().join("toolchain-store"));

        let output =
            run_python_wheel_build_with_store(&snapshot, &revision, "pyproject.toml", &store);
        let output = output.unwrap();
        assert_eq!(
            output.wheel_filename,
            "fixture_package-1.0.0-py2.py3-none-any.whl"
        );
        assert!(is_sha256(&output.toolchain_identity_sha256));

        let cached =
            run_python_wheel_build_with_store(&snapshot, &revision, "pyproject.toml", &store)
                .unwrap();
        assert_eq!(
            cached.toolchain_identity_sha256,
            output.toolchain_identity_sha256
        );
        assert_eq!(cached.wheel_filename, output.wheel_filename);
        assert_eq!(sha256(&cached.wheel_bytes), sha256(&output.wheel_bytes));
    }
}

#[cfg(test)]
mod toolchain_integration_tests {
    include!("benchmark_python_build_toolchain_integration_tests.rs");
}
