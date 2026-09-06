use super::super::intentional_boundary_runtime_snapshot::{
    IntentionalBoundaryRuntimeSnapshot, allocate_runtime_directory,
};
use super::super::non_blind_history_runtime::prepare_historical_runtime;
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
        |_, manifest_repository_path| run_python_wheel_build(&snapshot, manifest_repository_path),
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
        |_, manifest_repository_path| run_python_wheel_build(&snapshot, manifest_repository_path),
    )
}

fn run_python_wheel_build(
    snapshot: &IntentionalBoundaryRuntimeSnapshot,
    manifest_repository_path: &str,
) -> Result<PythonWheelBuildOutput, String> {
    require_dependency_free_python_backend(snapshot.path(), manifest_repository_path)?;
    let root = snapshot.sandbox_root();
    let runtime = PythonWheelBuildCallRuntime::create(root)?;
    let cache = runtime.path().join("cache");
    let output = cache.join("wheel-output");
    let runner = cache.join("pep517_runner.py");
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
    let logical_command = vec![
        if cfg!(windows) { "python" } else { "python3" }.to_string(),
        "-I".to_string(),
        "-S".to_string(),
        runner_argument,
        project_directory,
        output_argument,
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
    let toolchain_identity_sha256 = hash_json(&(
        "sniffbench-python-wheel-toolchain-v1",
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

fn require_dependency_free_python_backend(
    checkout: &Path,
    manifest_repository_path: &str,
) -> Result<(), String> {
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
    if !manifest.build_requirements.is_empty() {
        return Err(format!(
            "Python distribution {manifest_repository_path} requires an unavailable prepared deterministic build toolchain"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const FIXTURE_BACKEND: &str = r#"import base64
import csv
import hashlib
import io
import os
import zipfile


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

    #[test]
    fn production_runtime_builds_dependency_free_backend_offline() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("build_backend")).unwrap();
        fs::write(
            root.path().join("pyproject.toml"),
            "[build-system]\nrequires = []\nbuild-backend = 'fixture_backend'\nbackend-path = ['build_backend']\n",
        )
        .unwrap();
        fs::write(
            root.path().join("build_backend/fixture_backend.py"),
            FIXTURE_BACKEND,
        )
        .unwrap();

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

        let output = run_python_wheel_build(&snapshot, "pyproject.toml").unwrap();
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
    fn production_runtime_rejects_unprepared_external_build_requirements() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("pyproject.toml"),
            "[build-system]\nrequires = ['hatchling==1.27.0']\nbuild-backend = 'hatchling.build'\n",
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

        let error = run_python_wheel_build(&snapshot, "pyproject.toml").unwrap_err();
        assert!(
            error.contains("prepared deterministic build toolchain"),
            "{error}"
        );
    }
}
