use super::history_v2_python_distribution_surface::ParsedPythonDistributionManifest;
use super::intentional_boundary_runtime_snapshot::IntentionalBoundaryRuntimeSnapshot;
use super::non_blind_history_runtime::{
    persist_historical_runtime_directories, prepare_historical_runtime,
};
use super::python_build_requirement::validate_python_build_requirement;
use super::python_build_toolchain_store::{
    PreparedPythonBuildToolchain, PythonBuildRequirementsContract, PythonBuildToolchainRequest,
    PythonBuildToolchainStore, python_environment_tree_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PREPARATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PREPARATION_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const REQUIREMENTS_INPUT: &str = "build-requirements.in";
const STATIC_LOCK: &str = "static-requirements.txt";
const STATIC_PROVENANCE: &str = "static-wheelhouse-provenance.json";
const STATIC_WHEELHOUSE: &str = "static-wheelhouse";
const FINAL_LOCK: &str = "requirements.txt";
const REQUIREMENTS_CONTRACT: &str = "requirements-contract.json";
const PROVENANCE: &str = "wheelhouse-provenance.json";
const WHEELHOUSE: &str = "wheelhouse";
const DYNAMIC_REQUIREMENTS: &str = "dynamic-requirements.json";
const RESOLVER_ENVIRONMENT: &str = "pip-env";
const PRIVATE_ENVIRONMENT: &str = "python-env";
const PREPARED_TOOLCHAIN: &str = "prepared-toolchain";
const PIP_RUNNER_NAME: &str = "python-pip-runner.py";
const RUNTIME_CONTRACT_RUNNER_NAME: &str = "python-runtime-contract.py";
const WHEELHOUSE_RUNNER_NAME: &str = "python-wheelhouse-runner.py";
const PIP_RUNNER: &str = include_str!("benchmark_python_pip_runner.py");
const RUNTIME_CONTRACT_RUNNER: &str = include_str!("benchmark_python_runtime_contract_runner.py");
const WHEELHOUSE_RUNNER: &str = include_str!("benchmark_python_wheelhouse_runner.py");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PythonBuildRuntimeContract {
    version: u32,
    python_implementation: String,
    python_version: String,
    cache_tag: String,
    platform: String,
    pip_version: String,
    pip_file_count: usize,
    pip_total_bytes: u64,
    pip_files_sha256: String,
}

struct CommandOutput {
    stdout: String,
    runtime_identity: String,
}

pub(super) struct MaterializedPythonBuildToolchain {
    pub(super) identity_sha256: String,
    pub(super) requirements_contract: PathBuf,
    pub(super) environment_tree_sha256: String,
}

pub(super) struct PythonBuildToolchainMaterialization<'a> {
    pub(super) snapshot: &'a IntentionalBoundaryRuntimeSnapshot,
    pub(super) revision: &'a str,
    pub(super) cache: &'a Path,
    pub(super) runner_argument: &'a str,
    pub(super) project_argument: &'a str,
    pub(super) manifest: &'a ParsedPythonDistributionManifest,
    pub(super) store: &'a PythonBuildToolchainStore,
    pub(super) package_index: &'a str,
}

pub(super) fn materialize_python_build_toolchain(
    materialization: PythonBuildToolchainMaterialization<'_>,
) -> Result<MaterializedPythonBuildToolchain, String> {
    let PythonBuildToolchainMaterialization {
        snapshot,
        revision,
        cache,
        runner_argument,
        project_argument,
        manifest,
        store,
        package_index,
    } = materialization;
    let root = snapshot.sandbox_root();
    write_helper(cache, RUNTIME_CONTRACT_RUNNER_NAME, RUNTIME_CONTRACT_RUNNER)?;
    write_helper(cache, WHEELHOUSE_RUNNER_NAME, WHEELHOUSE_RUNNER)?;
    write_helper(cache, PIP_RUNNER_NAME, PIP_RUNNER)?;
    create_resolver_environment(root, cache)?;
    let (python_identity, pip_identity, target_platform) =
        python_build_runtime_identities(root, cache)?;
    let request = PythonBuildToolchainRequest {
        repository_revision: revision.to_string(),
        manifest_repository_path: manifest.repository_path.clone(),
        manifest_source_sha256: manifest.source_sha256.clone(),
        build_backend: manifest.build_backend.clone(),
        backend_path: manifest.backend_path.clone(),
        build_requirements: manifest
            .build_requirements
            .iter()
            .map(|requirement| requirement.requirement.clone())
            .collect(),
        package_index: package_index.to_string(),
        python_runtime_identity_sha256: python_identity,
        pip_runtime_identity_sha256: pip_identity,
        target_platform,
    };
    let entry_root = store.entry_root(&request)?;
    let installed = if entry_root.exists() {
        store.verify(&request)?
    } else {
        prepare_store_entry(
            root,
            cache,
            runner_argument,
            project_argument,
            &request,
            store,
        )?
    };
    installed.materialize_into(cache)?;
    create_environment_from_wheelhouse(root, cache, WHEELHOUSE, FINAL_LOCK)?;
    let environment_tree_sha256 = python_environment_tree_sha256(&cache.join(PRIVATE_ENVIRONMENT))?;
    remove_directory(
        &cache.join(RESOLVER_ENVIRONMENT),
        "private Python resolver environment",
    )?;
    Ok(MaterializedPythonBuildToolchain {
        identity_sha256: installed.identity_sha256,
        requirements_contract: cache.join(REQUIREMENTS_CONTRACT),
        environment_tree_sha256,
    })
}

fn prepare_store_entry(
    root: &Path,
    cache: &Path,
    runner_argument: &str,
    project_argument: &str,
    request: &PythonBuildToolchainRequest,
    store: &PythonBuildToolchainStore,
) -> Result<PreparedPythonBuildToolchain, String> {
    let input = cache.join(REQUIREMENTS_INPUT);
    write_requirements(&input, &request.build_requirements)?;
    resolve_wheelhouse(
        root,
        cache,
        REQUIREMENTS_INPUT,
        STATIC_WHEELHOUSE,
        STATIC_LOCK,
        STATIC_PROVENANCE,
        &request.package_index,
    )?;
    create_environment_from_wheelhouse(root, cache, STATIC_WHEELHOUSE, STATIC_LOCK)?;

    let dynamic_result = cache.join(DYNAMIC_REQUIREMENTS);
    let dynamic_argument = sandbox_relative(root, &dynamic_result)?;
    run_private_python(
        root,
        cache,
        &[
            "-I",
            "-B",
            runner_argument,
            "requirements",
            project_argument,
            &dynamic_argument,
        ],
        "Python dynamic build-requirements hook",
    )?;
    let dynamic_requirements = read_dynamic_requirements(&dynamic_result)?;

    remove_directory(
        &cache.join(PRIVATE_ENVIRONMENT),
        "static Python build environment",
    )?;
    remove_directory(&cache.join(STATIC_WHEELHOUSE), "static Python wheelhouse")?;
    remove_file(&cache.join(STATIC_LOCK), "static Python requirements lock")?;
    remove_file(
        &cache.join(STATIC_PROVENANCE),
        "static Python wheelhouse provenance",
    )?;
    let mut combined = request.build_requirements.clone();
    combined.extend(dynamic_requirements.iter().cloned());
    write_requirements(&input, &combined)?;
    resolve_wheelhouse(
        root,
        cache,
        REQUIREMENTS_INPUT,
        WHEELHOUSE,
        FINAL_LOCK,
        PROVENANCE,
        &request.package_index,
    )?;
    fs::write(
        cache.join(REQUIREMENTS_CONTRACT),
        serde_json::to_vec(&PythonBuildRequirementsContract {
            static_requirements: request.build_requirements.clone(),
            dynamic_requirements,
        })
        .map_err(|error| format!("failed to serialize Python requirements contract: {error}"))?,
    )
    .map_err(|error| format!("failed to write Python requirements contract: {error}"))?;

    let prepared = cache.join(PREPARED_TOOLCHAIN);
    fs::create_dir(&prepared)
        .map_err(|error| format!("failed to create prepared Python toolchain: {error}"))?;
    for name in [FINAL_LOCK, REQUIREMENTS_CONTRACT, PROVENANCE, WHEELHOUSE] {
        fs::rename(cache.join(name), prepared.join(name)).map_err(|error| {
            format!("failed to stage Python build-toolchain artifact {name}: {error}")
        })?;
    }
    let installed = store.import_prepared(request, &prepared)?;
    remove_directory(&prepared, "prepared Python build toolchain")?;
    remove_file(&input, "Python build requirements input")?;
    remove_file(&dynamic_result, "dynamic Python build requirements")?;
    Ok(installed)
}

fn resolve_wheelhouse(
    root: &Path,
    cache: &Path,
    input: &str,
    wheelhouse: &str,
    lock: &str,
    provenance: &str,
    package_index: &str,
) -> Result<(), String> {
    fs::create_dir(cache.join(wheelhouse))
        .map_err(|error| format!("failed to create Python wheelhouse: {error}"))?;
    let wheelhouse_argument = sandbox_relative(root, &cache.join(wheelhouse))?;
    let input_argument = sandbox_relative(root, &cache.join(input))?;
    let pip_runner = sandbox_relative(root, &cache.join(PIP_RUNNER_NAME))?;
    let input_bytes = fs::read(cache.join(input))
        .map_err(|error| format!("failed to read Python build requirements: {error}"))?;
    if !input_bytes.is_empty() {
        run_resolver_python(
            root,
            cache,
            &[
                "-I",
                "-B",
                &pip_runner,
                "--isolated",
                "download",
                "--disable-pip-version-check",
                "--no-input",
                "--no-color",
                "--progress-bar",
                "off",
                "--only-binary=:all:",
                "--index-url",
                package_index,
                "--dest",
                &wheelhouse_argument,
                "--requirement",
                &input_argument,
            ],
            true,
            "Python wheel resolution",
        )?;
    }
    let helper_argument = sandbox_relative(root, &cache.join(WHEELHOUSE_RUNNER_NAME))?;
    let lock_argument = sandbox_relative(root, &cache.join(lock))?;
    let provenance_argument = sandbox_relative(root, &cache.join(provenance))?;
    run_host_python(
        root,
        cache,
        &[
            "-I",
            "-B",
            &helper_argument,
            &wheelhouse_argument,
            &lock_argument,
            &provenance_argument,
        ],
        false,
        "Python wheelhouse inspection",
    )
}

fn create_environment_from_wheelhouse(
    root: &Path,
    cache: &Path,
    wheelhouse: &str,
    lock: &str,
) -> Result<(), String> {
    let environment = cache.join(PRIVATE_ENVIRONMENT);
    if environment.exists()
        && fs::read_dir(&environment)
            .map_err(|error| format!("failed to inspect private Python environment: {error}"))?
            .next()
            .is_some()
    {
        return Err("private Python build environment is not empty".to_string());
    }
    let environment_argument = sandbox_relative(root, &environment)?;
    run_host_python(
        root,
        cache,
        &[
            "-I",
            "-B",
            "-m",
            "venv",
            "--copies",
            "--without-pip",
            &environment_argument,
        ],
        false,
        "Python build-environment creation",
    )?;
    let lock_bytes = fs::read(cache.join(lock))
        .map_err(|error| format!("failed to read Python requirements lock: {error}"))?;
    if lock_bytes.is_empty() {
        return Ok(());
    }
    let wheelhouse_argument = sandbox_relative(root, &cache.join(wheelhouse))?;
    let lock_argument = sandbox_relative(root, &cache.join(lock))?;
    let pip_runner = sandbox_relative(root, &cache.join(PIP_RUNNER_NAME))?;
    run_resolver_python(
        root,
        cache,
        &[
            "-I",
            "-B",
            &pip_runner,
            "--isolated",
            "--python",
            &environment_argument,
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-color",
            "--no-compile",
            "--no-deps",
            "--no-index",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links",
            &wheelhouse_argument,
            "--requirement",
            &lock_argument,
        ],
        false,
        "hash-locked Python build-toolchain installation",
    )
}

fn create_resolver_environment(root: &Path, cache: &Path) -> Result<(), String> {
    let environment = cache.join(RESOLVER_ENVIRONMENT);
    if environment.exists()
        && fs::read_dir(&environment)
            .map_err(|error| format!("failed to inspect private Python resolver: {error}"))?
            .next()
            .is_some()
    {
        return Err("private Python resolver environment is not empty".to_string());
    }
    let environment_argument = sandbox_relative(root, &environment)?;
    run_host_python(
        root,
        cache,
        &[
            "-I",
            "-B",
            "-m",
            "venv",
            "--copies",
            "--without-pip",
            &environment_argument,
        ],
        false,
        "Python resolver-environment creation",
    )
}

fn python_build_runtime_identities(
    root: &Path,
    cache: &Path,
) -> Result<(String, String, String), String> {
    let runner = sandbox_relative(root, &cache.join(RUNTIME_CONTRACT_RUNNER_NAME))?;
    let output = run_resolver_python_output(
        root,
        cache,
        &["-I", &runner],
        false,
        "Python build-runtime inspection",
    )?;
    let contract: PythonBuildRuntimeContract = serde_json::from_str(output.stdout.trim())
        .map_err(|error| format!("Python build-runtime contract is invalid: {error}"))?;
    validate_runtime_contract(&contract)?;
    let python_identity = hash_json(&(
        "sniff-python-build-runtime-v1",
        &output.runtime_identity,
        &contract.python_implementation,
        &contract.python_version,
        &contract.cache_tag,
        &contract.platform,
    ))?;
    let pip_identity = hash_json(&(
        "sniff-pip-build-runtime-v1",
        &output.runtime_identity,
        format!("{:x}", Sha256::digest(PIP_RUNNER.as_bytes())),
        &contract,
    ))?;
    let target = format!(
        "{}-{}-{}-{}",
        contract.platform,
        contract.python_implementation,
        contract.python_version,
        contract.cache_tag
    );
    Ok((python_identity, pip_identity, target))
}

fn validate_runtime_contract(contract: &PythonBuildRuntimeContract) -> Result<(), String> {
    let safe = |value: &str| {
        !value.trim().is_empty() && !value.contains(['\r', '\n', '\0']) && value.len() <= 1024
    };
    if contract.version != 2
        || !safe(&contract.python_implementation)
        || !safe(&contract.python_version)
        || !safe(&contract.cache_tag)
        || !safe(&contract.platform)
        || !safe(&contract.pip_version)
        || contract.pip_file_count == 0
        || contract.pip_file_count > 100_000
        || contract.pip_total_bytes > 2 * 1024 * 1024 * 1024
        || contract.pip_files_sha256.len() != 64
        || !contract
            .pip_files_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("Python build-runtime contract is incomplete or unsafe".to_string());
    }
    Ok(())
}

fn run_host_python(
    root: &Path,
    cache: &Path,
    arguments: &[&str],
    allow_network: bool,
    label: &str,
) -> Result<(), String> {
    run_host_python_output(root, cache, arguments, allow_network, label).map(|_| ())
}

fn run_host_python_output(
    root: &Path,
    cache: &Path,
    arguments: &[&str],
    allow_network: bool,
    label: &str,
) -> Result<CommandOutput, String> {
    let mut command = vec![host_python().to_string()];
    command.extend(arguments.iter().map(|argument| argument.to_string()));
    run_command(root, cache, &command, allow_network, label)
}

fn run_private_python(
    root: &Path,
    cache: &Path,
    arguments: &[&str],
    label: &str,
) -> Result<(), String> {
    let mut command = vec!["{sniff_private_python}".to_string()];
    command.extend(arguments.iter().map(|argument| argument.to_string()));
    run_command(root, cache, &command, false, label).map(|_| ())
}

fn run_resolver_python(
    root: &Path,
    cache: &Path,
    arguments: &[&str],
    allow_network: bool,
    label: &str,
) -> Result<(), String> {
    run_resolver_python_output(root, cache, arguments, allow_network, label).map(|_| ())
}

fn run_resolver_python_output(
    root: &Path,
    cache: &Path,
    arguments: &[&str],
    allow_network: bool,
    label: &str,
) -> Result<CommandOutput, String> {
    let mut command = vec!["{sniff_resolver_python}".to_string()];
    command.extend(arguments.iter().map(|argument| argument.to_string()));
    run_command(root, cache, &command, allow_network, label)
}

fn run_command(
    root: &Path,
    cache: &Path,
    command: &[String],
    allow_network: bool,
    label: &str,
) -> Result<CommandOutput, String> {
    let mut plan = prepare_historical_runtime(root, cache, command)
        .map_err(|error| format!("failed to plan {label}: {error:?}"))?;
    plan.command.allow_network = allow_network;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = allow_network;
    }
    plan.command.timeout = PREPARATION_TIMEOUT;
    plan.command.output_limit = PREPARATION_OUTPUT_LIMIT;
    persist_historical_runtime_directories(&mut plan);
    let runtime_identity = plan.runtime_identity;
    let output = crate::sandbox::run(&plan.command)
        .map_err(|error| format!("sandboxed {label} failed: {error}"))?;
    if output.timed_out
        || output.memory_limit_exceeded
        || output.process_limit_exceeded
        || output.status_code != Some(0)
    {
        return Err(format!(
            "sandboxed {label} failed with status {}{}: {}",
            output
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string()),
            if output.timed_out {
                " after timing out"
            } else if output.memory_limit_exceeded {
                " after exceeding memory"
            } else if output.process_limit_exceeded {
                " after exceeding process limits"
            } else {
                ""
            },
            output.stderr.trim()
        ));
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        runtime_identity,
    })
}

fn write_helper(cache: &Path, name: &str, source: &str) -> Result<(), String> {
    let path = cache.join(name);
    if path.exists() {
        return Err(format!(
            "private Python helper already exists: {}",
            path.display()
        ));
    }
    fs::write(&path, source).map_err(|error| {
        format!(
            "failed to write private Python helper {}: {error}",
            path.display()
        )
    })
}

fn write_requirements(path: &Path, requirements: &[String]) -> Result<(), String> {
    for requirement in requirements {
        validate_python_build_requirement(requirement)?;
    }
    let source = if requirements.is_empty() {
        String::new()
    } else {
        format!("{}\n", requirements.join("\n"))
    };
    fs::write(path, source)
        .map_err(|error| format!("failed to write Python build requirements: {error}"))
}

fn read_dynamic_requirements(path: &Path) -> Result<Vec<String>, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read dynamic Python build requirements: {error}"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("dynamic Python build requirements exceed 4 MiB".to_string());
    }
    let requirements: Vec<String> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("dynamic Python build requirements are invalid: {error}"))?;
    for requirement in &requirements {
        validate_python_build_requirement(requirement)?;
    }
    Ok(requirements)
}

fn remove_directory(path: &Path, label: &str) -> Result<(), String> {
    fs::remove_dir_all(path).map_err(|error| format!("failed to remove {label}: {error}"))
}

fn remove_file(path: &Path, label: &str) -> Result<(), String> {
    fs::remove_file(path).map_err(|error| format!("failed to remove {label}: {error}"))
}

fn sandbox_relative(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|_| {
            format!(
                "Python build-toolchain path escaped its sandbox: {}",
                path.display()
            )
        })
}

fn host_python() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to hash Python build-toolchain identity: {error}"))
}

#[cfg(test)]
mod tests {
    use super::super::python_build_toolchain_store::PythonWheelhouseProvenance;
    use super::*;
    use std::io::Write;
    use std::process::Command;
    use zip::write::SimpleFileOptions;

    fn write_fixture_wheel(path: &Path) {
        let file = fs::File::create(path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        let files = [
            ("sniff_fixture/__init__.py", "VALUE = 1\n"),
            (
                "sniff_fixture-1.0.0.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: Sniff_Fixture\nVersion: 1.0.0\n\n",
            ),
            (
                "sniff_fixture-1.0.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nGenerator: sniff\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            ),
            (
                "sniff_fixture-1.0.0.dist-info/RECORD",
                "sniff_fixture/__init__.py,,\nsniff_fixture-1.0.0.dist-info/METADATA,,\nsniff_fixture-1.0.0.dist-info/WHEEL,,\nsniff_fixture-1.0.0.dist-info/RECORD,,\n",
            ),
        ];
        for (name, source) in files {
            archive.start_file(name, options).unwrap();
            archive.write_all(source.as_bytes()).unwrap();
        }
        archive.finish().unwrap();
    }

    #[test]
    fn wheelhouse_runner_writes_canonical_hash_lock_and_provenance() {
        let root = tempfile::tempdir().unwrap();
        let wheelhouse = root.path().join("wheelhouse");
        fs::create_dir(&wheelhouse).unwrap();
        let filename = "sniff_fixture-1.0.0-py3-none-any.whl";
        let wheel = wheelhouse.join(filename);
        write_fixture_wheel(&wheel);
        fs::write(root.path().join("runner.py"), WHEELHOUSE_RUNNER).unwrap();

        let output = Command::new(host_python())
            .args([
                "-I",
                "runner.py",
                "wheelhouse",
                "requirements.txt",
                "provenance.json",
            ])
            .current_dir(root.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let wheel_sha256 = format!("{:x}", Sha256::digest(fs::read(&wheel).unwrap()));
        assert_eq!(
            fs::read_to_string(root.path().join("requirements.txt")).unwrap(),
            format!("sniff-fixture==1.0.0 --hash=sha256:{wheel_sha256}\n")
        );
        let provenance: PythonWheelhouseProvenance =
            serde_json::from_slice(&fs::read(root.path().join("provenance.json")).unwrap())
                .unwrap();
        assert_eq!(provenance.artifacts.len(), 1);
        assert_eq!(provenance.artifacts[0].name, "sniff-fixture");
        assert_eq!(provenance.artifacts[0].filename, filename);
        assert_eq!(provenance.artifacts[0].sha256, wheel_sha256);
    }

    #[test]
    fn wheelhouse_runner_accepts_an_empty_resolved_environment() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("wheelhouse")).unwrap();
        fs::write(root.path().join("runner.py"), WHEELHOUSE_RUNNER).unwrap();

        let output = Command::new(host_python())
            .args([
                "-I",
                "runner.py",
                "wheelhouse",
                "requirements.txt",
                "provenance.json",
            ])
            .current_dir(root.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(root.path().join("requirements.txt")).unwrap(), b"");
        let provenance: PythonWheelhouseProvenance =
            serde_json::from_slice(&fs::read(root.path().join("provenance.json")).unwrap())
                .unwrap();
        assert!(provenance.artifacts.is_empty());
    }

    #[test]
    fn runtime_contract_runner_hashes_the_pip_distribution() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("runner.py"), RUNTIME_CONTRACT_RUNNER).unwrap();
        let environment = root.path().join("pip-env");
        let created = Command::new(host_python())
            .args(["-I", "-B", "-m", "venv", "--copies", "--without-pip"])
            .arg(&environment)
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let python = if cfg!(windows) {
            environment.join("Scripts").join("python.exe")
        } else {
            environment.join("bin").join("python")
        };

        let output = Command::new(python)
            .args(["-I", "runner.py"])
            .current_dir(root.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let contract: PythonBuildRuntimeContract = serde_json::from_slice(&output.stdout).unwrap();
        validate_runtime_contract(&contract).unwrap();
        assert!(contract.pip_file_count > 0);
        assert!(contract.pip_total_bytes > 0);
        assert_eq!(contract.pip_files_sha256.len(), 64);
    }
}
