use super::non_blind_history_runtime_adapters::{
    bun_launch, cargo_launch, generic_launch, go_launch, gradle_launch, node_launch,
    node_manager_launch, private_python_launch, python_launch,
};
#[cfg(windows)]
use super::non_blind_history_runtime_support::{
    batch_command_arguments, collapse_non_overlapping_roots, collect_windows_runtime_images,
    is_batch, path_value, resolve_on_path,
};
use super::non_blind_history_runtime_support::{
    canonical_directory, is_system_runtime, normalized_external_roots, push_external, runtime_bin,
    runtime_identity, sandbox_repository_path,
};
use crate::sandbox::{SandboxCommand, sandbox_path};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const TEST_OUTPUT_LIMIT: usize = 1024 * 1024;
const TEST_MEMORY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const TEST_PROCESS_LIMIT: u32 = 256;
const PRIVATE_ENVIRONMENT_DIRECTORIES: &[&str] = &[
    "home",
    "bun-cache",
    "cargo-home",
    "cargo-target",
    "corepack",
    "go-build",
    "go-mod",
    "go-path",
    "gradle",
    "npm",
    "pip",
    "pycache",
    "tmp",
    "xdg-cache",
];

pub(crate) struct HistoricalRuntimePlan {
    pub(crate) command: SandboxCommand,
    pub(crate) runtime_identity: String,
    pub(crate) launcher_kind: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HistoricalRuntimePlanError {
    Unavailable(String),
    Invalid(String),
}

pub(crate) fn prepare_historical_runtime(
    snapshot_root: &Path,
    cache_root: &Path,
    logical_command: &[String],
) -> Result<HistoricalRuntimePlan, HistoricalRuntimePlanError> {
    let root = canonical_directory(snapshot_root, "historical test snapshot")?;
    let cache_root = canonical_directory(cache_root, "historical test cache")?;
    if !cache_root.starts_with(&root) {
        return Err(HistoricalRuntimePlanError::Invalid(
            "historical test cache must remain inside its snapshot".to_string(),
        ));
    }
    prepare_private_environment_directories(&cache_root)?;
    let program = logical_command
        .first()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            HistoricalRuntimePlanError::Invalid(
                "historical test command requires a non-empty program".to_string(),
            )
        })?;
    if logical_command.iter().any(|value| value.contains('\0')) {
        return Err(HistoricalRuntimePlanError::Invalid(
            "historical test command contains a NUL byte".to_string(),
        ));
    }
    let expanded_args = logical_command[1..]
        .iter()
        .map(|argument| expand_reserved_argument(&root, &cache_root, argument))
        .collect::<Vec<_>>();

    let mut launch = match program.as_str() {
        "cargo" => cargo_launch(&expanded_args)?,
        "go" => go_launch(&expanded_args)?,
        "python" | "python3" => python_launch(program, &expanded_args)?,
        "{sniff_private_python}" => private_python_launch(&cache_root, &expanded_args)?,
        "node" => node_launch(&expanded_args)?,
        "npm" | "pnpm" | "yarn" => node_manager_launch(program, &expanded_args)?,
        "bun" => bun_launch(&expanded_args)?,
        "gradlew.bat" | "./gradlew" => gradle_launch(&root, program, &expanded_args)?,
        _ => generic_launch(&root, program, &expanded_args)?,
    };

    #[cfg(windows)]
    let mut launcher_kind = "direct";
    #[cfg(not(windows))]
    let launcher_kind = "direct";
    #[cfg(windows)]
    if is_batch(&launch.target) {
        let cmd = resolve_on_path("cmd")?;
        let command_args = batch_command_arguments(&launch.target, &launch.args)?;
        launch.runtime_files.push(cmd.clone());
        launch.env.push(("ComSpec".to_string(), path_value(&cmd)));
        launch.target = cmd;
        launch.args = command_args;
        launch.repository_target = false;
        launcher_kind = "windows_cmd_batch";
    }

    let runtime_identity = runtime_identity(&launch.runtime_files, &root, launcher_kind)?;
    let mut read_only_paths = Vec::new();
    let mut executable_paths = Vec::new();
    let runtime_roots = normalized_external_roots(&root, launch.runtime_roots)?;
    for runtime_root in &runtime_roots {
        read_only_paths.push(runtime_root.clone());
        #[cfg(windows)]
        collect_windows_runtime_images(runtime_root, &mut executable_paths)?;
    }
    if !launch.repository_target && !is_system_runtime(&launch.target) {
        push_external(&root, &mut read_only_paths, launch.target.clone());
        #[cfg(windows)]
        push_external(&root, &mut executable_paths, launch.target.clone());
    }
    read_only_paths.sort();
    read_only_paths.dedup();
    executable_paths.sort();
    executable_paths.dedup();

    let mut env = private_environment(&root, &cache_root);
    env.append(&mut launch.env);
    env.sort_by(|left, right| left.0.cmp(&right.0));
    for pair in env.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(HistoricalRuntimePlanError::Invalid(format!(
                "historical runtime planned duplicate environment variable {}",
                pair[0].0
            )));
        }
    }

    let mut path_prefixes = runtime_roots
        .iter()
        .map(|path| runtime_bin(path))
        .collect::<Vec<_>>();
    if let Some(parent) = launch.target.parent() {
        path_prefixes.push(parent.to_path_buf());
    }
    path_prefixes.extend(std::env::split_paths(std::ffi::OsStr::new(sandbox_path())));
    path_prefixes.sort();
    path_prefixes.dedup();
    let path = std::env::join_paths(path_prefixes).map_err(|error| {
        HistoricalRuntimePlanError::Invalid(format!(
            "failed to construct historical runtime PATH: {error}"
        ))
    })?;
    env.push(("PATH".to_string(), path.to_string_lossy().into_owned()));

    #[cfg(windows)]
    let windows_virtualized_paths = {
        let mut paths = vec![root.clone()];
        paths.extend(runtime_roots);
        collapse_non_overlapping_roots(paths)?
    };

    Ok(HistoricalRuntimePlan {
        command: SandboxCommand {
            root,
            workdir: PathBuf::from("."),
            program: launch.target.to_string_lossy().into_owned(),
            args: launch.args,
            read_only_paths,
            writable_paths: vec![cache_root],
            persistent_read_only_paths: Vec::new(),
            executable_paths,
            #[cfg(windows)]
            windows_virtualized_paths,
            env,
            allow_network: true,
            #[cfg(target_os = "macos")]
            allow_local_network: true,
            timeout: TEST_TIMEOUT,
            output_limit: TEST_OUTPUT_LIMIT,
            memory_limit: TEST_MEMORY_LIMIT,
            process_limit: TEST_PROCESS_LIMIT,
        },
        runtime_identity,
        launcher_kind,
    })
}

fn prepare_private_environment_directories(cache: &Path) -> Result<(), HistoricalRuntimePlanError> {
    for directory in PRIVATE_ENVIRONMENT_DIRECTORIES {
        fs::create_dir_all(cache.join(directory)).map_err(|error| {
            HistoricalRuntimePlanError::Invalid(format!(
                "failed to create private historical runtime directory {directory}: {error}"
            ))
        })?;
    }
    Ok(())
}

fn private_environment(root: &Path, cache: &Path) -> Vec<(String, String)> {
    let path = |name: &str| sandbox_repository_path(root, &cache.join(name));
    let home = path("home");
    let temp = path("tmp");
    vec![
        ("APPDATA".to_string(), home.clone()),
        ("BUN_INSTALL_CACHE_DIR".to_string(), path("bun-cache")),
        ("CARGO_HOME".to_string(), path("cargo-home")),
        ("CARGO_TARGET_DIR".to_string(), path("cargo-target")),
        ("CI".to_string(), "1".to_string()),
        ("COREPACK_HOME".to_string(), path("corepack")),
        ("GIT_CONFIG_GLOBAL".to_string(), path("gitconfig")),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
        ("GCM_INTERACTIVE".to_string(), "Never".to_string()),
        ("GOCACHE".to_string(), path("go-build")),
        ("GOMODCACHE".to_string(), path("go-mod")),
        ("GOPATH".to_string(), path("go-path")),
        ("GRADLE_USER_HOME".to_string(), path("gradle")),
        ("HOME".to_string(), home.clone()),
        ("LOCALAPPDATA".to_string(), home.clone()),
        ("NODE_REPL_HISTORY".to_string(), path("node-history")),
        ("PIP_CACHE_DIR".to_string(), path("pip")),
        ("PYTHONPYCACHEPREFIX".to_string(), path("pycache")),
        ("TEMP".to_string(), temp.clone()),
        ("TMP".to_string(), temp.clone()),
        ("TMPDIR".to_string(), temp),
        ("USERPROFILE".to_string(), home),
        ("XDG_CACHE_HOME".to_string(), path("xdg-cache")),
        ("npm_config_cache".to_string(), path("npm")),
        ("npm_config_userconfig".to_string(), path("npmrc")),
    ]
}

fn expand_reserved_argument(root: &Path, cache: &Path, argument: &str) -> String {
    match argument {
        "{sniff_private_python_env}" => sandbox_repository_path(root, &cache.join("python-env")),
        _ => argument.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::non_blind_history_runtime_support::runtime_identity;
    use super::*;
    use std::fs;

    #[test]
    fn missing_runtime_is_typed_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir(&cache).unwrap();
        let command = vec!["sniff-runtime-that-does-not-exist".to_string()];

        assert!(matches!(
            prepare_historical_runtime(root.path(), &cache, &command),
            Err(HistoricalRuntimePlanError::Unavailable(_))
        ));
    }

    #[test]
    fn runtime_prepares_every_directory_advertised_by_private_environment() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir(&cache).unwrap();
        let command = if cfg!(windows) {
            vec!["cmd".to_string(), "/c".to_string(), "exit 0".to_string()]
        } else {
            vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()]
        };

        let plan = prepare_historical_runtime(root.path(), &cache, &command).unwrap();
        let canonical_cache = fs::canonicalize(&cache).unwrap();
        for directory in PRIVATE_ENVIRONMENT_DIRECTORIES {
            assert!(
                cache.join(directory).is_dir(),
                "{directory} was not created"
            );
            let sandbox_value =
                sandbox_repository_path(&plan.command.root, &canonical_cache.join(directory));
            assert!(
                plan.command
                    .env
                    .iter()
                    .any(|(_, value)| value == &sandbox_value),
                "{directory} was not advertised by the private environment"
            );
        }
    }

    #[test]
    fn runtime_identity_does_not_bind_repository_program_bytes() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("test-tool");
        fs::write(&script, "first").unwrap();
        let first = runtime_identity(std::slice::from_ref(&script), root.path(), "direct").unwrap();
        fs::write(&script, "second").unwrap();
        let second = runtime_identity(&[script], root.path(), "direct").unwrap();

        assert_eq!(first, second);
    }
}
