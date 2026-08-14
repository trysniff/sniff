use super::non_blind_history_runtime::HistoricalRuntimePlanError;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const RUNTIME_IDENTITY_CONTRACT: &str = "sniffbench-historical-runtime-v1";
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const QUERY_OUTPUT_LIMIT: usize = 64 * 1024;

pub(super) fn runtime_identity(
    files: &[PathBuf],
    repository_root: &Path,
    launcher_kind: &str,
) -> Result<String, HistoricalRuntimePlanError> {
    let repository_root = canonical_directory(repository_root, "runtime identity repository")?;
    let mut records = Vec::new();
    for path in files {
        let path = canonical_file(path, "runtime identity file")?;
        if path.starts_with(&repository_root) {
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| {
            HistoricalRuntimePlanError::Invalid(format!(
                "failed to hash runtime image {}: {error}",
                path.display()
            ))
        })?;
        records.push((
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("runtime")
                .to_ascii_lowercase(),
            format!("{:x}", Sha256::digest(bytes)),
        ));
    }
    records.sort();
    records.dedup();
    let mut digest = Sha256::new();
    for value in [
        RUNTIME_IDENTITY_CONTRACT,
        std::env::consts::OS,
        std::env::consts::ARCH,
        launcher_kind,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    if records.is_empty() {
        digest.update(b"repository-native");
    }
    for (name, hash) in records {
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(hash.as_bytes());
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(windows)]
pub(super) fn resolve_rust_tool(name: &str) -> Result<PathBuf, HistoricalRuntimePlanError> {
    if let Ok(rustup) = resolve_on_path("rustup") {
        let output = run_query(&rustup, &["which", name], "rustup tool resolution")?;
        return canonical_file(Path::new(&output), "active Rust tool");
    }
    resolve_on_path(name)
}

#[cfg(not(windows))]
pub(super) fn resolve_rust_tool(name: &str) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let rustc = resolve_on_path("rustc")?;
    let sysroot = query_path(&rustc, &["--print", "sysroot"], "active Rust sysroot")?;
    canonical_file(&sysroot.join("bin").join(name), "active Rust tool")
}

pub(super) fn rust_toolchain_root(path: &Path) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("Rust tool has no containing directory"))?;
    if parent.file_name().is_some_and(|value| value == "bin") {
        return parent
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| unavailable("Rust toolchain bin has no root"));
    }
    Ok(parent.to_path_buf())
}

pub(super) fn reject_broad_user_root(path: &Path) -> Result<(), HistoricalRuntimePlanError> {
    let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
    else {
        return Ok(());
    };
    if canonical_directory(&home, "user home").is_ok_and(|home| home == path) {
        return Err(unavailable(
            "Rust runtime resolution would expose the complete user home; install rustup so Sniff can resolve the active toolchain exactly",
        ));
    }
    Ok(())
}

pub(super) fn query_path(
    program: &Path,
    args: &[&str],
    label: &str,
) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let value = run_query(program, args, label)?;
    canonical_directory(Path::new(&value), label)
}

fn run_query(
    program: &Path,
    args: &[&str],
    label: &str,
) -> Result<String, HistoricalRuntimePlanError> {
    let mut command = Command::new(program);
    command.args(args);
    let program_directory = program
        .parent()
        .ok_or_else(|| unavailable(format!("{label} program has no containing directory")))?;
    command.current_dir(program_directory);
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        QUERY_TIMEOUT,
        QUERY_OUTPUT_LIMIT,
    )
    .map_err(|error| unavailable(format!("failed to query {label}: {error}")))?;
    if output.timed_out || output.stdout_truncated || output.stderr_truncated {
        return Err(unavailable(format!(
            "{label} did not return bounded output"
        )));
    }
    if !output.status.success() {
        return Err(unavailable(format!("{label} failed")));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| unavailable(format!("{label} returned non-UTF-8 output")))?;
    let mut lines = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let value = lines
        .next()
        .ok_or_else(|| unavailable(format!("{label} returned no value")))?;
    if lines.next().is_some() {
        return Err(unavailable(format!("{label} returned multiple values")));
    }
    Ok(value.to_string())
}

pub(super) fn resolve_on_path(program: &str) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let path = std::env::var_os("PATH").ok_or_else(|| {
        unavailable(format!(
            "{program} runtime is unavailable because PATH is unset"
        ))
    })?;
    for directory in std::env::split_paths(&path) {
        let base = directory.join(program);
        #[cfg(windows)]
        let candidates = [
            base.clone(),
            base.with_extension("exe"),
            base.with_extension("cmd"),
            base.with_extension("bat"),
        ];
        #[cfg(not(windows))]
        let candidates = [base];
        for candidate in candidates {
            if candidate.is_file() {
                return canonical_file(&candidate, "runtime program");
            }
        }
    }
    Err(unavailable(format!(
        "required runtime {program} is unavailable"
    )))
}

pub(super) fn repository_program(
    root: &Path,
    program: &str,
) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let relative = program.strip_prefix("./").unwrap_or(program);
    let path = canonical_file(&root.join(relative), "repository test program")?;
    if !path.starts_with(root) {
        return Err(HistoricalRuntimePlanError::Invalid(
            "historical test program escapes its repository snapshot".to_string(),
        ));
    }
    Ok(path)
}

pub(super) fn looks_repository_relative(program: &str) -> bool {
    program.starts_with("./")
        || program.starts_with(".\\")
        || program.contains('/')
        || program.contains('\\')
}

pub(super) fn normalized_external_roots(
    repository_root: &Path,
    roots: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, HistoricalRuntimePlanError> {
    let mut normalized = Vec::new();
    for root in roots {
        let root = canonical_directory(&root, "runtime root")?;
        if root.starts_with(repository_root) {
            continue;
        }
        if repository_root.starts_with(&root) {
            return Err(HistoricalRuntimePlanError::Invalid(format!(
                "runtime root would expose a parent of the repository: {}",
                root.display()
            )));
        }
        normalized.push(root);
    }
    collapse_non_overlapping_roots(normalized)
}

pub(super) fn collapse_non_overlapping_roots(
    mut roots: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, HistoricalRuntimePlanError> {
    roots.sort_by_key(|path| path.components().count());
    let mut result = Vec::<PathBuf>::new();
    for path in roots {
        if path.parent().is_none() {
            return Err(HistoricalRuntimePlanError::Invalid(
                "refusing to grant a complete filesystem root to a historical test".to_string(),
            ));
        }
        if result.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        result.retain(|existing| !existing.starts_with(&path));
        result.push(path);
    }
    result.sort();
    Ok(result)
}

pub(super) fn parent_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, HistoricalRuntimePlanError> {
    path.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| unavailable(format!("{label} has no containing directory")))
}

pub(super) fn runtime_bin(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    if bin.is_dir() {
        bin
    } else {
        root.to_path_buf()
    }
}

pub(super) fn canonical_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, HistoricalRuntimePlanError> {
    if !path.is_dir() {
        return Err(unavailable(format!(
            "{label} is unavailable: {}",
            path.display()
        )));
    }
    fs::canonicalize(path)
        .map(normalize_path)
        .map_err(|error| unavailable(format!("failed to resolve {label}: {error}")))
}

pub(super) fn canonical_file(
    path: &Path,
    label: &str,
) -> Result<PathBuf, HistoricalRuntimePlanError> {
    if !path.is_file() {
        return Err(unavailable(format!(
            "{label} is unavailable: {}",
            path.display()
        )));
    }
    fs::canonicalize(path)
        .map(normalize_path)
        .map_err(|error| unavailable(format!("failed to resolve {label}: {error}")))
}

pub(super) fn push_external(root: &Path, paths: &mut Vec<PathBuf>, path: PathBuf) {
    let path = normalize_path(path);
    if !path.starts_with(root) {
        paths.push(path);
    }
}

pub(super) fn sandbox_repository_path(_root: &Path, path: &Path) -> String {
    #[cfg(target_os = "linux")]
    if let Ok(relative) = path.strip_prefix(_root) {
        return Path::new("/workspace")
            .join(relative)
            .to_string_lossy()
            .into_owned();
    }
    path_value(path)
}

pub(super) fn path_value(path: &Path) -> String {
    normalize_path(path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

#[cfg(windows)]
pub(super) fn is_batch(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("cmd") || value.eq_ignore_ascii_case("bat"))
}

#[cfg(windows)]
pub(super) fn batch_command_arguments(
    target: &Path,
    args: &[String],
) -> Result<Vec<String>, HistoricalRuntimePlanError> {
    let mut values = Vec::with_capacity(args.len() + 1);
    values.push(path_value(target));
    values.extend(args.iter().cloned());
    for value in &values {
        if value.contains(['"', '&', '|', '<', '>', '^', '%', '!']) {
            return Err(unavailable(
                "Windows batch launcher cannot preserve this exact argv without shell expansion",
            ));
        }
    }
    Ok(["/D", "/S", "/C", "call"]
        .into_iter()
        .map(str::to_string)
        .chain(values)
        .collect())
}

#[cfg(windows)]
pub(super) fn collect_windows_runtime_images(
    runtime_root: &Path,
    images: &mut Vec<PathBuf>,
) -> Result<(), HistoricalRuntimePlanError> {
    const MAX_ENTRIES: usize = 100_000;
    const MAX_IMAGES: usize = 4_096;
    let mut pending = vec![runtime_root.to_path_buf()];
    let mut entries = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            unavailable(format!(
                "failed to enumerate Windows runtime {}: {error}",
                directory.display()
            ))
        })? {
            let entry =
                entry.map_err(|error| unavailable(format!("invalid runtime entry: {error}")))?;
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err(unavailable(
                    "Windows runtime exceeds the bounded entry limit",
                ));
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                unavailable(format!("failed to inspect runtime entry: {error}"))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(unavailable(format!(
                    "Windows runtime contains an untrusted symlink: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| {
                        value.eq_ignore_ascii_case("exe") || value.eq_ignore_ascii_case("dll")
                    })
            {
                let bytes = fs::read(&path).map_err(|error| {
                    unavailable(format!("failed to read runtime image: {error}"))
                })?;
                if !bytes.starts_with(b"MZ") {
                    return Err(unavailable(format!(
                        "Windows runtime image is not PE: {}",
                        path.display()
                    )));
                }
                images.push(normalize_path(path));
                if images.len() > MAX_IMAGES {
                    return Err(unavailable(
                        "Windows runtime exceeds the executable image limit",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn is_system_runtime(path: &Path) -> bool {
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .and_then(|root| fs::canonicalize(root).ok())
            .is_some_and(|root| path.starts_with(normalize_path(root)))
    }
    #[cfg(not(windows))]
    {
        ["/usr", "/bin", "/System", "/Library"]
            .iter()
            .any(|root| path.starts_with(root))
    }
}

pub(super) fn unavailable(message: impl Into<String>) -> HistoricalRuntimePlanError {
    HistoricalRuntimePlanError::Unavailable(message.into())
}

#[cfg(windows)]
fn normalize_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    text.strip_prefix(r"\\?\").map_or(path, PathBuf::from)
}

#[cfg(not(windows))]
fn normalize_path(path: PathBuf) -> PathBuf {
    path
}
