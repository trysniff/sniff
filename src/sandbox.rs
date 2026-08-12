use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::ffi::c_void;
use std::io::{Read, Result as IoResult};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::process::CommandExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
#[path = "sandbox_windows.rs"]
mod sandbox_windows;

pub(crate) const DEFAULT_OUTPUT_LIMIT: usize = 256 * 1024;
#[cfg(windows)]
pub(crate) const DEFAULT_MEMORY_LIMIT: u64 = 1024 * 1024 * 1024;
#[cfg(unix)]
pub(crate) const DEFAULT_MEMORY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
#[cfg(not(any(unix, windows)))]
pub(crate) const DEFAULT_MEMORY_LIMIT: u64 = 1024 * 1024 * 1024;
pub(crate) const DEFAULT_PROCESS_LIMIT: u32 = 128;

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
type UnixResource = libc::__rlimit_resource_t;
#[cfg(any(all(target_os = "linux", target_env = "musl"), target_os = "macos"))]
type UnixResource = libc::c_int;

#[cfg(target_os = "linux")]
const SANDBOX_PROCESS_OVERHEAD: u64 = 2;
#[cfg(target_os = "macos")]
const SANDBOX_PROCESS_OVERHEAD: u64 = 0;

#[derive(Debug, Clone)]
pub(crate) struct SandboxCommand {
    pub(crate) root: PathBuf,
    pub(crate) workdir: PathBuf,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) read_only_paths: Vec<PathBuf>,
    /// Existing paths inside `root` that need an explicit transient write
    /// grant on backends whose root permission does not propagate retroactively.
    pub(crate) writable_paths: Vec<PathBuf>,
    /// Host-controlled toolchains that may retain a read-only sandbox grant.
    /// Repository content must never be placed in this collection.
    pub(crate) persistent_read_only_paths: Vec<PathBuf>,
    /// Trusted compiler/runtime images that the worker may execute. Windows
    /// grants these only to the unique per-run AppContainer identity.
    pub(crate) executable_paths: Vec<PathBuf>,
    /// Present explicitly trusted roots as temporary drives on Windows.
    /// AppContainer children otherwise traverse inaccessible host ancestors.
    #[cfg(windows)]
    pub(crate) windows_virtualized_paths: Vec<PathBuf>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) allow_network: bool,
    #[cfg(target_os = "macos")]
    pub(crate) allow_local_network: bool,
    pub(crate) timeout: Duration,
    pub(crate) output_limit: usize,
    pub(crate) memory_limit: u64,
    pub(crate) process_limit: u32,
}

impl SandboxCommand {
    fn all_read_only_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.read_only_paths
            .iter()
            .chain(self.persistent_read_only_paths.iter())
            .chain(self.executable_paths.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxOutput {
    pub(crate) status_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SandboxError {
    Unavailable(String),
    Invalid(String),
    Failed(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Invalid(message) | Self::Failed(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for SandboxError {}

pub(crate) fn run(spec: &SandboxCommand) -> Result<SandboxOutput, SandboxError> {
    validate_spec(spec)?;
    #[cfg(windows)]
    {
        if external_runner()?.is_none() {
            return sandbox_windows::run(spec);
        }
    }
    run_external(spec)
}

fn run_external(spec: &SandboxCommand) -> Result<SandboxOutput, SandboxError> {
    let mut command = build_command(spec)?;
    #[cfg(target_os = "linux")]
    configure_linux_resource_limits(&mut command, spec)?;
    #[cfg(target_os = "macos")]
    configure_macos_resource_limits(&mut command, spec)?;
    command
        .env_clear()
        .env("PATH", sandbox_path())
        .env("HOME", sandbox_home(spec))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .envs(spec.env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|error| {
        SandboxError::Failed(format!("failed to start sandbox worker: {error}"))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        SandboxError::Failed("sandbox worker stdout was not captured".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        SandboxError::Failed("sandbox worker stderr was not captured".to_string())
    })?;
    let limit = spec.output_limit.max(1);
    let stdout_reader = thread::spawn(move || read_limited(stdout, limit));
    let stderr_reader = thread::spawn(move || read_limited(stderr, limit));

    let started = Instant::now();
    let mut timed_out = false;
    #[cfg(target_os = "macos")]
    let mut memory_exceeded = false;
    #[cfg(target_os = "macos")]
    let mut process_limit_exceeded = false;
    let status = loop {
        #[cfg(target_os = "macos")]
        {
            let usage = match macos_process_group_usage(child.id(), spec.process_limit) {
                Ok(usage) => usage,
                Err(error) => {
                    let _ = terminate(&mut child);
                    let _ = child.wait();
                    return Err(error);
                }
            };
            if usage.processes > spec.process_limit {
                process_limit_exceeded = true;
                terminate(&mut child)?;
                break child.wait().map(Some).map_err(|error| {
                    SandboxError::Failed(format!("sandbox worker wait failed: {error}"))
                })?;
            }
            if usage.lifetime_peak_footprint > spec.memory_limit {
                memory_exceeded = true;
                terminate(&mut child)?;
                break child.wait().map(Some).map_err(|error| {
                    SandboxError::Failed(format!("sandbox worker wait failed: {error}"))
                })?;
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                #[cfg(target_os = "macos")]
                let _ = terminate_macos_process_group(child.id());
                break Some(status);
            }
            Ok(None) => {
                if started.elapsed() >= spec.timeout {
                    timed_out = true;
                    terminate(&mut child)?;
                    break child.wait().map(Some).map_err(|error| {
                        SandboxError::Failed(format!("sandbox worker wait failed: {error}"))
                    })?;
                }
                #[cfg(target_os = "macos")]
                thread::sleep(Duration::from_millis(1));
                #[cfg(not(target_os = "macos"))]
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                let _ = terminate(&mut child);
                return Err(SandboxError::Failed(format!(
                    "sandbox worker status failed: {error}"
                )));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| SandboxError::Failed("sandbox stdout reader panicked".to_string()))?
        .map_err(|error| SandboxError::Failed(format!("sandbox stdout read failed: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| SandboxError::Failed("sandbox stderr reader panicked".to_string()))?
        .map_err(|error| SandboxError::Failed(format!("sandbox stderr read failed: {error}")))?;
    #[cfg(target_os = "macos")]
    let mut stderr = stderr;
    #[cfg(target_os = "macos")]
    if memory_exceeded {
        if !stderr.is_empty() && !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        stderr
            .push_str("Sniff terminated the sandbox after its physical memory limit was exceeded");
    }
    #[cfg(target_os = "macos")]
    if process_limit_exceeded {
        if !stderr.is_empty() && !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        stderr.push_str("Sniff terminated the sandbox after its process limit was exceeded");
    }

    Ok(SandboxOutput {
        status_code: status.and_then(|status| status.code()),
        stdout,
        stderr,
        timed_out,
    })
}

fn validate_spec(spec: &SandboxCommand) -> Result<(), SandboxError> {
    if !spec.root.is_absolute() || !spec.root.is_dir() {
        return Err(SandboxError::Invalid(format!(
            "sandbox root must be an existing absolute directory: {}",
            spec.root.display()
        )));
    }
    if spec.workdir.is_absolute()
        || spec
            .workdir
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SandboxError::Invalid(
            "sandbox working directory must remain inside the sandbox root".to_string(),
        ));
    }
    if spec.program.trim().is_empty() {
        return Err(SandboxError::Invalid(
            "sandbox worker program cannot be empty".to_string(),
        ));
    }
    if spec.timeout.is_zero() {
        return Err(SandboxError::Invalid(
            "sandbox worker timeout must be positive".to_string(),
        ));
    }
    if spec.memory_limit == 0 || spec.process_limit == 0 {
        return Err(SandboxError::Invalid(
            "sandbox memory and process limits must be positive".to_string(),
        ));
    }
    for path in spec.all_read_only_paths() {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            SandboxError::Invalid(format!(
                "sandbox read-only path must exist: {} ({error})",
                path.display()
            ))
        })?;
        if !path.is_absolute() || metadata.file_type().is_symlink() {
            return Err(SandboxError::Invalid(format!(
                "sandbox read-only path must be an absolute non-symlink path: {}",
                path.display()
            )));
        }
    }
    let canonical_root = std::fs::canonicalize(&spec.root).map_err(|error| {
        SandboxError::Invalid(format!("sandbox root could not be canonicalized: {error}"))
    })?;
    for path in &spec.writable_paths {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            SandboxError::Invalid(format!(
                "sandbox writable path must exist: {} ({error})",
                path.display()
            ))
        })?;
        if !path.is_absolute() || metadata.file_type().is_symlink() {
            return Err(SandboxError::Invalid(format!(
                "sandbox writable path must be an absolute non-symlink path: {}",
                path.display()
            )));
        }
        let canonical_path = std::fs::canonicalize(path).map_err(|error| {
            SandboxError::Invalid(format!(
                "sandbox writable path could not be canonicalized: {} ({error})",
                path.display()
            ))
        })?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(SandboxError::Invalid(format!(
                "sandbox writable path must remain inside the repository root: {}",
                path.display()
            )));
        }
    }
    for path in &spec.persistent_read_only_paths {
        let canonical_path = std::fs::canonicalize(path).map_err(|error| {
            SandboxError::Invalid(format!(
                "persistent sandbox path could not be canonicalized: {} ({error})",
                path.display()
            ))
        })?;
        if canonical_path.starts_with(&canonical_root)
            || canonical_root.starts_with(&canonical_path)
        {
            return Err(SandboxError::Invalid(format!(
                "persistent sandbox read-only paths must not overlap the repository root: {}",
                path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        let mut seen = Vec::new();
        for path in &spec.windows_virtualized_paths {
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                SandboxError::Invalid(format!(
                    "Windows virtualized path must exist: {} ({error})",
                    path.display()
                ))
            })?;
            if !path.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(SandboxError::Invalid(format!(
                    "Windows virtualized path must be an absolute non-symlink directory: {}",
                    path.display()
                )));
            }
            let canonical_path = std::fs::canonicalize(path).map_err(|error| {
                SandboxError::Invalid(format!(
                    "Windows virtualized path could not be canonicalized: {} ({error})",
                    path.display()
                ))
            })?;
            if seen.iter().any(|existing: &PathBuf| {
                canonical_path.starts_with(existing) || existing.starts_with(&canonical_path)
            }) {
                return Err(SandboxError::Invalid(format!(
                    "Windows virtualized paths must be unique and non-overlapping: {}",
                    path.display()
                )));
            }
            seen.push(canonical_path.clone());
            if canonical_path == canonical_root {
                continue;
            }
            if canonical_path.starts_with(&canonical_root)
                || canonical_root.starts_with(&canonical_path)
            {
                return Err(SandboxError::Invalid(format!(
                    "Windows virtualized external paths must not overlap the repository root: {}",
                    path.display()
                )));
            }
            let covered = spec.persistent_read_only_paths.iter().any(|allowed| {
                std::fs::canonicalize(allowed)
                    .is_ok_and(|allowed| canonical_path.starts_with(allowed))
            });
            if !covered {
                return Err(SandboxError::Invalid(format!(
                    "Windows virtualized external paths require a persistent read-only grant: {}",
                    path.display()
                )));
            }
        }
    }
    for (key, value) in &spec.env {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(SandboxError::Invalid(
                "sandbox environment entries must have valid names and values".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_linux_resource_limits(
    command: &mut Command,
    spec: &SandboxCommand,
) -> Result<(), SandboxError> {
    let memory_limit = libc::rlim_t::try_from(spec.memory_limit)
        .map_err(|_| SandboxError::Invalid("sandbox memory limit exceeds rlim_t".to_string()))?;
    let current_processes = current_user_process_count().map_err(|error| {
        SandboxError::Failed(format!(
            "failed to establish the sandbox process baseline: {error}"
        ))
    })?;
    let process_limit = current_processes
        .checked_add(u64::from(spec.process_limit))
        .and_then(|limit| limit.checked_add(SANDBOX_PROCESS_OVERHEAD))
        .and_then(|limit| libc::rlim_t::try_from(limit).ok())
        .ok_or_else(|| SandboxError::Invalid("sandbox process limit exceeds rlim_t".to_string()))?;
    // The limits are installed after fork and before exec, then inherited by
    // the sandbox backend and every repository-controlled descendant.
    unsafe {
        command.pre_exec(move || {
            set_unix_memory_limit(memory_limit)?;
            set_unix_resource_limit(libc::RLIMIT_NPROC, process_limit)?;
            Ok(())
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_unix_resource_limit(resource: UnixResource, limit: libc::rlim_t) -> IoResult<()> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(resource, &mut current) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let limit = limit.min(current.rlim_max);
    let limits = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    if unsafe { libc::setrlimit(resource, &limits) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn set_unix_memory_limit(limit: libc::rlim_t) -> IoResult<()> {
    set_unix_resource_limit(libc::RLIMIT_AS, limit)
}

#[cfg(target_os = "macos")]
fn configure_macos_resource_limits(
    command: &mut Command,
    spec: &SandboxCommand,
) -> Result<(), SandboxError> {
    let current_processes = current_user_process_count().map_err(|error| {
        SandboxError::Failed(format!(
            "failed to establish the sandbox process baseline: {error}"
        ))
    })?;
    let process_limit = current_processes
        .checked_add(u64::from(spec.process_limit))
        .and_then(|limit| limit.checked_add(SANDBOX_PROCESS_OVERHEAD))
        .ok_or_else(|| SandboxError::Invalid("sandbox process limit overflowed".to_string()))?;
    let process_limit = libc::rlim_t::try_from(process_limit)
        .map_err(|_| SandboxError::Invalid("sandbox process limit is too large".to_string()))?;
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            set_unix_resource_limit(libc::RLIMIT_NPROC, process_limit)
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct MacosResourceUsageV4 {
    uuid: [u8; 16],
    fields_before_lifetime_peak: [u64; 28],
    lifetime_peak_footprint: u64,
    trailing_fields: [u64; 6],
}

#[cfg(target_os = "macos")]
struct MacosProcessGroupUsage {
    processes: u32,
    lifetime_peak_footprint: u64,
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listpgrppids(process_group: libc::pid_t, buffer: *mut c_void, size: i32) -> i32;
    fn proc_pid_rusage(pid: libc::pid_t, flavor: i32, buffer: *mut c_void) -> i32;
}

#[cfg(target_os = "macos")]
fn macos_process_group_usage(
    process_group: u32,
    process_limit: u32,
) -> Result<MacosProcessGroupUsage, SandboxError> {
    const RUSAGE_INFO_V4: i32 = 4;
    let observed =
        unsafe { proc_listpgrppids(process_group as libc::pid_t, std::ptr::null_mut(), 0) };
    if observed < 0 {
        return Err(SandboxError::Failed(format!(
            "failed to size the sandbox process inventory: {}",
            std::io::Error::last_os_error()
        )));
    }
    let maximum = usize::try_from(process_limit)
        .map_err(|_| SandboxError::Invalid("sandbox process limit is too large".to_string()))?
        .checked_add(32)
        .ok_or_else(|| SandboxError::Invalid("sandbox process limit overflowed".to_string()))?;
    let capacity = usize::try_from(observed)
        .map_err(|_| {
            SandboxError::Failed("macOS returned an invalid sandbox process count".to_string())
        })?
        .checked_add(32)
        .ok_or_else(|| SandboxError::Failed("sandbox process inventory overflowed".to_string()))?
        .min(maximum);
    let mut pids = vec![0 as libc::pid_t; capacity];
    let byte_size = pids
        .len()
        .checked_mul(std::mem::size_of::<libc::pid_t>())
        .and_then(|size| i32::try_from(size).ok())
        .ok_or_else(|| {
            SandboxError::Invalid("sandbox process inventory is too large".to_string())
        })?;
    let count = unsafe {
        proc_listpgrppids(
            process_group as libc::pid_t,
            pids.as_mut_ptr().cast(),
            byte_size,
        )
    };
    if count < 0 {
        return Err(SandboxError::Failed(format!(
            "failed to inspect sandbox process group memory: {}",
            std::io::Error::last_os_error()
        )));
    }
    let count = usize::try_from(count).map_err(|_| {
        SandboxError::Failed("macOS returned an invalid sandbox process count".to_string())
    })?;
    if count >= pids.len() {
        return Err(SandboxError::Failed(
            "sandbox process inventory exceeded its enforced process limit".to_string(),
        ));
    }

    let processes = u32::try_from(count)
        .map_err(|_| SandboxError::Failed("sandbox process count overflowed".to_string()))?;

    let lifetime_peak_footprint = pids
        .into_iter()
        .take(count)
        .filter(|pid| *pid > 0)
        .try_fold(0_u64, |total, pid| {
            let mut usage = MacosResourceUsageV4::default();
            let usage_pointer = std::ptr::from_mut(&mut usage).cast::<c_void>();
            if unsafe { proc_pid_rusage(pid, RUSAGE_INFO_V4, usage_pointer) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(total);
                }
                return Err(SandboxError::Failed(format!(
                    "failed to inspect sandbox process {pid} memory: {error}"
                )));
            }
            total
                .checked_add(usage.lifetime_peak_footprint)
                .ok_or_else(|| {
                    SandboxError::Failed(
                        "sandbox physical memory accounting overflowed".to_string(),
                    )
                })
        })?;
    Ok(MacosProcessGroupUsage {
        processes,
        lifetime_peak_footprint,
    })
}

#[cfg(target_os = "linux")]
fn current_user_process_count() -> IoResult<u64> {
    let current_uid = unsafe { libc::geteuid() };
    let mut total_threads = 0_u64;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let uid = status.lines().find_map(|line| {
            line.strip_prefix("Uid:")?
                .split_ascii_whitespace()
                .next()?
                .parse::<libc::uid_t>()
                .ok()
        });
        if uid != Some(current_uid) {
            continue;
        }
        let threads = status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:")?.trim().parse::<u64>().ok())
            .unwrap_or(1);
        total_threads = total_threads.saturating_add(threads);
    }
    Ok(total_threads.max(1))
}

#[cfg(target_os = "macos")]
fn current_user_process_count() -> IoResult<u64> {
    const PROC_UID_ONLY: u32 = 4;
    unsafe extern "C" {
        fn proc_listpids(
            process_type: u32,
            type_info: u32,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    let uid = unsafe { libc::geteuid() };
    let required = unsafe { proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0) };
    if required <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    let pid_size = std::mem::size_of::<libc::pid_t>();
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|bytes| bytes.checked_add(pid_size * 32))
        .ok_or_else(|| std::io::Error::other("macOS process list is too large"))?;
    let mut pids = vec![0 as libc::pid_t; capacity.div_ceil(pid_size)];
    let bytes = unsafe {
        proc_listpids(
            PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            libc::c_int::try_from(pids.len() * pid_size)
                .map_err(|_| std::io::Error::other("macOS process list is too large"))?,
        )
    };
    if bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let count = usize::try_from(bytes)
        .unwrap_or_default()
        .div_ceil(pid_size)
        .min(pids.len());
    Ok(pids[..count].iter().filter(|pid| **pid > 0).count().max(1) as u64)
}

fn build_command(spec: &SandboxCommand) -> Result<Command, SandboxError> {
    if let Some(runner) = external_runner()? {
        let mut command = Command::new(runner);
        command
            .arg("--root")
            .arg(&spec.root)
            .arg("--workdir")
            .arg(&spec.workdir)
            .arg("--timeout-ms")
            .arg(spec.timeout.as_millis().to_string())
            .arg("--memory-limit-bytes")
            .arg(spec.memory_limit.to_string())
            .arg("--process-limit")
            .arg(spec.process_limit.to_string())
            .args(spec.all_read_only_paths().flat_map(|path| {
                [
                    OsString::from("--read-only-path"),
                    path.as_os_str().to_os_string(),
                ]
            }))
            .args(spec.env.iter().flat_map(|(key, value)| {
                [
                    OsString::from("--env"),
                    OsString::from(format!("{key}={value}")),
                ]
            }))
            .arg(if spec.allow_network {
                "--allow-network"
            } else {
                "--deny-network"
            })
            .arg("--")
            .arg(&spec.program)
            .args(&spec.args);
        return Ok(command);
    }

    #[cfg(target_os = "linux")]
    {
        build_bubblewrap_command(spec)
    }

    #[cfg(target_os = "macos")]
    {
        return build_macos_sandbox_command(spec);
    }

    #[cfg(target_os = "windows")]
    {
        let _ = spec;
        Err(SandboxError::Unavailable(
            "Windows sandbox backend must be invoked through sandbox::run".to_string(),
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = spec;
        Err(SandboxError::Unavailable(
            "sandboxed execution is unavailable on this platform; configure SNIFF_SANDBOX_RUNNER with a hardened runner".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn build_bubblewrap_command(spec: &SandboxCommand) -> Result<Command, SandboxError> {
    let bwrap = find_on_path("bwrap").ok_or_else(|| {
        SandboxError::Unavailable(
            "Linux repository execution requires bubblewrap (`bwrap`)".to_string(),
        )
    })?;
    let mut command = Command::new(bwrap);
    command.args(["--die-with-parent", "--new-session", "--clearenv"]);
    if !spec.allow_network {
        command.arg("--unshare-all");
    } else {
        command.args(["--unshare-all", "--share-net"]);
    }
    command.args([
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/etc",
        "/etc",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/home",
        "--bind",
    ]);
    command.arg(&spec.root).arg("/workspace");
    if spec.allow_network {
        command.args(["--ro-bind", "/run", "/run"]);
    }
    for path in spec.all_read_only_paths() {
        if linux_system_mount_is_already_bound(path) {
            continue;
        }
        command.arg("--ro-bind").arg(path).arg(path);
    }
    let sandbox_workdir = if spec.workdir == Path::new(".") {
        "/workspace".to_string()
    } else {
        format!("/workspace/{}", spec.workdir.display())
    };
    command
        .args(["--chdir", &sandbox_workdir])
        .arg("--setenv")
        .arg("PATH")
        .arg(sandbox_path())
        .arg("--setenv")
        .arg("HOME")
        .arg("/tmp/home")
        .arg("--setenv")
        .arg("LANG")
        .arg("C")
        .arg("--setenv")
        .arg("LC_ALL")
        .arg("C")
        .args(spec.env.iter().flat_map(|(key, value)| {
            [
                OsString::from("--setenv"),
                OsString::from(key),
                OsString::from(value),
            ]
        }))
        .arg(linux_sandbox_program(spec)?)
        .args(&spec.args);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn linux_sandbox_program(spec: &SandboxCommand) -> Result<OsString, SandboxError> {
    let program = Path::new(&spec.program);
    if !program.is_absolute() {
        return Ok(program.as_os_str().to_os_string());
    }
    let canonical_program = std::fs::canonicalize(program).map_err(|error| {
        SandboxError::Invalid(format!(
            "sandbox worker program could not be canonicalized: {} ({error})",
            program.display()
        ))
    })?;
    let canonical_root = std::fs::canonicalize(&spec.root).map_err(|error| {
        SandboxError::Invalid(format!("sandbox root could not be canonicalized: {error}"))
    })?;
    let Ok(relative) = canonical_program.strip_prefix(&canonical_root) else {
        return Ok(canonical_program.into_os_string());
    };
    Ok(Path::new("/workspace").join(relative).into_os_string())
}

#[cfg(target_os = "linux")]
fn linux_system_mount_is_already_bound(path: &Path) -> bool {
    ["/usr", "/bin", "/lib", "/lib64", "/etc"]
        .iter()
        .any(|bound| Path::new(bound) == path)
}

#[cfg(target_os = "macos")]
fn build_macos_sandbox_command(spec: &SandboxCommand) -> Result<Command, SandboxError> {
    let sandbox_exec = find_on_path("sandbox-exec").ok_or_else(|| {
        SandboxError::Unavailable("macOS repository execution requires sandbox-exec".to_string())
    })?;
    let canonical_root = std::fs::canonicalize(&spec.root).map_err(|error| {
        SandboxError::Invalid(format!("sandbox root could not be canonicalized: {error}"))
    })?;
    let profile = canonical_root.join(".sniff-sandbox.sb");
    let root = profile_path(&canonical_root)?;
    let read_only_rules = spec
        .all_read_only_paths()
        .map(|path| {
            let path_text = profile_path(path)?;
            let filter = if path.is_dir() {
                format!("(subpath \"{path_text}\")")
            } else {
                format!("(literal \"{path_text}\")")
            };
            Ok::<_, SandboxError>(format!("(allow file-read* {filter})\n"))
        })
        .collect::<Result<String, _>>()?;
    let network_rule = if spec.allow_network {
        "(allow network*)\n"
    } else if spec.allow_local_network {
        "(allow network-bind (local ip \"*:*\"))\n(allow network-inbound (local ip \"localhost:*\"))\n(allow network* (remote ip \"localhost:*\"))\n(allow network* (remote unix-socket))\n"
    } else {
        "(deny network*)\n"
    };
    let profile_text = format!(
        "(version 1)\n(deny default)\n(allow process-exec)\n(allow process-exec-interpreter)\n(allow process-fork)\n(allow signal (target same-sandbox))\n(allow ipc-posix-shm)\n(allow ipc-posix-sem)\n(allow sysctl-read)\n(allow mach-lookup (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n(allow file-read-metadata)\n(allow file-read-data (literal \"/\"))\n(allow file-read* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (literal \"/dev/dtracehelper\") (literal \"/dev/tty\"))\n(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\"))\n(allow file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (literal \"/dev/dtracehelper\") (literal \"/dev/tty\"))\n(allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/private/etc\") (subpath \"/private/var/db\") (subpath \"/private/var/select\") (subpath \"{root}\"))\n{read_only_rules}(allow file-write* (subpath \"{root}\"))\n{network_rule}"
    );
    std::fs::write(&profile, profile_text).map_err(|error| {
        SandboxError::Failed(format!("failed to write macOS sandbox profile: {error}"))
    })?;
    let mut command = Command::new(sandbox_exec);
    command
        .arg("-f")
        .arg(profile)
        .arg("--")
        .arg(&spec.program)
        .args(&spec.args)
        .current_dir(canonical_root.join(&spec.workdir));
    Ok(command)
}

fn external_runner() -> Result<Option<PathBuf>, SandboxError> {
    validate_external_runner(std::env::var_os("SNIFF_SANDBOX_RUNNER"))
}

fn validate_external_runner(
    value: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, SandboxError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err(SandboxError::Unavailable(
            "SNIFF_SANDBOX_RUNNER must name an existing absolute executable".to_string(),
        ));
    }
    Ok(Some(path))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = directory.join(format!("{program}.exe"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub(crate) fn sandbox_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\Windows\System32"
    } else {
        "/usr/local/bin:/usr/bin:/bin"
    }
}

fn sandbox_home(spec: &SandboxCommand) -> String {
    if cfg!(target_os = "windows") {
        spec.root.to_string_lossy().to_string()
    } else {
        "/tmp/home".to_string()
    }
}

#[cfg(target_os = "macos")]
fn profile_path(path: &Path) -> Result<String, SandboxError> {
    let text = path
        .to_str()
        .ok_or_else(|| SandboxError::Invalid("sandbox path is not valid UTF-8".to_string()))?;
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn read_limited<R: Read>(reader: R, limit: usize) -> IoResult<String> {
    read_limited_with_observer(reader, limit, |_| {})
}

fn read_limited_with_observer<R, F>(
    mut reader: R,
    limit: usize,
    mut observer: F,
) -> IoResult<String>
where
    R: Read,
    F: FnMut(&[u8]),
{
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observer(&buffer[..count]);
        if bytes.len() < limit {
            let retained = count.min(limit - bytes.len());
            bytes.extend_from_slice(&buffer[..retained]);
            if retained < count {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        text.push_str("\n[output truncated by Sniff]");
    }
    Ok(text)
}

fn terminate(child: &mut Child) -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    return terminate_macos_process_group(child.id());

    #[cfg(not(target_os = "macos"))]
    child.kill().map_err(|error| {
        SandboxError::Failed(format!("failed to terminate sandbox worker: {error}"))
    })
}

#[cfg(target_os = "macos")]
fn terminate_macos_process_group(process_group: u32) -> Result<(), SandboxError> {
    if unsafe { libc::killpg(process_group as libc::pid_t, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SandboxError::Failed(format!(
            "failed to terminate sandbox process group: {error}"
        )))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::linux_sandbox_program;
    use super::{
        DEFAULT_MEMORY_LIMIT, DEFAULT_PROCESS_LIMIT, SandboxCommand, SandboxError, read_limited,
        read_limited_with_observer, validate_external_runner, validate_spec,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_child_accepts_process_group_and_process_limit_setup() {
        let mut command = std::process::Command::new("/usr/bin/true");
        let limits = spec(std::env::temp_dir());
        super::configure_macos_resource_limits(&mut command, &limits)
            .expect("prepare macOS resource wrapper");

        let status = command
            .status()
            .expect("macOS resource wrapper should start");

        assert!(status.success());
    }

    fn spec(root: PathBuf) -> SandboxCommand {
        SandboxCommand {
            root,
            workdir: PathBuf::from("."),
            program: "test".to_string(),
            args: Vec::new(),
            read_only_paths: Vec::new(),
            writable_paths: Vec::new(),
            persistent_read_only_paths: Vec::new(),
            executable_paths: Vec::new(),
            #[cfg(windows)]
            windows_virtualized_paths: Vec::new(),
            env: Vec::new(),
            allow_network: false,
            #[cfg(target_os = "macos")]
            allow_local_network: false,
            timeout: Duration::from_secs(1),
            output_limit: 32,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            process_limit: DEFAULT_PROCESS_LIMIT,
        }
    }

    #[test]
    fn rejects_workdir_escape() {
        let mut command = spec(std::env::temp_dir());
        command.workdir = PathBuf::from("../outside");

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("inside")));
    }

    #[test]
    fn rejects_relative_root() {
        let error = validate_spec(&spec(PathBuf::from("relative"))).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("absolute")));
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut command = spec(std::env::temp_dir());
        command.timeout = Duration::ZERO;

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("positive")));
    }

    #[test]
    fn rejects_zero_resource_limits() {
        let mut command = spec(std::env::temp_dir());
        command.memory_limit = 0;

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("limits")));

        command.memory_limit = DEFAULT_MEMORY_LIMIT;
        command.process_limit = 0;
        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("limits")));
    }

    #[test]
    fn rejects_invalid_read_only_mounts() {
        let mut command = spec(std::env::temp_dir());
        command.read_only_paths = vec![PathBuf::from("relative")];

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("read-only")));
    }

    #[test]
    fn rejects_writable_paths_outside_the_repository() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("repository");
        let outside = parent.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let mut command = spec(root);
        command.writable_paths = vec![outside];

        let error = validate_spec(&command).unwrap_err();

        assert!(
            matches!(error, SandboxError::Invalid(message) if message.contains("inside the repository"))
        );
    }

    #[test]
    fn rejects_persistent_access_to_repository_content() {
        let root =
            std::env::temp_dir().join(format!("sniff-persistent-root-test-{}", std::process::id()));
        let nested = root.join("tool");
        std::fs::create_dir_all(&nested).unwrap();
        let mut command = spec(root.clone());
        command.persistent_read_only_paths = vec![nested];

        let error = validate_spec(&command).unwrap_err();

        assert!(
            matches!(error, SandboxError::Invalid(message) if message.contains("must not overlap"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn rejects_ungranted_external_windows_drive_roots() {
        let repository = tempfile::tempdir().unwrap();
        let toolchain = tempfile::tempdir().unwrap();
        let mut command = spec(repository.path().to_path_buf());
        command.windows_virtualized_paths = vec![toolchain.path().to_path_buf()];

        let error = validate_spec(&command).unwrap_err();

        assert!(
            matches!(error, SandboxError::Invalid(message) if message.contains("persistent read-only grant"))
        );
    }

    #[test]
    fn rejects_persistent_access_to_repository_ancestors() {
        let parent = std::env::temp_dir().join(format!(
            "sniff-persistent-parent-test-{}",
            std::process::id()
        ));
        let root = parent.join("repository");
        std::fs::create_dir_all(&root).unwrap();
        let mut command = spec(root);
        command.persistent_read_only_paths = vec![parent.clone()];

        let error = validate_spec(&command).unwrap_err();

        assert!(
            matches!(error, SandboxError::Invalid(message) if message.contains("must not overlap"))
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn rejects_invalid_environment_entries() {
        let mut command = spec(std::env::temp_dir());
        command.env = vec![("BAD=NAME".to_string(), "value".to_string())];

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("environment")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_repository_program_uses_the_workspace_mount() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("worker");
        std::fs::write(&executable, b"worker").unwrap();
        let mut command = spec(root.path().to_path_buf());
        command.program = executable.to_string_lossy().into_owned();

        assert_eq!(
            linux_sandbox_program(&command).unwrap(),
            std::ffi::OsString::from("/workspace/worker")
        );
    }

    #[test]
    fn limits_worker_output_without_unbounded_buffering() {
        let output = read_limited("0123456789".as_bytes(), 4).unwrap();

        assert_eq!(output, "0123\n[output truncated by Sniff]");
    }

    #[test]
    fn observes_all_worker_output_while_retaining_only_the_limit() {
        let mut observed = Vec::new();
        let output = read_limited_with_observer("0123456789".as_bytes(), 4, |chunk| {
            observed.extend_from_slice(chunk);
        })
        .unwrap();

        assert_eq!(observed, b"0123456789");
        assert_eq!(output, "0123\n[output truncated by Sniff]");
    }

    #[test]
    fn invalid_external_runner_does_not_fall_through_to_a_platform_backend() {
        let error = validate_external_runner(Some(std::ffi::OsString::from("relative-runner")))
            .unwrap_err();
        assert!(
            matches!(error, SandboxError::Unavailable(message) if message.contains("absolute"))
        );
    }

    #[cfg(windows)]
    fn windows_test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sniff-sandbox-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create Windows sandbox test root");
        root
    }

    #[cfg(windows)]
    fn windows_command(root: PathBuf, script: String) -> SandboxCommand {
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot should be defined");
        let source = PathBuf::from(system_root).join("System32").join("cmd.exe");
        let program = root.join("sniff-test-worker.exe");
        std::fs::copy(source, &program).expect("stage Windows sandbox test worker");
        SandboxCommand {
            root,
            workdir: PathBuf::from("."),
            program: program.to_string_lossy().into_owned(),
            args: vec!["/D".to_string(), "/S".to_string(), "/C".to_string(), script],
            read_only_paths: Vec::new(),
            writable_paths: Vec::new(),
            persistent_read_only_paths: Vec::new(),
            executable_paths: Vec::new(),
            #[cfg(windows)]
            windows_virtualized_paths: Vec::new(),
            env: Vec::new(),
            allow_network: false,
            timeout: Duration::from_secs(2),
            output_limit: 1024,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            process_limit: DEFAULT_PROCESS_LIMIT,
        }
    }

    #[cfg(windows)]
    #[cfg(windows)]
    #[test]
    fn windows_backend_denies_writes_outside_repository_root() {
        let root = windows_test_root("escape");
        let outside = root.with_extension("outside");
        let mut command =
            windows_command(root.clone(), format!("type nul > {}", outside.display()));
        command.timeout = Duration::from_secs(5);

        let _ = super::run(&command).expect("Windows AppContainer should start");

        assert!(!outside.exists(), "sandbox wrote outside repository root");
        std::fs::remove_dir_all(root).unwrap();
        let _ = std::fs::remove_file(outside);
    }

    #[cfg(windows)]
    #[test]
    fn windows_backend_writes_to_an_explicit_preexisting_directory() {
        let root = windows_test_root("explicit-write");
        let cache = root.join(".sniff-indexer-cache");
        let evidence = cache.join("probe.txt");
        std::fs::create_dir(&cache).unwrap();
        let mut command = windows_command(
            root.clone(),
            r"echo sandbox-write>.sniff-indexer-cache\probe.txt".to_string(),
        );
        command.writable_paths = vec![cache];

        let output = super::run(&command).expect("Windows AppContainer should start");

        assert_eq!(
            output.status_code,
            Some(0),
            "stdout={:?} stderr={:?}",
            output.stdout,
            output.stderr
        );
        assert_eq!(
            std::fs::read_to_string(evidence).unwrap().trim(),
            "sandbox-write"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_backend_reads_only_explicit_external_toolchains() {
        let root = windows_test_root("persistent-read");
        let external = windows_test_root("external-toolchain");
        let evidence = external.join("evidence.txt");
        std::fs::write(&evidence, "trusted-toolchain-evidence").unwrap();

        let denied = windows_command(root.clone(), format!("type {}", evidence.display()));
        let denied_output = super::run(&denied).expect("Windows AppContainer should start");
        assert_ne!(denied_output.status_code, Some(0));
        assert!(!denied_output.stdout.contains("trusted-toolchain-evidence"));

        let mut allowed = windows_command(root.clone(), format!("type {}", evidence.display()));
        allowed.persistent_read_only_paths = vec![external.clone()];
        let allowed_output = super::run(&allowed).expect("persistent read capability should work");
        assert_eq!(
            allowed_output.status_code,
            Some(0),
            "stdout={:?} stderr={:?}",
            allowed_output.stdout,
            allowed_output.stderr
        );
        assert!(allowed_output.stdout.contains("trusted-toolchain-evidence"));

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(external).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_backend_executes_only_explicit_external_toolchains() {
        let root = windows_test_root("persistent-execute");
        let external = windows_test_root("external-executable");
        let child = external.join("trusted-child.exe");
        let sibling = external.join("private-sibling.txt");
        std::fs::write(&sibling, "must-not-leak").expect("stage private sibling");
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot should be defined");
        std::fs::copy(
            PathBuf::from(system_root)
                .join("System32")
                .join("whoami.exe"),
            &child,
        )
        .expect("stage signed external child process");
        let script = child.display().to_string();
        let denied = windows_command(root.clone(), script);
        let denied_output = super::run(&denied).expect("Windows AppContainer should start");
        assert_ne!(denied_output.status_code, Some(0));

        let mut allowed = denied;
        allowed.executable_paths = vec![child.clone()];
        let allowed_output =
            super::run(&allowed).expect("transient toolchain execution grant should work");
        assert_eq!(
            allowed_output.status_code,
            Some(0),
            "stdout={:?} stderr={:?}",
            allowed_output.stdout,
            allowed_output.stderr
        );
        assert!(allowed_output.stdout.contains('\\'));

        let mut sibling_read = windows_command(root.clone(), format!("type {}", sibling.display()));
        sibling_read.executable_paths = vec![child];
        let sibling_output = super::run(&sibling_read).expect("Windows AppContainer should start");
        assert_ne!(sibling_output.status_code, Some(0));
        assert!(!sibling_output.stdout.contains("must-not-leak"));

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(external).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_backend_terminates_a_timed_out_worker() {
        let root = windows_test_root("timeout");
        let mut command = windows_command(
            root.clone(),
            "for /L %i in (1,1,2147483647) do @rem".to_string(),
        );
        command.timeout = Duration::from_millis(100);

        let output = super::run(&command).expect("Windows AppContainer should start");

        assert!(output.timed_out, "worker should be marked as timed out");
        assert_ne!(output.status_code, Some(0));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_backend_denies_writes_outside_repository_root() {
        let root = std::env::temp_dir().join(format!(
            "sniff-sandbox-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create sandbox root");
        let outside_name = format!(
            "sniff-sandbox-escape-{}",
            root.file_name()
                .expect("sandbox root should have a name")
                .to_string_lossy()
        );
        let outside = root
            .parent()
            .expect("sandbox root has a parent")
            .join(&outside_name);
        let command = SandboxCommand {
            root: root.clone(),
            workdir: PathBuf::from("."),
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), format!("touch ../{outside_name}")],
            read_only_paths: Vec::new(),
            writable_paths: Vec::new(),
            persistent_read_only_paths: Vec::new(),
            executable_paths: Vec::new(),
            #[cfg(windows)]
            windows_virtualized_paths: Vec::new(),
            env: Vec::new(),
            allow_network: false,
            #[cfg(target_os = "macos")]
            allow_local_network: false,
            timeout: Duration::from_secs(2),
            output_limit: 1024,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            process_limit: DEFAULT_PROCESS_LIMIT,
        };

        let result = super::run(&command).expect("Unix sandbox backend should be available");
        assert!(
            result.status_code.is_some(),
            "sandbox worker did not start successfully: stderr={:?}",
            result.stderr
        );
        assert!(!outside.exists(), "sandbox wrote outside repository root");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(outside);
    }

    #[cfg(unix)]
    #[test]
    fn unix_backend_terminates_a_timed_out_worker() {
        let root = std::env::temp_dir().join(format!(
            "sniff-sandbox-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create sandbox root");
        let command = SandboxCommand {
            root: root.clone(),
            workdir: PathBuf::from("."),
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "while :; do :; done".to_string()],
            read_only_paths: Vec::new(),
            writable_paths: Vec::new(),
            persistent_read_only_paths: Vec::new(),
            executable_paths: Vec::new(),
            #[cfg(windows)]
            windows_virtualized_paths: Vec::new(),
            env: Vec::new(),
            allow_network: false,
            #[cfg(target_os = "macos")]
            allow_local_network: false,
            timeout: Duration::from_millis(100),
            output_limit: 1024,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            process_limit: DEFAULT_PROCESS_LIMIT,
        };

        let result = super::run(&command).expect("Unix sandbox backend should be available");
        assert!(result.timed_out, "worker should be marked as timed out");
        assert_ne!(
            result.status_code,
            Some(0),
            "timed-out worker unexpectedly passed"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
#[path = "tests/sandbox_security.rs"]
mod security_tests;
