use std::ffi::OsString;
use std::io::{Read, Result as IoResult};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_OUTPUT_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct SandboxCommand {
    pub(crate) root: PathBuf,
    pub(crate) workdir: PathBuf,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) read_only_paths: Vec<PathBuf>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) allow_network: bool,
    pub(crate) timeout: Duration,
    pub(crate) output_limit: usize,
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
    let mut command = build_command(spec)?;
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
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= spec.timeout => {
                timed_out = true;
                terminate(&mut child)?;
                break child.wait().map(Some).map_err(|error| {
                    SandboxError::Failed(format!("sandbox worker wait failed: {error}"))
                })?;
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
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
    for path in &spec.read_only_paths {
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
    for (key, value) in &spec.env {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(SandboxError::Invalid(
                "sandbox environment entries must have valid names and values".to_string(),
            ));
        }
    }
    Ok(())
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
            .args(spec.read_only_paths.iter().flat_map(|path| {
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
            "sandboxed execution is unavailable on Windows; configure SNIFF_SANDBOX_RUNNER with a hardened runner".to_string(),
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
        command.arg("--unshare-net");
    }
    command.args([
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-cgroup",
        "--unshare-user",
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
    for path in &spec.read_only_paths {
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
        .arg(&spec.program)
        .args(&spec.args);
    Ok(command)
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
        .read_only_paths
        .iter()
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
    } else {
        "(deny network*)\n"
    };
    let profile_text = format!(
        "(version 1)\n(deny default)\n(allow process-exec)\n(allow process-exec-interpreter)\n(allow process-fork)\n(allow signal (target same-sandbox))\n(allow ipc-posix-shm)\n(allow ipc-posix-sem)\n(allow sysctl-read)\n(allow mach-lookup (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n(allow file-read-metadata)\n(allow file-read-data (literal \"/\"))\n(allow file-read* (literal \"/dev/dtracehelper\") (literal \"/dev/tty\"))\n(allow file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (literal \"/dev/dtracehelper\") (literal \"/dev/tty\"))\n(allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/private\") (subpath \"{root}\"))\n{read_only_rules}(allow file-write* (subpath \"{root}\"))\n{network_rule}"
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

fn read_limited<R: Read>(mut reader: R, limit: usize) -> IoResult<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        text.push_str("\n[output truncated by Sniff]");
    }
    Ok(text)
}

fn terminate(child: &mut Child) -> Result<(), SandboxError> {
    child.kill().map_err(|error| {
        SandboxError::Failed(format!("failed to terminate sandbox worker: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        SandboxCommand, SandboxError, read_limited, validate_external_runner, validate_spec,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn spec(root: PathBuf) -> SandboxCommand {
        SandboxCommand {
            root,
            workdir: PathBuf::from("."),
            program: "test".to_string(),
            args: Vec::new(),
            read_only_paths: Vec::new(),
            env: Vec::new(),
            allow_network: false,
            timeout: Duration::from_secs(1),
            output_limit: 32,
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
    fn rejects_invalid_read_only_mounts() {
        let mut command = spec(std::env::temp_dir());
        command.read_only_paths = vec![PathBuf::from("relative")];

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("read-only")));
    }

    #[test]
    fn rejects_invalid_environment_entries() {
        let mut command = spec(std::env::temp_dir());
        command.env = vec![("BAD=NAME".to_string(), "value".to_string())];

        let error = validate_spec(&command).unwrap_err();
        assert!(matches!(error, SandboxError::Invalid(message) if message.contains("environment")));
    }

    #[test]
    fn limits_worker_output_without_unbounded_buffering() {
        let output = read_limited("0123456789".as_bytes(), 4).unwrap();

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
            env: Vec::new(),
            allow_network: false,
            timeout: Duration::from_secs(2),
            output_limit: 1024,
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
            env: Vec::new(),
            allow_network: false,
            timeout: Duration::from_millis(100),
            output_limit: 1024,
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
