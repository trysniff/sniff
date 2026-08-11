use super::{
    SandboxCommand, SandboxError, SandboxOutput, read_limited, read_limited_with_observer,
};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation, WAIT_ABANDONED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetExplicitEntriesFromAclW, GetNamedSecurityInfoW, REVOKE_ACCESS, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, DeriveCapabilitySidsFromName, EqualSid, NO_INHERITANCE,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateMutexW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ReleaseMutex, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

const INTERNET_CLIENT_SID: &str = "S-1-15-3-1";
const PERSISTENT_READ_CAPABILITY: &str = "trysniff.semantic-indexer-read.v1";
const SE_GROUP_ENABLED: u32 = 0x00000004;
const FILE_GENERIC_READ_ACCESS: u32 = 0x0012_0089;
const PROCESS_CREATION_CHILD_PROCESS_OVERRIDE: u32 = 0x02;
const MAX_PROCESS_MEMORY: usize = 1024 * 1024 * 1024;
const MAX_ACTIVE_PROCESSES: u32 = 128;
const ACL_COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const ACL_COMMAND_OUTPUT_LIMIT: usize = 64 * 1024;
const WINDOWS_SANDBOX_LOCK_NAME: &str = r"Local\SniffWindowsSandboxAclLock";
const WINDOWS_SANDBOX_LOCK_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const SANDBOX_PROCESS_CREATION_FLAGS: u32 =
    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED;
static WINDOWS_SANDBOX_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn run(spec: &SandboxCommand) -> Result<SandboxOutput, SandboxError> {
    let started = Instant::now();
    let _sandbox_lock = WINDOWS_SANDBOX_LOCK.lock().map_err(|_| {
        SandboxError::Failed("Windows sandbox coordination lock was poisoned".to_string())
    })?;
    let _cross_process_lock = CrossProcessLock::acquire()?;
    trace_phase(started, "coordination lock acquired");
    let program = resolve_program(&spec.program)?;
    let mut effective_spec = spec.clone();
    effective_spec.program = program.to_string_lossy().into_owned();
    effective_spec.read_only_paths.push(program.clone());
    effective_spec
        .read_only_paths
        .extend(effective_spec.executable_paths.iter().cloned());
    let profile_name = unique_profile_name();
    let profile_name_w = wide_null(&profile_name);
    let display_name = wide_null("Sniff temporary sandbox");
    let description = wide_null("Ephemeral Sniff repository worker");

    let mut network_sid = std::ptr::null_mut();
    let mut capabilities = Vec::new();
    if spec.allow_network {
        if unsafe {
            ConvertStringSidToSidW(wide_null(INTERNET_CLIENT_SID).as_ptr(), &mut network_sid) == 0
        } {
            return Err(last_error("create Windows network capability SID"));
        }
        capabilities.push(SID_AND_ATTRIBUTES {
            Sid: network_sid,
            Attributes: SE_GROUP_ENABLED,
        });
    }
    let persistent_read_capability = if spec.persistent_read_only_paths.is_empty() {
        None
    } else {
        let capability = CapabilitySid::derive(PERSISTENT_READ_CAPABILITY)?;
        capabilities.push(SID_AND_ATTRIBUTES {
            Sid: capability.sid,
            Attributes: SE_GROUP_ENABLED,
        });
        Some(capability)
    };

    let mut app_container_sid = std::ptr::null_mut();
    let capability_pointer = if capabilities.is_empty() {
        std::ptr::null()
    } else {
        capabilities.as_ptr()
    };
    let profile_result = unsafe {
        CreateAppContainerProfile(
            profile_name_w.as_ptr(),
            display_name.as_ptr(),
            description.as_ptr(),
            capability_pointer,
            capabilities.len() as u32,
            &mut app_container_sid,
        )
    };
    if profile_result < 0 {
        free_sid(network_sid);
        return Err(SandboxError::Failed(format!(
            "create Windows AppContainer profile failed with HRESULT 0x{:08x}",
            profile_result as u32
        )));
    }
    let profile_guard = ProfileGuard {
        name: profile_name_w,
        sid: app_container_sid,
        network_sid,
    };
    trace_phase(started, "AppContainer profile created");

    let app_container_sid_text = sid_string(profile_guard.sid)?;
    if let Some(capability) = &persistent_read_capability {
        let capability_sid = sid_string(capability.sid)?;
        for path in &effective_spec.persistent_read_only_paths {
            ensure_persistent_read_acl(path, capability.sid, &capability_sid)?;
        }
        trace_phase(started, "persistent toolchain access verified");
    }
    let mut acl_guard = AclGuard::grant(
        &effective_spec.root,
        &effective_spec.read_only_paths,
        &app_container_sid_text,
    )?;
    trace_phase(started, "filesystem access granted");
    // AppContainer file-read permission is not enough to launch an executable.
    grant_acl(&program, &app_container_sid_text, "RX")?;
    for path in &effective_spec.executable_paths {
        grant_acl(path, &app_container_sid_text, "RX")?;
    }
    trace_phase(started, "program execution granted");
    let result = run_process(&effective_spec, profile_guard.sid, &mut capabilities);
    trace_phase(started, "sandbox process returned");
    let revoke = acl_guard.revoke();
    trace_phase(started, "filesystem access revoked");
    match (result, revoke) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(SandboxError::Failed(format!(
            "{error}; additionally, Windows sandbox ACL cleanup failed: {cleanup_error}"
        ))),
    }
}

struct CapabilitySid {
    sid: *mut c_void,
}

impl CapabilitySid {
    fn derive(name: &str) -> Result<Self, SandboxError> {
        let name = wide_null(name);
        let mut group_sids = std::ptr::null_mut();
        let mut group_count = 0_u32;
        let mut capability_sids = std::ptr::null_mut();
        let mut capability_count = 0_u32;
        let derived = unsafe {
            DeriveCapabilitySidsFromName(
                name.as_ptr(),
                &mut group_sids,
                &mut group_count,
                &mut capability_sids,
                &mut capability_count,
            )
        };
        if derived == 0 {
            return Err(last_error("derive Windows sandbox capability SID"));
        }

        let capability_sid = if capability_count == 1 && !capability_sids.is_null() {
            unsafe { *capability_sids }
        } else {
            std::ptr::null_mut()
        };
        unsafe {
            free_sid_array(group_sids, group_count, std::ptr::null_mut());
            free_sid_array(capability_sids, capability_count, capability_sid);
        }
        if capability_sid.is_null() {
            return Err(SandboxError::Failed(format!(
                "Windows returned {capability_count} SIDs for sandbox capability {PERSISTENT_READ_CAPABILITY}; expected exactly one"
            )));
        }
        Ok(Self {
            sid: capability_sid,
        })
    }
}

impl Drop for CapabilitySid {
    fn drop(&mut self) {
        free_sid(self.sid);
    }
}

unsafe fn free_sid_array(array: *mut *mut c_void, count: u32, retained: *mut c_void) {
    if array.is_null() {
        return;
    }
    for index in 0..count as usize {
        let sid = unsafe { *array.add(index) };
        if sid != retained {
            free_sid(sid);
        }
    }
    unsafe { LocalFree(array as _) };
}

fn trace_phase(started: Instant, phase: &str) {
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!(
            "[sniff] Windows sandbox {phase}: {:.3}s",
            started.elapsed().as_secs_f64()
        );
    }
}

struct CrossProcessLock {
    handle: HANDLE,
}

impl CrossProcessLock {
    fn acquire() -> Result<Self, SandboxError> {
        let name = wide_null(WINDOWS_SANDBOX_LOCK_NAME);
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(last_error("create Windows sandbox coordination mutex"));
        }

        let wait =
            unsafe { WaitForSingleObject(handle, WINDOWS_SANDBOX_LOCK_TIMEOUT.as_millis() as u32) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            return Ok(Self { handle });
        }

        unsafe {
            CloseHandle(handle);
        }
        if wait == WAIT_TIMEOUT {
            return Err(SandboxError::Failed(format!(
                "Windows sandbox coordination mutex was not acquired within {} seconds",
                WINDOWS_SANDBOX_LOCK_TIMEOUT.as_secs()
            )));
        }
        Err(last_error("wait for Windows sandbox coordination mutex"))
    }
}

impl Drop for CrossProcessLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

fn resolve_program(program: &str) -> Result<std::path::PathBuf, SandboxError> {
    let candidate = std::path::Path::new(program);
    if candidate.is_absolute() || program.contains(['\\', '/']) {
        return std::fs::canonicalize(candidate)
            .map(normalize_windows_path)
            .map_err(|error| {
                SandboxError::Failed(format!(
                    "sandbox program {} is unavailable: {error}",
                    candidate.display()
                ))
            });
    }
    let path = std::env::var_os("PATH").ok_or_else(|| {
        SandboxError::Unavailable("sandbox program resolution requires PATH".to_string())
    })?;
    for directory in std::env::split_paths(&path) {
        let base = directory.join(program);
        for candidate in [
            base.clone(),
            base.with_extension("exe"),
            base.with_extension("cmd"),
        ] {
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate)
                    .map(normalize_windows_path)
                    .map_err(|error| {
                        SandboxError::Failed(format!(
                            "sandbox program {} could not be resolved: {error}",
                            candidate.display()
                        ))
                    });
            }
        }
    }
    Err(SandboxError::Failed(format!(
        "sandbox program {program} was not found on the host PATH"
    )))
}

fn normalize_windows_path(path: std::path::PathBuf) -> std::path::PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{}", rest));
    }
    text.strip_prefix(r"\\?\")
        .map_or(path, std::path::PathBuf::from)
}

fn run_process(
    spec: &SandboxCommand,
    app_container_sid: *mut c_void,
    capabilities: &mut [SID_AND_ATTRIBUTES],
) -> Result<SandboxOutput, SandboxError> {
    let (stdout_read, stdout_write) = create_pipe()?;
    let (stderr_read, stderr_write) = create_pipe()?;
    let mut attributes_size = 0usize;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 3, 0, &mut attributes_size);
    }
    if attributes_size == 0 {
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("size Windows process attribute list"));
    }
    let mut attributes_buffer = vec![0u8; attributes_size];
    let attributes = attributes_buffer.as_mut_ptr() as *mut c_void;
    if unsafe {
        InitializeProcThreadAttributeList(attributes as _, 3, 0, &mut attributes_size) == 0
    } {
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("initialize Windows process attribute list"));
    }
    let capability_pointer = if capabilities.is_empty() {
        std::ptr::null_mut()
    } else {
        capabilities.as_mut_ptr()
    };
    let mut security = SECURITY_CAPABILITIES {
        AppContainerSid: app_container_sid,
        Capabilities: capability_pointer,
        CapabilityCount: capabilities.len() as u32,
        Reserved: 0,
    };
    if unsafe {
        UpdateProcThreadAttribute(
            attributes as _,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &mut security as *mut _ as _,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) == 0
    } {
        unsafe { DeleteProcThreadAttributeList(attributes as _) };
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("configure Windows AppContainer process"));
    }
    let mut child_process_policy = PROCESS_CREATION_CHILD_PROCESS_OVERRIDE;
    if unsafe {
        UpdateProcThreadAttribute(
            attributes as _,
            0,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
            &mut child_process_policy as *mut _ as _,
            std::mem::size_of::<u32>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
    } {
        unsafe { DeleteProcThreadAttributeList(attributes as _) };
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("allow Windows sandbox compiler child processes"));
    }
    let inherited_handles = [stdout_write, stderr_write];
    if unsafe {
        UpdateProcThreadAttribute(
            attributes as _,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited_handles.as_ptr() as _,
            std::mem::size_of_val(&inherited_handles),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
    } {
        unsafe { DeleteProcThreadAttributeList(attributes as _) };
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("configure Windows AppContainer output handles"));
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = stdout_write;
    startup.StartupInfo.hStdError = stderr_write;
    startup.lpAttributeList = attributes as _;

    let mut command_line = command_line(spec);
    let mut environment = environment(spec);
    let current_directory = spec.root.join(&spec.workdir);
    let current_directory_w = wide_null(&current_directory.to_string_lossy());
    let mut process_info = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            SANDBOX_PROCESS_CREATION_FLAGS,
            environment.as_mut_ptr() as _,
            current_directory_w.as_ptr(),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    unsafe { DeleteProcThreadAttributeList(attributes as _) };
    unsafe {
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);
    }
    if created == 0 {
        close_handles([stdout_read, stderr_read]);
        return Err(last_error("start Windows AppContainer process"));
    }
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        terminate_process_and_close(process_info.hProcess);
        unsafe { CloseHandle(process_info.hThread) };
        close_handles([stdout_read, stderr_read]);
        return Err(last_error("create Windows sandbox job"));
    }
    if let Err(error) = configure_job(job) {
        terminate_process_and_close(process_info.hProcess);
        unsafe {
            CloseHandle(job);
            CloseHandle(process_info.hThread);
        }
        close_handles([stdout_read, stderr_read]);
        return Err(error);
    }
    if unsafe { AssignProcessToJobObject(job, process_info.hProcess) } == 0 {
        unsafe {
            TerminateJobObject(job, 1);
            CloseHandle(job);
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
        }
        close_handles([stdout_read, stderr_read]);
        return Err(last_error("assign Windows AppContainer process to job"));
    }
    let resumed = unsafe { ResumeThread(process_info.hThread) };
    unsafe { CloseHandle(process_info.hThread) };
    if resumed == u32::MAX {
        let error = last_error("resume Windows AppContainer process");
        unsafe {
            TerminateJobObject(job, 1);
            CloseHandle(job);
            CloseHandle(process_info.hProcess);
        }
        close_handles([stdout_read, stderr_read]);
        return Err(error);
    }

    let stdout_thread = read_thread(stdout_read, spec.output_limit, "stdout");
    let stderr_thread = read_thread(stderr_read, spec.output_limit, "stderr");
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        let wait = unsafe { WaitForSingleObject(process_info.hProcess, 25) };
        if wait == WAIT_OBJECT_0 {
            break;
        }
        if wait != WAIT_TIMEOUT {
            unsafe {
                TerminateJobObject(job, 1);
                CloseHandle(job);
                CloseHandle(process_info.hProcess);
            }
            return Err(last_error("wait for Windows AppContainer process"));
        }
        if started.elapsed() >= spec.timeout {
            timed_out = true;
            unsafe {
                TerminateJobObject(job, 1);
                WaitForSingleObject(process_info.hProcess, 5_000);
            }
            break;
        }
    }
    let mut exit_code = 1u32;
    if unsafe { GetExitCodeProcess(process_info.hProcess, &mut exit_code) } == 0 {
        exit_code = 1;
    }
    unsafe {
        CloseHandle(job);
        CloseHandle(process_info.hProcess);
    }
    let stdout = stdout_thread
        .join()
        .map_err(|_| SandboxError::Failed("Windows stdout reader panicked".to_string()))?
        .map_err(|error| SandboxError::Failed(format!("Windows stdout read failed: {error}")))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| SandboxError::Failed("Windows stderr reader panicked".to_string()))?
        .map_err(|error| SandboxError::Failed(format!("Windows stderr read failed: {error}")))?;
    Ok(SandboxOutput {
        status_code: Some(exit_code as i32),
        stdout,
        stderr,
        timed_out,
    })
}

fn terminate_process_and_close(process: HANDLE) {
    unsafe {
        TerminateProcess(process, 1);
        CloseHandle(process);
    }
}

fn configure_job(job: HANDLE) -> Result<(), SandboxError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = MAX_ACTIVE_PROCESSES;
    limits.ProcessMemoryLimit = MAX_PROCESS_MEMORY;
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(last_error("configure Windows sandbox job limits"));
    }
    Ok(())
}

fn create_pipe() -> Result<(HANDLE, HANDLE), SandboxError> {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(last_error("create Windows sandbox output pipe"));
    }
    if unsafe { SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0) } == 0 {
        close_handles([read, write]);
        return Err(last_error("protect Windows sandbox output pipe"));
    }
    Ok((read, write))
}

fn read_thread(
    handle: HANDLE,
    limit: usize,
    stream_name: &'static str,
) -> thread::JoinHandle<std::io::Result<String>> {
    let handle_value = handle as isize;
    let debug = std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some();
    thread::spawn(move || unsafe {
        let file = std::fs::File::from_raw_handle(handle_value as _);
        if debug {
            let mut traced = 0usize;
            read_limited_with_observer(file, limit, |chunk| {
                if traced >= limit {
                    return;
                }
                let count = chunk.len().min(limit - traced);
                eprintln!(
                    "[sniff] semantic indexer {stream_name}: {}",
                    String::from_utf8_lossy(&chunk[..count])
                );
                traced += count;
            })
        } else {
            read_limited(file, limit)
        }
    })
}

fn command_line(spec: &SandboxCommand) -> Vec<u16> {
    let mut values = Vec::with_capacity(spec.args.len() + 1);
    values.push(spec.program.clone());
    values.extend(spec.args.iter().cloned());
    wide_null(
        &values
            .into_iter()
            .map(|value| quote_arg(&value))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn environment(spec: &SandboxCommand) -> Vec<u16> {
    let mut values = BTreeMap::from([
        ("PATH".to_string(), super::sandbox_path().to_string()),
        ("HOME".to_string(), spec.root.to_string_lossy().to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
    ]);
    let root = spec.root.to_string_lossy();
    if root.as_bytes().get(1) == Some(&b':') {
        values.insert(format!("={}", &root[..2]), root.to_string());
    }
    for key in [
        "ALLUSERSPROFILE",
        "APPDATA",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
        "ComSpec",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "OS",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "SystemDrive",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            values.insert(key.to_string(), value.to_string_lossy().into_owned());
        }
    }
    for (key, value) in &spec.env {
        values.insert(key.clone(), value.clone());
    }
    let mut block = values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\0")
        .encode_utf16()
        .collect::<Vec<_>>();
    // CreateProcessW requires an environment block terminated by two NULs.
    block.push(0);
    block.push(0);
    block
}

fn quote_arg(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return value.to_string();
    }
    let mut quoted = String::from("\"");
    let mut slashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
        } else if character == '"' {
            quoted.push_str(&"\\".repeat(slashes * 2 + 1));
            quoted.push('"');
            slashes = 0;
        } else {
            quoted.push_str(&"\\".repeat(slashes));
            quoted.push(character);
            slashes = 0;
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

fn grant_acl(path: &Path, sid: &str, permission: &str) -> Result<(), SandboxError> {
    let path = normalize_windows_path(path.to_path_buf());
    let inheritance = if path.is_dir() { "(OI)(CI)" } else { "" };
    let rule = format!("*{sid}:{inheritance}{permission}");
    let mut command = Command::new("icacls");
    command.arg(&path).arg("/grant").arg(rule).arg("/C");
    let output = run_icacls(command).map_err(|error| match error {
        SandboxError::Unavailable(message) => SandboxError::Unavailable(format!(
            "Windows AppContainer requires icacls for {}: {message}",
            path.display()
        )),
        SandboxError::Invalid(message) => {
            SandboxError::Invalid(format!("icacls failed for {}: {message}", path.display()))
        }
        SandboxError::Failed(message) => {
            SandboxError::Failed(format!("icacls failed for {}: {message}", path.display()))
        }
    })?;
    if !output.success {
        return Err(SandboxError::Failed(format!(
            "grant Windows AppContainer access to {} failed: {}",
            path.display(),
            output.error_text()
        )));
    }
    Ok(())
}

fn ensure_persistent_read_acl(
    path: &Path,
    capability_sid: *mut c_void,
    capability_sid_text: &str,
) -> Result<(), SandboxError> {
    if persistent_read_acl_exists(path, capability_sid)? {
        return Ok(());
    }
    grant_acl(path, capability_sid_text, "R")
}

fn persistent_read_acl_exists(
    path: &Path,
    capability_sid: *mut c_void,
) -> Result<bool, SandboxError> {
    let path = normalize_windows_path(path.to_path_buf());
    let path_w = wide_null(&path.to_string_lossy());
    let mut acl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let get_status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if get_status != 0 {
        return Err(SandboxError::Failed(format!(
            "read persistent sandbox DACL for {} failed with Windows error {get_status}",
            path.display()
        )));
    }

    let mut entries = std::ptr::null_mut();
    let mut entry_count = 0_u32;
    let explicit_status =
        unsafe { GetExplicitEntriesFromAclW(acl, &mut entry_count, &mut entries) };
    let result = if explicit_status != 0 {
        Err(SandboxError::Failed(format!(
            "inspect persistent sandbox DACL for {} failed with Windows error {explicit_status}",
            path.display()
        )))
    } else {
        let entries = if entries.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(entries, entry_count as usize) }
        };
        Ok(entries.iter().any(|entry| {
            let trustee_sid = entry.Trustee.ptstrName as *mut c_void;
            entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                && !trustee_sid.is_null()
                && unsafe { EqualSid(trustee_sid, capability_sid) != 0 }
                && matches!(entry.grfAccessMode, GRANT_ACCESS | SET_ACCESS)
                && entry.grfAccessPermissions & FILE_GENERIC_READ_ACCESS == FILE_GENERIC_READ_ACCESS
                && (!path.is_dir()
                    || entry.grfInheritance & SUB_CONTAINERS_AND_OBJECTS_INHERIT
                        == SUB_CONTAINERS_AND_OBJECTS_INHERIT)
        }))
    };
    unsafe {
        if !entries.is_null() {
            LocalFree(entries as _);
        }
        if !descriptor.is_null() {
            LocalFree(descriptor);
        }
    }
    result
}

fn revoke_acl(path: &Path, sid: &str) -> Result<(), String> {
    let path = normalize_windows_path(path.to_path_buf());
    update_acl_entry(&path, sid, 0, REVOKE_ACCESS)
        .map_err(|error| format!("native ACL revoke failed for {}: {error}", path.display()))
}

fn update_acl_entry(
    path: &Path,
    sid: &str,
    permissions: u32,
    access_mode: i32,
) -> Result<(), String> {
    let sid_w = wide_null(sid);
    let mut sid_ptr = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid_ptr) } == 0 {
        return Err(format!(
            "convert AppContainer SID failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let path_w = wide_null(&path.to_string_lossy());
    let mut old_acl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let get_status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if get_status != 0 {
        unsafe {
            LocalFree(sid_ptr);
        }
        return Err(format!("read DACL failed with Windows error {get_status}"));
    }

    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
        ptstrName: sid_ptr as _,
        ..Default::default()
    };
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: permissions,
        grfAccessMode: access_mode,
        grfInheritance: NO_INHERITANCE,
        Trustee: trustee,
    };
    let mut new_acl = std::ptr::null_mut();
    let set_status = unsafe { SetEntriesInAclW(1, &entry, old_acl, &mut new_acl) };
    let result = if set_status != 0 {
        Err(format!(
            "build updated DACL failed with Windows error {set_status}"
        ))
    } else {
        let write_status = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_acl,
                std::ptr::null_mut(),
            )
        };
        if write_status == 0 {
            Ok(())
        } else {
            Err(format!(
                "write updated DACL failed with Windows error {write_status}"
            ))
        }
    };
    unsafe {
        if !new_acl.is_null() {
            LocalFree(new_acl as _);
        }
        if !descriptor.is_null() {
            LocalFree(descriptor);
        }
        LocalFree(sid_ptr);
    }
    result
}

struct IcalcsOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl IcalcsOutput {
    fn error_text(&self) -> String {
        let text = format!("{}\n{}", self.stderr.trim(), self.stdout.trim());
        text.trim().to_string()
    }
}

fn run_icacls(mut command: Command) -> Result<IcalcsOutput, SandboxError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| SandboxError::Unavailable(format!("icacls could not run: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Failed("icacls stdout was not captured".to_string()))?;
    let stdout_reader = thread::spawn(move || read_limited(stdout, ACL_COMMAND_OUTPUT_LIMIT));
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Failed("icacls stderr was not captured".to_string()))?;
    let stderr_reader = thread::spawn(move || read_limited(stderr, ACL_COMMAND_OUTPUT_LIMIT));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= ACL_COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(SandboxError::Failed(format!(
                    "icacls timed out after {} seconds",
                    ACL_COMMAND_TIMEOUT.as_secs()
                )));
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(SandboxError::Failed(format!(
                    "icacls status check failed: {error}"
                )));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| SandboxError::Failed("icacls stdout reader panicked".to_string()))?
        .map_err(|error| SandboxError::Failed(format!("icacls stdout read failed: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| SandboxError::Failed("icacls stderr reader panicked".to_string()))?
        .map_err(|error| SandboxError::Failed(format!("icacls stderr read failed: {error}")))?;
    let reported_failures =
        stdout.contains("Failed processing") && !stdout.contains("Failed processing 0 files");
    Ok(IcalcsOutput {
        success: status.success() && !reported_failures,
        stdout,
        stderr,
    })
}

struct AclGrant {
    path: std::path::PathBuf,
}

struct AclGuard {
    grants: Vec<AclGrant>,
    sid: String,
}

impl AclGuard {
    fn grant(
        root: &Path,
        read_only_paths: &[std::path::PathBuf],
        sid: &str,
    ) -> Result<Self, SandboxError> {
        let paths = explicit_acl_paths(root, read_only_paths);
        let mut grants: Vec<AclGrant> = Vec::with_capacity(paths.len());
        for path in paths {
            // Directory grants use inheritance rather than recursively
            // walking every dependency file. Cleanup removes the parent ACE;
            // inherited child access then disappears with it.
            let permission = if path.as_path() == root { "M" } else { "R" };
            if let Err(error) = grant_acl(&path, sid, permission) {
                for granted in grants.iter().rev() {
                    let _ = revoke_acl(&granted.path, sid);
                }
                return Err(error);
            }
            grants.push(AclGrant { path });
        }
        Ok(Self {
            grants,
            sid: sid.to_string(),
        })
    }

    fn revoke(&mut self) -> Result<(), SandboxError> {
        let mut failures = Vec::new();
        for grant in self.grants.drain(..).rev() {
            if let Err(error) = revoke_acl(&grant.path, &self.sid) {
                failures.push(format!("{}: {error}", grant.path.display()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::Failed(failures.join("; ")))
        }
    }
}

fn explicit_acl_paths(root: &Path, read_only_paths: &[std::path::PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(read_only_paths.len() + 1);
    for path in std::iter::once(root.to_path_buf()).chain(read_only_paths.iter().cloned()) {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

impl Drop for AclGuard {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

struct ProfileGuard {
    name: Vec<u16>,
    sid: *mut c_void,
    network_sid: *mut c_void,
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        let started = Instant::now();
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
            if !self.sid.is_null() {
                LocalFree(self.sid);
            }
            if !self.network_sid.is_null() {
                LocalFree(self.network_sid);
            }
        }
        if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
            eprintln!(
                "[sniff] Windows sandbox AppContainer profile deleted: {:.3}s",
                started.elapsed().as_secs_f64()
            );
        }
    }
}

fn sid_string(sid: *mut c_void) -> Result<String, SandboxError> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(last_error("convert Windows AppContainer SID"));
    }
    let result = unsafe {
        let mut length = 0usize;
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    };
    unsafe { LocalFree(text as _) };
    Ok(result)
}

fn free_sid(sid: *mut c_void) {
    if !sid.is_null() {
        unsafe { LocalFree(sid) };
    }
}

fn close_handles<const N: usize>(handles: [HANDLE; N]) {
    for handle in handles {
        if !handle.is_null() {
            unsafe { CloseHandle(handle) };
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn unique_profile_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    format!("SniffSandbox-{}-{nanos}", std::process::id())
}

fn last_error(action: &str) -> SandboxError {
    SandboxError::Failed(format!(
        "{action} failed with Windows error {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CREATE_SUSPENDED, CapabilitySid, SANDBOX_PROCESS_CREATION_FLAGS,
        ensure_persistent_read_acl, explicit_acl_paths, persistent_read_acl_exists, sid_string,
    };
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Security::EqualSid;

    #[test]
    fn appcontainer_process_starts_suspended_before_job_assignment() {
        assert_ne!(SANDBOX_PROCESS_CREATION_FLAGS & CREATE_SUSPENDED, 0);
    }

    #[test]
    fn repository_acl_targets_never_include_ancestors() {
        let root = Path::new(r"C:\work\repository");
        let tool = PathBuf::from(r"C:\tools\node.exe");

        let paths = explicit_acl_paths(root, std::slice::from_ref(&tool));

        assert_eq!(paths, [root.to_path_buf(), tool]);
        assert!(!paths.contains(&PathBuf::from(r"C:\")));
        assert!(!paths.contains(&PathBuf::from(r"C:\work")));
    }

    #[test]
    fn named_persistent_read_capability_is_stable() {
        let first = CapabilitySid::derive(super::PERSISTENT_READ_CAPABILITY).unwrap();
        let second = CapabilitySid::derive(super::PERSISTENT_READ_CAPABILITY).unwrap();

        assert_ne!(first.sid, second.sid);
        assert_ne!(unsafe { EqualSid(first.sid, second.sid) }, 0);
    }

    #[test]
    fn persistent_read_acl_is_granted_once_and_detected() {
        let root = std::env::temp_dir().join(format!(
            "sniff-persistent-acl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let capability = CapabilitySid::derive(super::PERSISTENT_READ_CAPABILITY).unwrap();
        let capability_text = sid_string(capability.sid).unwrap();

        assert!(!persistent_read_acl_exists(&root, capability.sid).unwrap());
        ensure_persistent_read_acl(&root, capability.sid, &capability_text).unwrap();
        assert!(persistent_read_acl_exists(&root, capability.sid).unwrap());

        std::fs::remove_dir_all(root).unwrap();
    }
}
