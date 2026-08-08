use super::{SandboxCommand, SandboxError, SandboxOutput, read_limited};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

const INTERNET_CLIENT_SID: &str = "S-1-15-3-1";
const SE_GROUP_ENABLED: u32 = 0x00000004;
const MAX_PROCESS_MEMORY: usize = 1024 * 1024 * 1024;
const MAX_ACTIVE_PROCESSES: u32 = 128;

pub(super) fn run(spec: &SandboxCommand) -> Result<SandboxOutput, SandboxError> {
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

    let mut app_container_sid = std::ptr::null_mut();
    let profile_result = unsafe {
        CreateAppContainerProfile(
            profile_name_w.as_ptr(),
            display_name.as_ptr(),
            description.as_ptr(),
            capabilities.as_ptr(),
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

    let sid_string = sid_string(profile_guard.sid)?;
    let mut acl_guard = AclGuard::grant(&spec.root, &spec.read_only_paths, &sid_string)?;
    let result = run_process(spec, profile_guard.sid, &mut capabilities);
    let revoke = acl_guard.revoke();
    match (result, revoke) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(SandboxError::Failed(format!(
            "{error}; additionally, Windows sandbox ACL cleanup failed: {cleanup_error}"
        ))),
    }
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
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attributes_size);
    }
    if attributes_size == 0 {
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("size Windows process attribute list"));
    }
    let mut attributes_buffer = vec![0u8; attributes_size];
    let attributes = attributes_buffer.as_mut_ptr() as *mut c_void;
    if unsafe {
        InitializeProcThreadAttributeList(attributes as _, 1, 0, &mut attributes_size) == 0
    } {
        close_handles([stdout_read, stdout_write, stderr_read, stderr_write]);
        return Err(last_error("initialize Windows process attribute list"));
    }
    let mut security = SECURITY_CAPABILITIES {
        AppContainerSid: app_container_sid,
        Capabilities: capabilities.as_mut_ptr(),
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
    let creation_flags =
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            creation_flags,
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
    unsafe { CloseHandle(process_info.hThread) };

    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        terminate_process_and_close(process_info.hProcess);
        close_handles([stdout_read, stderr_read]);
        return Err(last_error("create Windows sandbox job"));
    }
    if let Err(error) = configure_job(job) {
        terminate_process_and_close(process_info.hProcess);
        unsafe {
            CloseHandle(job);
        }
        close_handles([stdout_read, stderr_read]);
        return Err(error);
    }
    if unsafe { AssignProcessToJobObject(job, process_info.hProcess) } == 0 {
        unsafe {
            TerminateJobObject(job, 1);
            CloseHandle(job);
            CloseHandle(process_info.hProcess);
        }
        close_handles([stdout_read, stderr_read]);
        return Err(last_error("assign Windows AppContainer process to job"));
    }

    let stdout_thread = read_thread(stdout_read, spec.output_limit);
    let stderr_thread = read_thread(stderr_read, spec.output_limit);
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

fn read_thread(handle: HANDLE, limit: usize) -> thread::JoinHandle<std::io::Result<String>> {
    let handle_value = handle as isize;
    thread::spawn(move || unsafe {
        read_limited(std::fs::File::from_raw_handle(handle_value as _), limit)
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
    let inheritance = if path.is_dir() { "(OI)(CI)" } else { "" };
    let rule = format!("*{sid}:{inheritance}{permission}");
    let mut command = Command::new("icacls");
    command.arg(path).arg("/grant").arg(rule).arg("/C");
    if path.is_dir() {
        command.arg("/T");
    }
    let output = command.output().map_err(|error| {
        SandboxError::Unavailable(format!("Windows AppContainer requires icacls: {error}"))
    })?;
    if !output.status.success() {
        return Err(SandboxError::Failed(format!(
            "grant Windows AppContainer access to {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn revoke_acl(path: &Path, sid: &str) -> Result<(), String> {
    let mut command = Command::new("icacls");
    command.arg(path).arg("/remove").arg(format!("*{sid}"));
    if path.is_dir() {
        command.args(["/T", "/C"]);
    }
    let output = command
        .output()
        .map_err(|error| format!("icacls could not run: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

struct AclGuard {
    paths: Vec<std::path::PathBuf>,
    sid: String,
}

impl AclGuard {
    fn grant(
        root: &Path,
        read_only_paths: &[std::path::PathBuf],
        sid: &str,
    ) -> Result<Self, SandboxError> {
        grant_acl(root, sid, "M")?;
        let mut paths = Vec::with_capacity(read_only_paths.len() + 1);
        paths.push(root.to_path_buf());
        for path in read_only_paths {
            if let Err(error) = grant_acl(path, sid, "R") {
                for granted in paths.iter().rev() {
                    let _ = revoke_acl(granted, sid);
                }
                return Err(error);
            }
            paths.push(path.clone());
        }
        Ok(Self {
            paths,
            sid: sid.to_string(),
        })
    }

    fn revoke(&mut self) -> Result<(), SandboxError> {
        let mut failures = Vec::new();
        for path in self.paths.drain(..).rev() {
            if let Err(error) = revoke_acl(&path, &self.sid) {
                failures.push(format!("{}: {error}", path.display()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::Failed(failures.join("; ")))
        }
    }
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
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
            if !self.sid.is_null() {
                LocalFree(self.sid);
            }
            if !self.network_sid.is_null() {
                LocalFree(self.network_sid);
            }
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
