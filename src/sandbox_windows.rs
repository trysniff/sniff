use super::{
    CapturedOutput, SandboxCommand, SandboxError, SandboxOutput, read_limited, read_limited_hashed,
    read_limited_hashed_with_observer,
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
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
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

#[path = "sandbox_windows_drive.rs"]
mod drive;
use drive::SandboxDriveMapping;
#[path = "sandbox_windows_recovery.rs"]
mod recovery;
use recovery::RecoveryLedger;
#[path = "sandbox_windows_global_access.rs"]
mod global_access;
use global_access::{all_application_packages_access, all_application_packages_tree_access};

const INTERNET_CLIENT_SID: &str = "S-1-15-3-1";
const PERSISTENT_READ_CAPABILITY: &str = "trysniff.semantic-indexer-read.v1";
const SE_GROUP_ENABLED: u32 = 0x00000004;
const FILE_GENERIC_READ_ACCESS: u32 = 0x0012_0089;
const FILE_GENERIC_EXECUTE_ACCESS: u32 = 0x0012_00A0;
const DIRECTORY_TRAVERSE_ACCESS: u32 = 0x0012_00A0;
const PROCESS_CREATION_CHILD_PROCESS_OVERRIDE: u32 = 0x02;
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
    let system_program = is_system_program(&program)?;
    let mut effective_spec = spec.clone();
    effective_spec.program = program.to_string_lossy().into_owned();
    if !system_program {
        effective_spec.read_only_paths.push(program.clone());
    }
    effective_spec
        .read_only_paths
        .extend(effective_spec.executable_paths.iter().cloned());
    extend_executable_mapping_roots(&mut effective_spec)?;
    let profile_name = unique_profile_name();
    let recovery_ledger = RecoveryLedger::recover_and_begin(&profile_name)?;
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
    let mut profile_guard = ProfileGuard {
        name: profile_name_w,
        sid: app_container_sid,
        network_sid,
        active: true,
    };
    trace_phase(started, "AppContainer profile created");

    let app_container_sid_text = sid_string(profile_guard.sid)?;
    recovery_ledger.record_sid(&app_container_sid_text)?;
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
        &effective_spec.writable_paths,
        &effective_spec.persistent_read_only_paths,
        &app_container_sid_text,
        &recovery_ledger,
    )?;
    trace_phase(started, "filesystem access granted");
    // AppContainer file-read permission is not enough to launch an executable.
    if !system_program
        && !globally_accessible_persistent_executable(
            &program,
            &effective_spec.persistent_read_only_paths,
        )?
    {
        acl_guard.grant_once(&program, "RX", false, &recovery_ledger)?;
    }
    for path in &effective_spec.executable_paths {
        acl_guard.grant_external_executable(
            path,
            &effective_spec.persistent_read_only_paths,
            &recovery_ledger,
        )?;
    }
    trace_phase(started, "program execution granted");
    let canonical_root = normalize_windows_path(
        std::fs::canonicalize(&effective_spec.root).map_err(|error| {
            SandboxError::Invalid(format!("resolve Windows sandbox root failed: {error}"))
        })?,
    );
    let mut process_spec = effective_spec.clone();
    let mut drive_mappings = Vec::new();
    for path in &effective_spec.windows_virtualized_paths {
        let canonical_path =
            normalize_windows_path(std::fs::canonicalize(path).map_err(|error| {
                SandboxError::Invalid(format!(
                    "resolve Windows virtualized path {} failed: {error}",
                    path.display()
                ))
            })?);
        let mapping = SandboxDriveMapping::create(&canonical_path, |drive, root| {
            recovery_ledger.record_mapping(drive, root)
        })?;
        mapping.rewrite_process_spec(&mut process_spec, path, canonical_path == canonical_root);
        drive_mappings.push(mapping);
    }
    if !drive_mappings.is_empty() {
        trace_phase(started, "private drive roots mapped");
    }
    let result = run_process(&process_spec, profile_guard.sid, &mut capabilities);
    trace_phase(started, "sandbox process returned");
    let mut mapping_cleanup_failures = Vec::new();
    for mapping in drive_mappings.iter_mut().rev() {
        if let Err(error) = mapping.remove() {
            mapping_cleanup_failures.push(error.to_string());
        }
    }
    let mapping_cleanup = if mapping_cleanup_failures.is_empty() {
        Ok(())
    } else {
        Err(SandboxError::Failed(mapping_cleanup_failures.join("; ")))
    };
    if !drive_mappings.is_empty() {
        trace_phase(started, "private drive roots unmapped");
    }
    let mappings_clean = mapping_cleanup.is_ok();
    let result = match (result, mapping_cleanup) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(SandboxError::Failed(format!(
            "{error}; additionally, Windows sandbox drive cleanup failed: {cleanup_error}"
        ))),
    };
    let revoke = acl_guard.revoke();
    let acls_clean = revoke.is_ok();
    trace_phase(started, "filesystem access revoked");
    let result = match (result, revoke) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(SandboxError::Failed(format!(
            "{error}; additionally, Windows sandbox ACL cleanup failed: {cleanup_error}"
        ))),
    };
    let profile_cleanup = profile_guard.remove();
    let profile_clean = profile_cleanup.is_ok();
    let result = match (result, profile_cleanup) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(SandboxError::Failed(format!(
            "{error}; additionally, Windows sandbox profile cleanup failed: {cleanup_error}"
        ))),
    };
    if mappings_clean && acls_clean && profile_clean {
        recovery_ledger.clear()?;
    }
    result
}

fn extend_executable_mapping_roots(spec: &mut SandboxCommand) -> Result<(), SandboxError> {
    let executable_paths = spec.executable_paths.clone();
    let mut canonical_roots = spec
        .windows_virtualized_paths
        .iter()
        .map(|root| std::fs::canonicalize(root).map(normalize_windows_path))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            SandboxError::Invalid(format!(
                "Windows virtualized path could not be canonicalized: {error}"
            ))
        })?;
    for path in executable_paths {
        let canonical_path =
            normalize_windows_path(std::fs::canonicalize(&path).map_err(|error| {
                SandboxError::Invalid(format!(
                    "sandbox executable path could not be canonicalized: {} ({error})",
                    path.display()
                ))
            })?);
        let mapping_root = if canonical_path.is_dir() {
            canonical_path
        } else {
            canonical_path
                .parent()
                .ok_or_else(|| {
                    SandboxError::Invalid(format!(
                        "sandbox executable path has no containing directory: {}",
                        canonical_path.display()
                    ))
                })?
                .to_path_buf()
        };
        let covered = canonical_roots
            .iter()
            .any(|root| mapping_root.starts_with(root));
        if !covered {
            canonical_roots.push(mapping_root.clone());
            spec.windows_virtualized_paths.push(mapping_root);
        }
    }
    Ok(())
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

fn is_system_program(program: &Path) -> Result<bool, SandboxError> {
    let root = std::env::var_os("SystemRoot").ok_or_else(|| {
        SandboxError::Unavailable("Windows sandbox requires SystemRoot".to_string())
    })?;
    let system32 = normalize_windows_path(
        std::fs::canonicalize(PathBuf::from(root).join("System32")).map_err(|error| {
            SandboxError::Unavailable(format!("resolve Windows System32 failed: {error}"))
        })?,
    );
    Ok(program.starts_with(system32))
}

fn normalize_windows_path(path: std::path::PathBuf) -> std::path::PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{}", rest));
    }
    text.strip_prefix(r"\\?\")
        .map_or(path, std::path::PathBuf::from)
}

fn native_acl_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text.starts_with(r"\\?\") {
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix(r"\\") {
        return PathBuf::from(format!(r"\\?\UNC\{rest}"));
    }
    if path.is_absolute() {
        return PathBuf::from(format!(r"\\?\{text}"));
    }
    path.to_path_buf()
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
    if let Err(error) = configure_job(job, spec.memory_limit, spec.process_limit) {
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
        stdout: stdout.text,
        stderr: stderr.text,
        stdout_sha256: stdout.sha256,
        stderr_sha256: stderr.sha256,
        timed_out,
    })
}

fn terminate_process_and_close(process: HANDLE) {
    unsafe {
        TerminateProcess(process, 1);
        CloseHandle(process);
    }
}

fn configure_job(job: HANDLE, memory_limit: u64, process_limit: u32) -> Result<(), SandboxError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = process_limit;
    limits.ProcessMemoryLimit = usize::try_from(memory_limit).map_err(|_| {
        SandboxError::Invalid("Windows sandbox memory limit exceeds usize".to_string())
    })?;
    limits.JobMemoryLimit = limits.ProcessMemoryLimit;
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
) -> thread::JoinHandle<std::io::Result<CapturedOutput>> {
    let handle_value = handle as isize;
    let debug = std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some();
    thread::spawn(move || unsafe {
        let file = std::fs::File::from_raw_handle(handle_value as _);
        if debug {
            let mut traced = 0usize;
            read_limited_hashed_with_observer(file, limit, |chunk| {
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
            read_limited_hashed(file, limit)
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
    grant_acl_with_inheritance(path, sid, permission, path.is_dir())
}

fn grant_acl_with_inheritance(
    path: &Path,
    sid: &str,
    permission: &str,
    inherit: bool,
) -> Result<(), SandboxError> {
    let path = normalize_windows_path(path.to_path_buf());
    let inheritance = if inherit { "(OI)(CI)" } else { "" };
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
        return Err(SandboxError::Unavailable(format!(
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
    if all_application_packages_tree_access(path, FILE_GENERIC_READ_ACCESS)? {
        return Ok(());
    }
    grant_acl(path, capability_sid_text, "R")
}

fn persistent_read_acl_exists(
    path: &Path,
    capability_sid: *mut c_void,
) -> Result<bool, SandboxError> {
    let path = normalize_windows_path(path.to_path_buf());
    let native_path = native_acl_path(&path);
    let path_w = wide_null(&native_path.to_string_lossy());
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

    let native_path = native_acl_path(path);
    let path_w = wide_null(&native_path.to_string_lossy());
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

    if access_mode == REVOKE_ACCESS {
        let mut entries = std::ptr::null_mut();
        let mut entry_count = 0_u32;
        let status = unsafe { GetExplicitEntriesFromAclW(old_acl, &mut entry_count, &mut entries) };
        if status != 0 {
            unsafe {
                if !descriptor.is_null() {
                    LocalFree(descriptor);
                }
                LocalFree(sid_ptr);
            }
            return Err(format!(
                "inspect DACL before revoke failed with Windows error {status}"
            ));
        }
        let present = if entries.is_null() {
            false
        } else {
            unsafe { std::slice::from_raw_parts(entries, entry_count as usize) }
                .iter()
                .any(|entry| {
                    let trustee_sid = entry.Trustee.ptstrName as *mut c_void;
                    entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                        && !trustee_sid.is_null()
                        && unsafe { EqualSid(trustee_sid, sid_ptr) != 0 }
                })
        };
        unsafe {
            if !entries.is_null() {
                LocalFree(entries as _);
            }
        }
        if !present {
            unsafe {
                if !descriptor.is_null() {
                    LocalFree(descriptor);
                }
                LocalFree(sid_ptr);
            }
            return Ok(());
        }
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
        writable_paths: &[std::path::PathBuf],
        persistent_read_only_paths: &[PathBuf],
        sid: &str,
        recovery: &RecoveryLedger,
    ) -> Result<Self, SandboxError> {
        let paths = explicit_acl_paths(root, read_only_paths, writable_paths);
        let mut grants: Vec<AclGrant> = Vec::with_capacity(paths.len());
        for (path, permission) in paths {
            if permission == "R"
                && globally_accessible_persistent_read(&path, persistent_read_only_paths)?
            {
                continue;
            }
            // Directory grants use inheritance rather than recursively
            // walking every dependency file. Cleanup removes the parent ACE;
            // inherited child access then disappears with it.
            recovery.record_acl(&path)?;
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

    fn grant_external_executable(
        &mut self,
        path: &Path,
        persistent_read_only_paths: &[PathBuf],
        recovery: &RecoveryLedger,
    ) -> Result<(), SandboxError> {
        let path = normalize_windows_path(std::fs::canonicalize(path).map_err(|error| {
            SandboxError::Invalid(format!(
                "sandbox executable path could not be canonicalized: {} ({error})",
                path.display()
            ))
        })?);
        if globally_accessible_persistent_executable(&path, persistent_read_only_paths)? {
            return Ok(());
        }
        if path.is_dir() {
            return self.grant_once(&path, "RX", true, recovery);
        }
        let parent = path.parent().ok_or_else(|| {
            SandboxError::Invalid(format!(
                "sandbox executable path has no containing directory: {}",
                path.display()
            ))
        })?;

        // The process uses a private drive rooted here, so no host ancestors
        // need temporary ACEs. Generic execute on a directory includes
        // traversal and attributes, but not listing or sibling-file reads.
        self.grant_traverse_once(parent, recovery)?;
        self.grant_once(&path, "RX", false, recovery)
    }

    fn grant_traverse_once(
        &mut self,
        path: &Path,
        recovery: &RecoveryLedger,
    ) -> Result<(), SandboxError> {
        let path = normalize_windows_path(path.to_path_buf());
        if self.grants.iter().any(|grant| grant.path == path) {
            return Ok(());
        }
        recovery.record_acl(&path)?;
        update_acl_entry(&path, &self.sid, DIRECTORY_TRAVERSE_ACCESS, GRANT_ACCESS).map_err(
            |error| {
                SandboxError::Failed(format!(
                    "grant Windows AppContainer traversal to {} failed: {error}",
                    path.display()
                ))
            },
        )?;
        self.grants.push(AclGrant { path });
        Ok(())
    }

    fn grant_once(
        &mut self,
        path: &Path,
        permission: &'static str,
        inherit: bool,
        recovery: &RecoveryLedger,
    ) -> Result<(), SandboxError> {
        let path = normalize_windows_path(path.to_path_buf());
        if self.grants.iter().any(|grant| grant.path == path) {
            grant_acl_with_inheritance(&path, &self.sid, permission, inherit)?;
            return Ok(());
        }
        recovery.record_acl(&path)?;
        grant_acl_with_inheritance(&path, &self.sid, permission, inherit)?;
        self.grants.push(AclGrant { path });
        Ok(())
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

fn globally_accessible_persistent_executable(
    executable: &Path,
    persistent_read_only_paths: &[PathBuf],
) -> Result<bool, SandboxError> {
    if !covered_by_persistent_path(executable, persistent_read_only_paths)? {
        return Ok(false);
    }
    if executable.is_dir() {
        return all_application_packages_tree_access(
            executable,
            FILE_GENERIC_READ_ACCESS | FILE_GENERIC_EXECUTE_ACCESS,
        );
    }
    let Some(parent) = executable.parent() else {
        return Ok(false);
    };
    Ok(
        all_application_packages_access(parent, DIRECTORY_TRAVERSE_ACCESS)?
            && all_application_packages_access(
                executable,
                FILE_GENERIC_READ_ACCESS | FILE_GENERIC_EXECUTE_ACCESS,
            )?,
    )
}

fn globally_accessible_persistent_read(
    path: &Path,
    persistent_read_only_paths: &[PathBuf],
) -> Result<bool, SandboxError> {
    if !covered_by_persistent_path(path, persistent_read_only_paths)? {
        return Ok(false);
    }
    if path.is_dir() {
        all_application_packages_tree_access(path, FILE_GENERIC_READ_ACCESS)
    } else {
        all_application_packages_access(path, FILE_GENERIC_READ_ACCESS)
    }
}

fn covered_by_persistent_path(
    path: &Path,
    persistent_read_only_paths: &[PathBuf],
) -> Result<bool, SandboxError> {
    for root in persistent_read_only_paths {
        let root = normalize_windows_path(std::fs::canonicalize(root).map_err(|error| {
            SandboxError::Invalid(format!(
                "persistent sandbox path could not be canonicalized: {} ({error})",
                root.display()
            ))
        })?);
        if path.starts_with(root) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn explicit_acl_paths(
    root: &Path,
    read_only_paths: &[std::path::PathBuf],
    writable_paths: &[std::path::PathBuf],
) -> Vec<(PathBuf, &'static str)> {
    let mut paths = vec![(root.to_path_buf(), "M")];
    for path in writable_paths {
        if !paths.iter().any(|(existing, _)| existing == path) {
            paths.push((path.clone(), "M"));
        }
    }
    for path in read_only_paths {
        if !paths.iter().any(|(existing, _)| existing == path) {
            paths.push((path.clone(), "R"));
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
    active: bool,
}

impl ProfileGuard {
    fn remove(&mut self) -> Result<(), SandboxError> {
        let started = Instant::now();
        let deleted = if self.active {
            unsafe { DeleteAppContainerProfile(self.name.as_ptr()) }
        } else {
            0
        };
        unsafe {
            if !self.sid.is_null() {
                LocalFree(self.sid);
                self.sid = std::ptr::null_mut();
            }
            if !self.network_sid.is_null() {
                LocalFree(self.network_sid);
                self.network_sid = std::ptr::null_mut();
            }
        }
        if deleted < 0 {
            return Err(SandboxError::Failed(format!(
                "delete Windows AppContainer profile failed with HRESULT 0x{:08x}",
                deleted as u32
            )));
        }
        self.active = false;
        if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
            eprintln!(
                "[sniff] Windows sandbox AppContainer profile deleted: {:.3}s",
                started.elapsed().as_secs_f64()
            );
        }
        Ok(())
    }
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        let _ = self.remove();
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
        ensure_persistent_read_acl, explicit_acl_paths, extend_executable_mapping_roots,
        native_acl_path, persistent_read_acl_exists, revoke_acl, sid_string, update_acl_entry,
    };
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Security::EqualSid;

    #[test]
    fn appcontainer_process_starts_suspended_before_job_assignment() {
        assert_ne!(SANDBOX_PROCESS_CREATION_FLAGS & CREATE_SUSPENDED, 0);
    }

    #[test]
    fn revoking_an_absent_sid_does_not_rewrite_a_protected_dacl() {
        let capability = CapabilitySid::derive(super::PERSISTENT_READ_CAPABILITY).unwrap();
        let sid = sid_string(capability.sid).unwrap();
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");

        revoke_acl(&cmd, &sid).unwrap();
    }

    #[test]
    fn native_acl_updates_support_paths_longer_than_max_path() {
        let capability = CapabilitySid::derive(super::PERSISTENT_READ_CAPABILITY).unwrap();
        let sid = sid_string(capability.sid).unwrap();
        let mut root = std::env::temp_dir().join(format!(
            "sniff-long-acl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        while root.as_os_str().len() <= 280 {
            root.push("long-path-segment-0123456789");
        }
        std::fs::create_dir_all(&root).unwrap();
        let canonical = std::fs::canonicalize(&root).unwrap();
        let normalized = super::normalize_windows_path(canonical);

        assert!(normalized.as_os_str().len() > 260);
        assert!(
            native_acl_path(&normalized)
                .to_string_lossy()
                .starts_with(r"\\?\")
        );
        update_acl_entry(
            &normalized,
            &sid,
            super::DIRECTORY_TRAVERSE_ACCESS,
            super::GRANT_ACCESS,
        )
        .unwrap();
        revoke_acl(&normalized, &sid).unwrap();

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repository_acl_targets_never_include_ancestors() {
        let root = Path::new(r"C:\work\repository");
        let tool = PathBuf::from(r"C:\tools\node.exe");
        let cache = PathBuf::from(r"C:\work\repository\.sniff-indexer-cache");

        let paths = explicit_acl_paths(
            root,
            std::slice::from_ref(&tool),
            std::slice::from_ref(&cache),
        );

        assert_eq!(
            paths,
            [(root.to_path_buf(), "M"), (cache, "M"), (tool, "R")]
        );
        assert!(!paths.iter().any(|(path, _)| path == Path::new(r"C:\")));
        assert!(!paths.iter().any(|(path, _)| path == Path::new(r"C:\work")));
    }

    #[test]
    fn canonical_toolchain_root_prevents_a_narrower_executable_mapping() {
        let directory = tempfile::tempdir().unwrap();
        let real_root = directory.path().join("jdk-real");
        let alias_root = directory.path().join("jdk-alias");
        let bin = real_root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("java.exe"), b"fixture").unwrap();
        std::os::windows::fs::symlink_dir(&real_root, &alias_root).unwrap();
        let mut spec = crate::sandbox::SandboxCommand {
            root: directory.path().to_path_buf(),
            workdir: PathBuf::from("."),
            program: "cmd.exe".to_string(),
            args: Vec::new(),
            read_only_paths: Vec::new(),
            writable_paths: Vec::new(),
            persistent_read_only_paths: Vec::new(),
            executable_paths: Vec::new(),
            windows_virtualized_paths: Vec::new(),
            env: Vec::new(),
            allow_network: false,
            timeout: std::time::Duration::from_secs(1),
            output_limit: 1024,
            memory_limit: 1024,
            process_limit: 1,
        };
        spec.executable_paths = vec![alias_root.join("bin").join("java.exe")];
        spec.windows_virtualized_paths = vec![real_root.clone()];

        extend_executable_mapping_roots(&mut spec).unwrap();

        assert_eq!(spec.windows_virtualized_paths, vec![real_root]);
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
