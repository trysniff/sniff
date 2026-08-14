use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 1024 * 1024;

pub(crate) struct BoundedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) timed_out: bool,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
}

pub(crate) fn run(command: &mut Command, timeout: Duration) -> io::Result<BoundedOutput> {
    run_with_output_limit(command, timeout, OUTPUT_LIMIT)
}

pub(crate) fn run_with_output_limit(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
) -> io::Result<BoundedOutput> {
    configure_process_group(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    #[cfg(windows)]
    let job = WindowsJob::attach(&mut child)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("bounded child stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("bounded child stderr was not captured"))?;
    let stdout_reader = thread::spawn(move || read_limited(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_limited(stderr, output_limit));
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait()? {
            Some(status) => break (status, false),
            None if started.elapsed() >= timeout => {
                #[cfg(windows)]
                job.terminate()?;
                #[cfg(not(windows))]
                terminate_tree(&mut child)?;
                break (child.wait()?, true);
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    };
    #[cfg(windows)]
    drop(job);
    #[cfg(unix)]
    if !timed_out {
        // A normally exiting parent can leave helpers behind. The timeout path
        // already killed the process group before waiting for the parent.
        terminate_process_group(child.id())?;
    }
    let (stdout, stdout_truncated) = join_reader(stdout_reader, "stdout")?;
    let (stderr, stderr_truncated) = join_reader(stderr_reader, "stderr")?;
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
        timed_out,
        stdout_truncated,
        stderr_truncated,
    })
}

fn read_limited(mut reader: impl Read, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok((retained, truncated));
        }
        if retained.len() < limit {
            let keep = count.min(limit - retained.len());
            retained.extend_from_slice(&buffer[..keep]);
            truncated |= keep < count;
        } else {
            truncated = true;
        }
    }
}

fn join_reader(
    reader: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
    label: &str,
) -> io::Result<(Vec<u8>, bool)> {
    reader
        .join()
        .map_err(|_| io::Error::other(format!("bounded child {label} reader panicked")))?
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    // A dedicated group lets a timeout terminate Git helpers and transports too.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

#[cfg(windows)]
fn configure_process_group(command: &mut Command) {
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(not(any(unix, windows)))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_tree(child: &mut Child) -> io::Result<()> {
    terminate_process_group(child.id())
}

#[cfg(unix)]
fn terminate_process_group(process_group: u32) -> io::Result<()> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| io::Error::other("bounded child process ID overflowed"))?;
    if unsafe { libc::killpg(process_group, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(windows)]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl WindowsJob {
    fn attach(child: &mut Child) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            let _ = child.kill();
            return Err(io::Error::last_os_error());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        let assigned = configured != 0
            && unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as _) } != 0;
        if !assigned {
            let error = io::Error::last_os_error();
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            let _ = child.kill();
            return Err(error);
        }
        Ok(Self { handle })
    }

    fn terminate(&self) -> io::Result<()> {
        if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, 1) }
            == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(not(any(unix, windows)))]
fn terminate_tree(child: &mut Child) -> io::Result<()> {
    child.kill()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_output_limit_reports_truncation() {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoProfile",
                "-Command",
                "[Console]::Out.Write('0123456789')",
            ]);
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "printf 0123456789"]);
            command
        };

        let output = run_with_output_limit(&mut command, Duration::from_secs(5), 4).unwrap();

        assert_eq!(output.stdout, b"0123");
        assert!(output.stdout_truncated);
        assert!(!output.stderr_truncated);
    }

    #[test]
    fn deadline_terminates_the_complete_child_tree() {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoProfile",
                "-Command",
                "$p=Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 30' -PassThru; [Console]::Out.WriteLine($p.Id); Start-Sleep -Seconds 30",
            ]);
            command
        };
        #[cfg(unix)]
        let (mut command, survivor_marker) = {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("descendant-survived");
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg("(sleep 3; printf survived > \"$1\") & echo $!; wait")
                .arg("bounded-process-test")
                .arg(&marker);
            (command, (directory, marker))
        };

        let output = run(&mut command, Duration::from_secs(2)).unwrap();
        assert!(output.timed_out);
        let descendant = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        #[cfg(windows)]
        {
            let status = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "if(Get-Process -Id {descendant} -ErrorAction SilentlyContinue){{exit 1}}"
                    ),
                ])
                .status()
                .unwrap();
            assert!(status.success());
        }
        #[cfg(unix)]
        {
            let _ = descendant;
            thread::sleep(Duration::from_millis(1_200));
            assert!(!survivor_marker.1.exists());
        }
    }
}
