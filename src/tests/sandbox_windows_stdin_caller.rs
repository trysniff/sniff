use std::io::Write;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Command;
use std::time::Duration;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, SetStdHandle};
use windows_sys::Win32::System::Pipes::CreatePipe;

const BROKER_ENV: &str = "SNIFF_INPUT_BROKER_TEST";

pub(super) fn run_broker(test: &str) -> bool {
    if let Some(selected) = std::env::var_os(BROKER_ENV) {
        assert_eq!(
            selected, test,
            "input broker must run only its selected test"
        );
        return false;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            test,
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(BROKER_ENV, test)
        .env_remove(super::CHILD_ENV);
    let output = crate::bounded_process::run(&mut command, Duration::from_secs(120))
        .expect("launch the trusted input broker fixture");
    assert!(
        !output.timed_out && output.status.success(),
        "input broker failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "input broker must execute exactly one test"
    );
    true
}

pub(super) struct CallerInput {
    original: HANDLE,
    _read: OwnedHandle,
    _writer: std::fs::File,
}

impl CallerInput {
    pub(super) fn open() -> Self {
        assert!(std::env::var_os(BROKER_ENV).is_some());
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) },
            0
        );
        let read = unsafe { OwnedHandle::from_raw_handle(read) };
        let mut writer = unsafe { std::fs::File::from_raw_handle(write) };
        writer
            .write_all(b"caller-input-must-not-reach-worker\n")
            .unwrap();
        let original = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        assert_ne!(
            unsafe { SetStdHandle(STD_INPUT_HANDLE, read.as_raw_handle()) },
            0
        );
        Self {
            original,
            _read: read,
            _writer: writer,
        }
    }
}

impl Drop for CallerInput {
    fn drop(&mut self) {
        // Standard-handle mutation is confined to the trusted, one-test broker process.
        assert_ne!(unsafe { SetStdHandle(STD_INPUT_HANDLE, self.original) }, 0);
    }
}
