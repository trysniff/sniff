use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, DENY_ACCESS, GRANT_ACCESS, GetExplicitEntriesFromAclW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// Includes generic write/all, maximum-allowed and every file/security mutation right.
const MUTATION_RIGHTS: u32 = 0x520d_0156;

pub(super) fn lock_base(path: &Path, create: bool) -> Result<Vec<File>, String> {
    let mut paths = path.ancestors().collect::<Vec<_>>();
    paths.reverse();
    let mut held = Vec::new();
    for path in paths {
        if create && !path.try_exists().map_err(|error| error.to_string())? {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("failed to create Go cache ancestor: {error}")),
            }
        }
        // Hold ancestors without delete sharing: even a writable shared parent
        // cannot rename the verified namespace out from under a planned command.
        held.push(open_plain(path, true, FILE_SHARE_READ)?);
    }
    Ok(held)
}

pub(super) fn create_namespace(path: &Path) -> Result<(), String> {
    let user = CurrentUser::read()?;
    let descriptor = descriptor(&format!(
        "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        user.text()?,
        user.text()?
    ))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!(
                "failed to create protected Go adapter namespace: {error}"
            ));
        }
    }
    // Existing namespaces are validated, never adopted by rewriting their ACL.
    Ok(())
}

pub(super) fn hold_trusted(path: &Path, directory: bool, protected: bool) -> Result<File, String> {
    // Protected cache directories need write sharing for owned atomic publication.
    // Unlike shared ancestors, their DACL must reject every untrusted writer.
    let file = open_plain(
        path,
        directory,
        FILE_SHARE_READ | if directory { FILE_SHARE_WRITE } else { 0 },
    )?;
    let mut owner = std::ptr::null_mut();
    let mut acl = std::ptr::null_mut();
    let mut raw_descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut raw_descriptor,
        )
    };
    let descriptor = LocalAllocation(raw_descriptor);
    if status != 0 {
        return Err(format!(
            "failed to inspect Go adapter ownership/DACL: Windows error {status}"
        ));
    }
    let user = CurrentUser::read()?;
    let system = sid("S-1-5-18")?;
    let administrators = sid("S-1-5-32-544")?;
    let trusted = |principal| {
        [user.sid(), system.0, administrators.0]
            .iter()
            .any(|sid| unsafe { EqualSid(principal, *sid) } != 0)
    };
    if owner.is_null()
        || !trusted(owner)
        || acl.is_null()
        || (protected && unsafe { EqualSid(owner, user.sid()) } == 0)
    {
        return Err("Go adapter cache must have a trusted owner and non-null DACL; namespace ownership must match the current user".to_string());
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
        || (protected && control & SE_DACL_PROTECTED == 0)
    {
        return Err("Go adapter namespace must have a protected DACL".to_string());
    }
    let mut count = 0;
    let mut entries = std::ptr::null_mut();
    let status = unsafe { GetExplicitEntriesFromAclW(acl, &mut count, &mut entries) };
    let _entries = LocalAllocation(entries.cast());
    if status != 0 || count > 4096 || (count > 0 && entries.is_null()) {
        return Err("Go adapter DACL cannot be inspected within its entry bound".to_string());
    }
    for index in 0..count as usize {
        let entry = unsafe { &*entries.add(index) };
        if entry.grfAccessMode == DENY_ACCESS {
            continue;
        }
        if ![GRANT_ACCESS, SET_ACCESS].contains(&entry.grfAccessMode)
            || entry.Trustee.TrusteeForm != TRUSTEE_IS_SID
            || !entry.Trustee.pMultipleTrustee.is_null()
            || entry.Trustee.ptstrName.is_null()
        {
            return Err("Go adapter DACL contains an unsupported trustee/access entry".to_string());
        }
        let trustee = entry.Trustee.ptstrName.cast();
        if !trusted(trustee) && entry.grfAccessPermissions & MUTATION_RIGHTS != 0 {
            return Err(
                "Go adapter cache grants write/replace authority to another principal".to_string(),
            );
        }
    }
    Ok(file)
}

fn open_plain(path: &Path, directory: bool, sharing: u32) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(sharing)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| format!("failed to lock Go adapter path {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.file_attributes() & 0x400 != 0
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err("Go adapter lease requires plain files/directories".to_string());
    }
    Ok(file)
}

struct CurrentUser(Vec<usize>);

impl CurrentUser {
    fn read() -> Result<Self, String> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!(
                "failed to read Go adapter producer token: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut size = 0;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size) };
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let ok = size >= std::mem::size_of::<TOKEN_USER>() as u32
            && unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut size,
                )
            } != 0;
        let error = std::io::Error::last_os_error();
        unsafe { CloseHandle(token) };
        if !ok {
            return Err(format!(
                "failed to read Go adapter producer identity: {error}"
            ));
        }
        Ok(Self(buffer))
    }

    fn sid(&self) -> *mut c_void {
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn text(&self) -> Result<String, String> {
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
            return Err("failed to format Go adapter producer identity".to_string());
        }
        let _allocation = LocalAllocation(text.cast());
        let mut units = Vec::new();
        for index in 0..256 {
            let unit = unsafe { *text.add(index) };
            if unit == 0 {
                return String::from_utf16(&units).map_err(|error| error.to_string());
            }
            units.push(unit);
        }
        Err("Go adapter producer SID exceeds its bound".to_string())
    }
}

fn descriptor(sddl: &str) -> Result<LocalAllocation, String> {
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(std::ffi::OsStr::new(sddl)).as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!(
            "failed to prepare Go adapter DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(LocalAllocation(descriptor))
}

fn sid(text: &str) -> Result<LocalAllocation, String> {
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide(std::ffi::OsStr::new(text)).as_ptr(), &mut sid) } == 0 {
        return Err("failed to resolve trusted Go adapter principal".to_string());
    }
    Ok(LocalAllocation(sid))
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    text.encode_wide().chain(Some(0)).collect()
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
pub(super) fn make_shared_writable_for_test(path: &Path) {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let user = CurrentUser::read().unwrap().text().unwrap();
    let descriptor = descriptor(&format!("D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;AU)")).unwrap();
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) },
        0
    );
    assert_eq!(
        unsafe {
            SetNamedSecurityInfoW(
                wide(path.as_os_str()).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        },
        0
    );
}
