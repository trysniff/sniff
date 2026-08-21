use super::{SandboxError, free_sid, last_error, normalize_windows_path, wide_null};
use std::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

const ALL_APPLICATION_PACKAGES_SID: &str = "S-1-15-2-1";
const GLOBAL_ACCESS_TREE_LIMIT: usize = 100_000;

pub(super) fn all_application_packages_tree_access(
    root: &Path,
    required: u32,
) -> Result<bool, SandboxError> {
    let sid = LocalSid::from_text(ALL_APPLICATION_PACKAGES_SID)?;
    let mut pending = vec![root.to_path_buf()];
    let mut inspected = 0usize;
    while let Some(path) = pending.pop() {
        inspected = inspected.saturating_add(1);
        if inspected > GLOBAL_ACCESS_TREE_LIMIT {
            return Ok(false);
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            SandboxError::Failed(format!(
                "inspect globally accessible Windows path {} failed: {error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !effective_access_for_sid(&path, sid.0, required)? {
            return Ok(false);
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).map_err(|error| {
                SandboxError::Failed(format!(
                    "enumerate globally accessible Windows directory {} failed: {error}",
                    path.display()
                ))
            })? {
                pending.push(
                    entry
                        .map_err(|error| {
                            SandboxError::Failed(format!(
                                "enumerate globally accessible Windows directory {} failed: {error}",
                                path.display()
                            ))
                        })?
                        .path(),
                );
            }
        }
    }
    Ok(true)
}

pub(super) fn all_application_packages_access(
    path: &Path,
    required: u32,
) -> Result<bool, SandboxError> {
    let sid = LocalSid::from_text(ALL_APPLICATION_PACKAGES_SID)?;
    effective_access_for_sid(path, sid.0, required)
}

fn effective_access_for_sid(
    path: &Path,
    sid: *mut c_void,
    required: u32,
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
            "read Windows DACL for {} failed with Windows error {get_status}",
            path.display()
        )));
    }
    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
        ptstrName: sid as _,
        ..Default::default()
    };
    let mut rights = 0u32;
    let status = unsafe { GetEffectiveRightsFromAclW(acl, &trustee, &mut rights) };
    unsafe {
        if !descriptor.is_null() {
            LocalFree(descriptor);
        }
    }
    if status != 0 {
        return Err(SandboxError::Failed(format!(
            "resolve Windows effective rights for {} failed with Windows error {status}",
            path.display()
        )));
    }
    Ok(rights & required == required)
}

struct LocalSid(*mut c_void);

impl LocalSid {
    fn from_text(value: &str) -> Result<Self, SandboxError> {
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide_null(value).as_ptr(), &mut sid) } == 0 {
            return Err(last_error("resolve Windows well-known SID"));
        }
        Ok(Self(sid))
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        free_sid(self.0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn globally_accessible_runtime_tree_needs_no_redundant_appcontainer_grant() {
        let root = std::env::temp_dir().join(format!(
            "sniff-global-app-package-access-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/runtime.exe"), b"runtime").unwrap();
        super::super::grant_acl(&root, super::ALL_APPLICATION_PACKAGES_SID, "RX").unwrap();

        assert!(
            super::all_application_packages_tree_access(
                &root,
                super::super::FILE_GENERIC_READ_ACCESS | super::super::FILE_GENERIC_EXECUTE_ACCESS,
            )
            .unwrap()
        );

        std::fs::remove_dir_all(root).unwrap();
    }
}
