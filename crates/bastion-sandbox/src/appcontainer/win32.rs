//! The Win32 calls of the AppContainer backend — the only `unsafe` code in
//! this crate (the crate denies `unsafe_code`; this module alone allows it).
//!
//! Each function wraps one step in a safe signature: owned values free
//! themselves ([`Sid`], [`Job`], [`Child`]), strings are converted to
//! NUL-terminated UTF-16 here, and every buffer handed to Windows outlives
//! the call that reads it. Failures come back as the OS error.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    LocalFree, SetHandleInformation, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
    NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, FreeSid, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SE_GROUP_ENABLED,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ReleaseMutex, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use super::rights::map_generic;

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

fn wide_str(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// A SID Windows allocated, freed the way its allocator requires.
pub(super) struct Sid {
    ptr: PSID,
    local_alloc: bool,
}

impl Sid {
    /// A well-known or capability SID from its string form.
    pub(super) fn from_string(text: &str) -> Result<Self, String> {
        let text_w = wide_str(text);
        let mut ptr: PSID = null_mut();
        // SAFETY: `text_w` is NUL-terminated; on success `ptr` receives a
        // LocalAlloc'd SID that `Drop` frees with LocalFree.
        let ok = unsafe { ConvertStringSidToSidW(text_w.as_ptr(), &mut ptr) };
        if ok == 0 {
            return Err(format!("SID {text}: {}", io::Error::last_os_error()));
        }
        Ok(Self {
            ptr,
            local_alloc: true,
        })
    }

    /// The SID of the AppContainer `name`, creating its profile when it does
    /// not exist yet.
    pub(super) fn app_container(name: &str) -> Result<Self, String> {
        let name_w = wide_str(name);
        let mut ptr: PSID = null_mut();
        // SAFETY: all strings are NUL-terminated and outlive the call; no
        // capabilities are passed (count 0 with a null array). On success
        // `ptr` receives a SID that `Drop` frees with FreeSid.
        let created = unsafe {
            CreateAppContainerProfile(
                name_w.as_ptr(),
                name_w.as_ptr(),
                name_w.as_ptr(),
                null(),
                0,
                &mut ptr,
            )
        };
        if created < 0 {
            let already_exists = (0x8007_0000u32 | ERROR_ALREADY_EXISTS) as i32;
            if created != already_exists {
                return Err(format!(
                    "creating AppContainer {name}: {}",
                    io::Error::from_raw_os_error(created)
                ));
            }
            // SAFETY: as above; the SID is FreeSid-allocated as well.
            let derived =
                unsafe { DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut ptr) };
            if derived < 0 {
                return Err(format!(
                    "AppContainer {name}: {}",
                    io::Error::from_raw_os_error(derived)
                ));
            }
        }
        Ok(Self {
            ptr,
            local_alloc: false,
        })
    }

    fn as_ptr(&self) -> PSID {
        self.ptr
    }

    fn equals(&self, other: PSID) -> bool {
        // SAFETY: both are valid SIDs (`other` comes from an ACE or a list
        // Windows returned, and is read only).
        unsafe { EqualSid(self.ptr, other) != 0 }
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from the allocator `local_alloc` names and is
        // freed exactly once.
        unsafe {
            if self.local_alloc {
                LocalFree(self.ptr);
            } else {
                FreeSid(self.ptr);
            }
        }
    }
}

/// A security descriptor returned by `GetNamedSecurityInfoW`.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: LocalAlloc'd by GetNamedSecurityInfoW, freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// The DACL of `path` (null for a NULL DACL) and the descriptor that owns it.
fn dacl(path: &Path) -> io::Result<(*mut ACL, Descriptor)> {
    let path_w = wide(path.as_os_str());
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `path_w` is NUL-terminated; `dacl` points into `descriptor`,
    // which the returned `Descriptor` keeps alive and frees.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(os_error(status));
    }
    Ok((dacl, Descriptor(descriptor)))
}

/// File rights the explicit and inherited allow ACEs of `path` give any of
/// `sids`, minus what deny ACEs for them take away. Inherit-only ACEs do not
/// apply to `path` itself and are ignored. A NULL DACL allows everything.
pub(super) fn allowed_rights(path: &Path, sids: &[&Sid]) -> io::Result<u32> {
    let (acl, _descriptor) = dacl(path)?;
    if acl.is_null() {
        return Ok(u32::MAX);
    }
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    // SAFETY: `acl` is a valid ACL owned by `_descriptor`; `info` is sized
    // for the AclSizeInformation class.
    let ok = unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let (mut allowed, mut denied) = (0u32, 0u32);
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `index` is below the ACE count; `ace` then points at an ACE
        // inside `acl`.
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Allow and deny ACEs share ACCESS_ALLOWED_ACE's layout: header,
        // mask, then the SID starting at `SidStart`.
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: every ACE starts with an ACE_HEADER, and for the two types
        // read below the mask and the SID follow it.
        let (kind, flags) = unsafe { ((*ace).Header.AceType, (*ace).Header.AceFlags) };
        if u32::from(flags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let kind = u32::from(kind);
        if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        // SAFETY: see above; the SID is read in place.
        let (mask, sid) = unsafe { ((*ace).Mask, (&raw mut (*ace).SidStart).cast::<c_void>()) };
        if !sids.iter().any(|s| s.equals(sid)) {
            continue;
        }
        if kind == ACCESS_ALLOWED_ACE_TYPE {
            allowed |= map_generic(mask);
        } else {
            denied |= map_generic(mask);
        }
    }
    Ok(allowed & !denied)
}

/// Adds an allow ACE for `sid` with `mask` to the DACL of `path`, inherited
/// by files and directories below it when `inherit`. Windows propagates the
/// change to the existing children.
pub(super) fn add_allow_ace(path: &Path, sid: &Sid, mask: u32, inherit: bool) -> io::Result<()> {
    let (old, _descriptor) = dacl(path)?;
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: if inherit {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.as_ptr().cast(),
        },
    };
    let mut new: *mut ACL = null_mut();
    // SAFETY: one entry, whose SID outlives the call; `old` belongs to
    // `_descriptor`; `new` is LocalAlloc'd on success and freed below.
    let status = unsafe { SetEntriesInAclW(1, &entry, old, &mut new) };
    if status != ERROR_SUCCESS {
        return Err(os_error(status));
    }
    let path_w = wide(path.as_os_str());
    // SAFETY: `path_w` is NUL-terminated and `new` a valid ACL; only the
    // DACL is written.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new,
            null(),
        )
    };
    // SAFETY: allocated by SetEntriesInAclW above, freed once.
    unsafe { LocalFree(new.cast()) };
    if status != ERROR_SUCCESS {
        return Err(os_error(status));
    }
    Ok(())
}

/// Adds `container` to the machine's loopback exemptions unless it is there.
/// Needs an elevated caller. A named mutex keeps two helpers from rewriting
/// the list at the same time and dropping each other's entry.
pub(super) fn exempt_from_loopback_isolation(container: &Sid) -> io::Result<()> {
    let name = wide_str(r"Local\bastion-sandbox-loopback-exemptions");
    // SAFETY: `name` is NUL-terminated; the handle is owned right away.
    let mutex = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if mutex.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh, valid handle owned by nothing else.
    let mutex = unsafe { OwnedHandle::from_raw_handle(mutex) };
    // SAFETY: valid mutex handle. An abandoned mutex (a helper that died
    // holding it) is acquired as well, which is what we want.
    unsafe { WaitForSingleObject(mutex.as_raw_handle(), INFINITE) };
    let result = exempt_locked(container);
    // SAFETY: this thread owns the mutex.
    unsafe { ReleaseMutex(mutex.as_raw_handle()) };
    result
}

fn exempt_locked(container: &Sid) -> io::Result<()> {
    let mut count = 0u32;
    let mut current: *mut SID_AND_ATTRIBUTES = null_mut();
    // SAFETY: out-parameters only. The returned array is not freed: its
    // allocator is not documented, and the helper makes this call once.
    let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut current) };
    if status != ERROR_SUCCESS {
        return Err(os_error(status));
    }
    let current: &[SID_AND_ATTRIBUTES] = if current.is_null() || count == 0 {
        &[]
    } else {
        // SAFETY: Windows returned `count` entries at `current`.
        unsafe { std::slice::from_raw_parts(current, count as usize) }
    };
    if current.iter().any(|entry| container.equals(entry.Sid)) {
        return Ok(());
    }
    let mut list = current.to_vec();
    list.push(SID_AND_ATTRIBUTES {
        Sid: container.as_ptr(),
        Attributes: 0,
    });
    // SAFETY: `list` holds valid SIDs that outlive the call.
    let status = unsafe { NetworkIsolationSetAppContainerConfig(list.len() as u32, list.as_ptr()) };
    if status != ERROR_SUCCESS {
        return Err(os_error(status));
    }
    Ok(())
}

/// A Job Object that kills its processes when the last handle closes (when
/// the helper exits or is killed) and keeps them away from other processes'
/// windows, the clipboard, global atoms and system settings.
pub(super) struct Job(OwnedHandle);

impl Job {
    pub(super) fn new() -> Result<Self, String> {
        // SAFETY: anonymous job, default security.
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(format!("CreateJobObject: {}", io::Error::last_os_error()));
        }
        // SAFETY: fresh handle owned by nothing else.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        // SAFETY: all-zero is a valid "no limits" value of this plain C
        // struct; the flags are set on top.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        job.set(
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits),
        )?;
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_EXITWINDOWS,
        };
        job.set(
            JobObjectBasicUIRestrictions,
            (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            std::mem::size_of_val(&ui),
        )?;
        Ok(job)
    }

    fn set(&self, class: i32, info: *const c_void, size: usize) -> Result<(), String> {
        // SAFETY: `info` points at a live struct of `size` bytes matching
        // `class` (both callers above).
        let ok =
            unsafe { SetInformationJobObject(self.0.as_raw_handle(), class, info, size as u32) };
        if ok == 0 {
            return Err(format!(
                "SetInformationJobObject: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(super) fn assign(&self, child: &Child) -> Result<(), String> {
        // SAFETY: both handles are valid and owned.
        let ok = unsafe {
            AssignProcessToJobObject(self.0.as_raw_handle(), child.process.as_raw_handle())
        };
        if ok == 0 {
            return Err(format!(
                "AssignProcessToJobObject: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// What [`spawn_suspended`] starts.
pub(super) struct Spawn<'a> {
    pub program: &'a Path,
    /// NUL-terminated; CreateProcessW may write to it.
    pub command_line: Vec<u16>,
    /// A complete Unicode environment block.
    pub environment: &'a [u16],
    pub cwd: Option<&'a Path>,
    pub container: &'a Sid,
    pub capabilities: &'a [Sid],
}

/// A created process and its main thread.
pub(super) struct Child {
    process: OwnedHandle,
    thread: OwnedHandle,
}

/// The helper's standard handles, made inheritable, without duplicates or
/// missing ones.
fn std_handles() -> ([HANDLE; 3], Vec<HANDLE>) {
    let handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
        // SAFETY: GetStdHandle only reads the process parameters.
        .map(|which| unsafe { GetStdHandle(which) });
    let mut inherit = Vec::new();
    for handle in handles {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE || inherit.contains(&handle) {
            continue;
        }
        // SAFETY: a valid handle of this process; only its inherit flag
        // changes.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } != 0 {
            inherit.push(handle);
        }
    }
    (handles, inherit)
}

/// Creates the process suspended, in the AppContainer, inheriting only the
/// helper's standard handles.
pub(super) fn spawn_suspended(spawn: Spawn<'_>) -> Result<Child, String> {
    let Spawn {
        program,
        mut command_line,
        environment,
        cwd,
        container,
        capabilities,
    } = spawn;
    let mut capability_list: Vec<SID_AND_ATTRIBUTES> = capabilities
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_ptr(),
            Attributes: SE_GROUP_ENABLED as u32,
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: container.as_ptr(),
        Capabilities: if capability_list.is_empty() {
            null_mut()
        } else {
            capability_list.as_mut_ptr()
        },
        CapabilityCount: capability_list.len() as u32,
        Reserved: 0,
    };
    let (std, inherit) = std_handles();

    let attribute_count = if inherit.is_empty() { 1 } else { 2 };
    let mut size = 0usize;
    // SAFETY: size query with a null list; failing with
    // ERROR_INSUFFICIENT_BUFFER is the documented outcome.
    unsafe { InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut size) };
    // usize elements keep the list pointer-aligned.
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let list = storage.as_mut_ptr().cast::<c_void>();
    // SAFETY: `storage` holds at least `size` bytes.
    if unsafe { InitializeProcThreadAttributeList(list, attribute_count, 0, &mut size) } == 0 {
        return Err(format!(
            "InitializeProcThreadAttributeList: {}",
            io::Error::last_os_error()
        ));
    }
    let result = (|| {
        // SAFETY: the list was initialized above. `security`,
        // `capability_list` and `inherit` are only referenced by the list and
        // live until CreateProcessW returns.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&security as *const SECURITY_CAPABILITIES).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "security capabilities: {}",
                io::Error::last_os_error()
            ));
        }
        if !inherit.is_empty() {
            // SAFETY: as above.
            let ok = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    inherit.as_ptr().cast(),
                    std::mem::size_of_val(inherit.as_slice()),
                    null_mut(),
                    null(),
                )
            };
            if ok == 0 {
                return Err(format!("handle list: {}", io::Error::last_os_error()));
            }
        }

        // SAFETY: all-zero is valid for this plain C struct; the fields that
        // matter are set below.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = std[0];
        startup.StartupInfo.hStdOutput = std[1];
        startup.StartupInfo.hStdError = std[2];
        startup.lpAttributeList = list;

        let program_w = wide(program.as_os_str());
        let cwd_w = cwd.map(|dir| wide(dir.as_os_str()));
        // SAFETY: plain C struct, filled by CreateProcessW.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every string is NUL-terminated and outlives the call,
        // `command_line` is writable, `environment` is a complete Unicode
        // block, and `startup` carries the initialized attribute list.
        let ok = unsafe {
            CreateProcessW(
                program_w.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                i32::from(!inherit.is_empty()),
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                cwd_w.as_ref().map_or(null(), |dir| dir.as_ptr()),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if ok == 0 {
            return Err(format!(
                "cannot start {}: {}",
                program.display(),
                io::Error::last_os_error()
            ));
        }
        // SAFETY: CreateProcessW returned two fresh handles the caller owns.
        Ok(unsafe {
            Child {
                process: OwnedHandle::from_raw_handle(info.hProcess),
                thread: OwnedHandle::from_raw_handle(info.hThread),
            }
        })
    })();
    // SAFETY: initialized above, deleted once.
    unsafe { DeleteProcThreadAttributeList(list) };
    result
}

impl Child {
    pub(super) fn resume(&self) -> Result<(), String> {
        // SAFETY: valid thread handle of a suspended process.
        if unsafe { ResumeThread(self.thread.as_raw_handle()) } == u32::MAX {
            let error = io::Error::last_os_error();
            self.terminate();
            return Err(format!("ResumeThread: {error}"));
        }
        Ok(())
    }

    pub(super) fn terminate(&self) {
        // SAFETY: valid process handle; failure (already gone) is harmless.
        unsafe { TerminateProcess(self.process.as_raw_handle(), 126) };
    }

    /// Waits for the process and returns its exit code.
    pub(super) fn wait(&self) -> Result<u32, String> {
        // SAFETY: valid process handle.
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(format!(
                "waiting for the child: {}",
                io::Error::last_os_error()
            ));
        }
        let mut code = 0u32;
        // SAFETY: valid process handle, out-parameter only.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(format!("exit code: {}", io::Error::last_os_error()));
        }
        Ok(code)
    }
}
