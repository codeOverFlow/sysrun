use std::ptr::null_mut;
use windows::{
    Win32::{
        Foundation::{ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID},
        Security::{
            AdjustTokenPrivileges,
            DuplicateTokenEx,
            GetTokenInformation,
            IsWellKnownSid,
            LUID_AND_ATTRIBUTES,
            LookupPrivilegeValueW,
            PSID,
            SE_DEBUG_NAME,
            SE_PRIVILEGE_ENABLED,
            SecurityImpersonation,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_ALL_ACCESS,
            TOKEN_ASSIGN_PRIMARY,
            TOKEN_DUPLICATE,
            TOKEN_IMPERSONATE,
            TOKEN_PRIVILEGES,
            TOKEN_PRIVILEGES_ATTRIBUTES,
            TOKEN_QUERY,
            TokenImpersonation,
            TokenPrimary,
            TokenSessionId,
            WinLocalSystemSid,
        },
        System::{
            RemoteDesktop::{
                WTS_CURRENT_SERVER_HANDLE,
                WTS_PROCESS_INFOW,
                WTSEnumerateProcessesW,
                WTSFreeMemory,
            },
            Threading::{
                GetCurrentProcess,
                OpenProcess,
                OpenProcessToken,
                PROCESS_QUERY_INFORMATION,
            },
        },
    },
    core::{Free, PCWSTR},
};

pub mod cli;

pub struct WindowsGuard<T: Free>(pub T);

impl<T: Free> Drop for WindowsGuard<T> {
    fn drop(&mut self) {
        unsafe { self.0.free() };
    }
}

struct WtsProcessInfoGuard(*mut WTS_PROCESS_INFOW);

impl Drop for WtsProcessInfoGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
}

pub fn is_system_sid(sid: PSID) -> bool {
    unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }.as_bool()
}

pub fn open_system_process_token() -> anyhow::Result<WindowsGuard<HANDLE>> {
    let mut info = WtsProcessInfoGuard(null_mut());
    let mut count = 0;
    unsafe {
        WTSEnumerateProcessesW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            0,
            1,
            &raw mut info.0,
            &raw mut count,
        )
    }
    .inspect_err(|err| {
        eprintln!("Error enumerating processes (are you running elevated?) (error={err})");
    })?;

    let mut token = WindowsGuard(HANDLE::default());
    for i in 0..count as usize {
        if isize::try_from(i * size_of::<WTS_PROCESS_INFOW>()).is_err() {
            return Err(anyhow::anyhow!(
                "Safety violation: current process infow is at an offset exceeding isize::MAX"
            ));
        }

        // SAFETY: offset has been checked to fit in isize.
        if let Some(info) = unsafe { info.0.add(i as _).as_ref() } {
            if info.SessionId == 0 && is_system_sid(info.pUserSid) {
                let process_handle = match unsafe {
                    OpenProcess(PROCESS_QUERY_INFORMATION, false, info.ProcessId)
                } {
                    Ok(handle) => WindowsGuard(handle),
                    Err(_) => continue,
                };

                if unsafe {
                    OpenProcessToken(
                        process_handle.0,
                        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE,
                        &raw mut token.0,
                    )
                }
                .is_ok()
                {
                    break;
                }
            }
        }
    }

    Ok(token)
}

pub fn set_privilege(
    token: &WindowsGuard<HANDLE>,
    privilege: PCWSTR,
    enable_privilege: bool,
) -> anyhow::Result<()> {
    if token.0.is_invalid() {
        return Err(anyhow::anyhow!("Invalid token"));
    }

    if privilege.is_null() {
        return Err(anyhow::anyhow!("Privilege cannot be an empty string"));
    }

    let mut luid = LUID::default();

    unsafe { LookupPrivilegeValueW(PCWSTR::null(), privilege, &raw mut luid) }?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: if enable_privilege {
                SE_PRIVILEGE_ENABLED
            } else {
                TOKEN_PRIVILEGES_ATTRIBUTES::default()
            },
        }],
    };

    // Enable the privilege or disable all privileges.
    let size = u32::try_from(size_of::<TOKEN_PRIVILEGES>())?;
    unsafe { AdjustTokenPrivileges(token.0, false, Some(&raw const tp), size, None, None) }?;

    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return Err(anyhow::anyhow!("Not all privileges have been assigned."));
    }

    Ok(())
}

pub fn enable_debug_privilege() -> anyhow::Result<()> {
    let mut token = WindowsGuard(HANDLE::default());
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut token.0,
        )
    }?;
    set_privilege(&token, SE_DEBUG_NAME, true)?;
    Ok(())
}

pub fn get_dup_and_primary_tokens() -> anyhow::Result<(WindowsGuard<HANDLE>, WindowsGuard<HANDLE>)>
{
    let mut dup_token = WindowsGuard(HANDLE::default());
    let mut primary_token = WindowsGuard(HANDLE::default());

    let token = open_system_process_token().inspect_err(|_| {
        eprintln!("OpenSystemProcessToken failed: Access denied (are you running elevated?)");
    })?;

    unsafe {
        DuplicateTokenEx(
            token.0,
            TOKEN_DUPLICATE
                | TOKEN_IMPERSONATE
                | TOKEN_QUERY
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_PRIVILEGES,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut dup_token.0,
        )
    }
    .inspect_err(|err| {
        eprintln!("Failed to create token (are you running elevated?) (error={err})");
    })?;

    unsafe {
        DuplicateTokenEx(
            token.0,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary_token.0,
        )
    }
    .inspect_err(|err| {
        eprintln!("Failed to create token (are you running elevated?) (error={err})");
    })?;

    Ok((dup_token, primary_token))
}

pub fn get_session() -> anyhow::Result<(u32, u32)> {
    let mut session = 0u32;
    let mut len = u32::try_from(size_of_val(&session)).expect("u32 cannot exceed u32::MAX");

    let mut current_token = WindowsGuard(HANDLE::default());
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ALL_ACCESS,
            &raw mut current_token.0,
        )
    }
    .inspect_err(|_| eprintln!("Failed to open current process token."))?;

    unsafe {
        GetTokenInformation(
            current_token.0,
            TokenSessionId,
            Some((&raw mut session).cast()),
            len,
            &raw mut len,
        )
    }
    .inspect_err(|_| eprintln!("Failed to get token session information."))?;

    Ok((session, len))
}
