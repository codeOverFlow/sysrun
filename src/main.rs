#![deny(clippy::all, clippy::pedantic)]

use crate::windows::{get_dup_and_primary_tokens, get_session, set_privilege};
use ::windows::{
    Win32::{
        Security::{
            SE_ASSIGNPRIMARYTOKEN_NAME,
            SE_DEBUG_NAME,
            SE_INCREASE_QUOTA_NAME,
            SetTokenInformation,
            TokenSessionId,
        },
        System::Threading::{
            CreateProcessAsUserW,
            PROCESS_CREATION_FLAGS,
            PROCESS_INFORMATION,
            STARTUPINFOW,
            SetThreadToken,
        },
    },
    core::{PCWSTR, PWSTR},
};
use std::{ffi::OsString, os::windows::ffi::OsStrExt};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use crate::windows::{cli, enable_debug_privilege};
    use clap::Parser;
    use std::process::ExitCode;

    let cli = cli::Cli::parse();

    if enable_debug_privilege().is_err() {
        eprintln!("EnableDebugPrivilege failed: Access denied (are you running elevated?)");
        return ExitCode::FAILURE;
    }

    let Ok((dup_token, primary_token)) = get_dup_and_primary_tokens() else {
        return ExitCode::FAILURE;
    };

    if unsafe { SetThreadToken(None, Some(dup_token.0)) }.is_err() {
        eprintln!("SetThreadToken failed: Access denied (are you running elevated?)");
        return ExitCode::FAILURE;
    }

    let Ok((mut session, len)) = get_session() else {
        return ExitCode::FAILURE;
    };

    if set_privilege(&dup_token, SE_ASSIGNPRIMARYTOKEN_NAME, true).is_err()
        || set_privilege(&dup_token, SE_DEBUG_NAME, true).is_err()
        || set_privilege(&dup_token, SE_INCREASE_QUOTA_NAME, true).is_err()
    {
        eprintln!("SetPrivilege failed: Insufficient privileges");
        return ExitCode::FAILURE;
    }

    if unsafe {
        SetTokenInformation(
            primary_token.0,
            TokenSessionId,
            (&raw mut session).cast(),
            len,
        )
    }
    .is_err()
    {
        eprintln!("Failed to set token session information.");
        return ExitCode::FAILURE;
    }

    let executable = cli
        .executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let args = cli.args.join(" ".as_ref());
    let mut args = args.encode_wide().chain(Some(0)).collect::<Vec<_>>();

    let si_cb =
        u32::try_from(size_of::<STARTUPINFOW>()).expect("STARTUPINFOW cannot exceed u32::MAX");
    let desktop = OsString::from(r"Winsta0\default");
    let mut desktop = desktop.encode_wide().chain(Some(0)).collect::<Vec<u16>>();

    let si = STARTUPINFOW {
        cb: si_cb,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };

    let mut pi = PROCESS_INFORMATION::default();

    if let Err(reason) = unsafe {
        CreateProcessAsUserW(
            Some(primary_token.0),
            PCWSTR(executable.as_ptr()),
            Some(PWSTR(args.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS::default(),
            None,
            None,
            &raw const si,
            &raw mut pi,
        )
    } {
        eprintln!("Failed to create process (error={reason})");
        ExitCode::FAILURE
    } else {
        println!("Process created: {}", pi.dwProcessId);
        ExitCode::SUCCESS
    }
}

#[cfg(not(windows))]
fn main() {
    compile_error!("This crate is only supported on Windows");
}
