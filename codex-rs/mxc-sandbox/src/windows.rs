//! Resolve executor-local state and launch the decoded MXC helper request.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use windows_sys::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
use windows_sys::Win32::System::Com::COINIT_MULTITHREADED;
use windows_sys::Win32::System::Com::CoInitializeEx;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Com::CoUninitialize;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::UI::Shell::FOLDERID_ProgramData;
use windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles;
use windows_sys::Win32::UI::Shell::FOLDERID_ProgramFilesX86;
use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

struct ComUninitializeGuard;

impl Drop for ComUninitializeGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

pub(super) fn run() -> Result<i32> {
    // The host helper retains trusted setup variables. The workload's exact
    // environment travels in the bounded request instead of configuring it.
    let mut env = std::env::vars_os()
        .map(|(key, value)| {
            let key = key
                .into_string()
                .map_err(|_| anyhow::anyhow!("MXC requires Unicode environment variable names"))?;
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("MXC requires Unicode environment variable values"))?;
            Ok((key, value))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    // Serde errors can quote arbitrary payload values; do not print them to stderr.
    let command = crate::transport::decode(&mut env)
        .map_err(|_| anyhow::anyhow!("invalid MXC launcher request"))?;
    if std::env::args_os()
        .nth(2)
        .is_some_and(|arg| arg == "--target")
    {
        // This relay is already inside MXC and the retained Jobs. Ordinary
        // descendants inherit enforcement without Windows rewriting their
        // environment as it does during initial native process creation.
        use std::os::windows::process::CommandExt;
        let (program, args) = command
            .command
            .split_first()
            .context("missing MXC command")?;
        let status = std::process::Command::new(program)
            .args(args)
            .env_clear()
            .envs(command.environment)
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
            .status()
            .context("launching the MXC command")?;
        return Ok(status.code().unwrap_or(/*default*/ 1));
    }
    ensure!(
        crate::is_available(),
        "native MXC is unavailable on this Windows build"
    );
    let mask = unsafe { GetLogicalDrives() };
    ensure!(
        mask != 0,
        "cannot enumerate Windows volumes: {}",
        std::io::Error::last_os_error()
    );
    let mut volumes: Vec<PathBuf> = (0..26)
        .filter(|index| mask & (1 << index) != 0)
        .map(|index| PathBuf::from(format!("{}:\\", (b'A' + index as u8) as char)))
        .collect();
    let command_cwd = std::env::current_dir()?;
    // An explicit UNC cwd has no drive letter and is absent from GetLogicalDrives.
    for cwd in [&command.sandbox_policy_cwd, &command_cwd] {
        if let Some(root) = cwd.ancestors().last() {
            volumes.push(root.to_path_buf());
        }
    }
    let mut request = crate::policy::build_request(
        &command,
        &command_cwd,
        command
            .environment
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        &volumes,
        &platform_read_roots()?,
    )?;
    // Native creation requires LOCALAPPDATA, then replaces it along with TEMP
    // and TMP. Give only this inert setup value and the target request to the
    // in-environment relay; no executor environment is copied into MXC.
    let mut target_environment = HashMap::from([("LOCALAPPDATA".to_owned(), String::new())]);
    crate::transport::encode(&command, &mut target_environment)?;
    request.env = target_environment
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    request.script_code = wxc_common::cmdline::cmdline_from_argv_for_context(
        &[
            std::env::current_exe()?
                .into_os_string()
                .into_string()
                .map_err(|_| anyhow::anyhow!("MXC requires a Unicode launcher path"))?,
            crate::CODEX_WINDOWS_MXC_ARG1.to_owned(),
            "--target".to_owned(),
        ],
        wxc_common::cmdline::CommandLineContext::WindowsCreateProcess,
    )?;
    crate::native::launch(&request)
}

fn platform_read_roots() -> Result<Vec<PathBuf>> {
    use std::os::windows::ffi::OsStringExt;

    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    ensure!(
        length > 0 && (length as usize) < buffer.len(),
        "cannot locate the Windows directory"
    );
    let com_status = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
    ensure!(
        com_status >= 0 || com_status == RPC_E_CHANGED_MODE,
        "cannot initialize COM: HRESULT {com_status:#010x}"
    );
    let _com = (com_status >= 0).then(|| ComUninitializeGuard);
    let mut roots = vec![PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length as usize],
    ))];
    for folder in [
        FOLDERID_ProgramFiles,
        FOLDERID_ProgramFilesX86,
        FOLDERID_ProgramData,
    ] {
        let mut path = std::ptr::null_mut();
        let status = unsafe {
            SHGetKnownFolderPath(&folder, /*dwflags*/ 0, std::ptr::null_mut(), &mut path)
        };
        if status >= 0 && !path.is_null() {
            let mut length = 0;
            unsafe {
                while *path.add(length) != 0 {
                    length += 1;
                }
                roots.push(PathBuf::from(std::ffi::OsString::from_wide(
                    std::slice::from_raw_parts(path, length),
                )));
                CoTaskMemFree(path.cast());
            }
        } else {
            if !path.is_null() {
                unsafe { CoTaskMemFree(path.cast()) };
            }
            anyhow::bail!(
                "cannot locate required Windows platform directory: HRESULT {status:#010x}"
            );
        }
    }
    Ok(roots)
}
