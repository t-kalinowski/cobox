use anyhow::Context;
use anyhow::Result;
use std::fs::File;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;

/// The protected state directory owns admission, so a workload cannot squat a
/// public kernel-object name. Closing this locked handle releases the barrier
/// even after host death; durable per-slot leases still quarantine live workloads.
pub(crate) fn configuration_guard(state: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        // Permit setup's ACL inheritance, but never pathname replacement while held.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(
            state
                .join(".sandbox-secrets")
                .join("console-proxy-configuration.lock"),
        )
        .context("Console proxy configuration lock is unavailable")?;
    file.try_lock()
        .context("Console proxy setup or admission is in progress; retry after it completes")?;
    Ok(file)
}

#[cfg(test)]
#[path = "windows_proxy_tests.rs"]
mod tests;
