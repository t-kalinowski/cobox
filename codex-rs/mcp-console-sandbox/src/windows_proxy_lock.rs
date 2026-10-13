use anyhow::Context;
use anyhow::Result;
use std::fs::File;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
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

pub(crate) fn pool_marker(state: &Path) -> PathBuf {
    state.join(".sandbox-secrets").join("console-proxy-pool-v1")
}

/// Exclude admission before inspecting durable leases and invalidating readiness.
pub(crate) fn begin_setup(state: &Path) -> Result<File> {
    let secrets = state.join(".sandbox-secrets");
    std::fs::create_dir_all(&secrets)?;
    let configuration = configuration_guard(state)?;
    for entry in std::fs::read_dir(&secrets)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        anyhow::ensure!(
            !(name.ends_with(".lease")
                && (name.starts_with("proxy-slot-")
                    || (name.starts_with("legacy-session-") && entry.metadata()?.len() != 0))),
            "{name} is leased or quarantined; setup cannot replace an unretired workload"
        );
    }
    // A caller can have write access without DELETE; keep this protected object.
    std::fs::write(pool_marker(state), b"")?;
    Ok(configuration)
}

/// Base-account workloads may run concurrently, but each must retire before setup.
pub(crate) struct LegacyLease {
    file: Option<File>,
    started: bool,
}

impl LegacyLease {
    pub(crate) fn acquire(state: &Path, _configuration: File) -> Result<Self> {
        anyhow::ensure!(
            std::fs::read(pool_marker(state)).ok().as_deref() == Some(b"1\n"),
            "Windows sandbox setup is required; run `mcp-console-sandbox setup` with the original base state directory"
        );
        let secrets = state.join(".sandbox-secrets");
        let mut reusable = None;
        for entry in std::fs::read_dir(&secrets)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("legacy-session-")
                && name.ends_with(".lease")
                && entry.metadata()?.len() == 0
            {
                reusable = Some(File::options().write(true).open(entry.path())?);
                break;
            }
        }
        let file = match reusable {
            Some(file) => file,
            None => {
                tempfile::Builder::new()
                    .prefix("legacy-session-")
                    .suffix(".lease")
                    .tempfile_in(&secrets)?
                    .keep()?
                    .0
            }
        };
        file.set_len(1)?;
        Ok(Self {
            file: Some(file),
            started: false,
        })
    }

    pub(crate) fn mark_spawn_attempted(&mut self) {
        self.started = true;
    }

    pub(crate) fn release(mut self) -> Result<()> {
        // This is the final mutation: another admission may immediately reuse the
        // empty file. Deletion afterward would race that new owner and needs DELETE.
        self.file
            .take()
            .context("legacy lease file")?
            .set_len(0)
            .context("release retired Console legacy lease")
    }
}

impl Drop for LegacyLease {
    fn drop(&mut self) {
        if !self.started
            && let Some(file) = self.file.take()
        {
            let _ = file.set_len(0);
        }
    }
}

#[cfg(test)]
#[path = "windows_proxy_tests.rs"]
mod tests;
