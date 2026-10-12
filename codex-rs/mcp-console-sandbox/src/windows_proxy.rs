//! Console owns one provisioned account/port lease through confirmed native retirement.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_network_proxy::NetworkProxy;
use codex_network_proxy::NetworkProxyHandle;
use codex_network_proxy::NetworkProxyState;
use codex_network_proxy::RemoteNetworkProxyConfig;
use codex_network_proxy::RemoteNetworkProxyLaunchConfig;
use codex_windows_sandbox::ConsoleProxySlot;
use std::collections::HashMap;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;

pub(crate) fn validate(config: &RemoteNetworkProxyConfig) -> Result<()> {
    ensure!(config.enabled, "proxy.enabled must be true");
    ensure!(
        !config.enable_socks5_udp,
        "SOCKS5 UDP is not supported on Windows"
    );
    ensure!(
        !config.dangerously_allow_all_unix_sockets
            && config
                .unix_sockets
                .as_ref()
                .is_none_or(|sockets| sockets.entries.is_empty()),
        "Unix sockets are not supported on Windows"
    );
    Ok(())
}

pub(crate) fn pool_marker(state: &Path) -> PathBuf {
    state.join(".sandbox-secrets").join("console-proxy-pool-v1")
}

/// Short admission barrier; explicit pool setup holds it until all helpers finish.
pub(crate) struct ConfigurationGuard(OwnedHandle);

impl Drop for ConfigurationGuard {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.0.as_raw_handle()) };
    }
}

pub(crate) fn configuration_guard() -> Result<ConfigurationGuard> {
    let name: Vec<u16> = "Global\\McpConsoleProxyConfiguration\0"
        .encode_utf16()
        .collect();
    let handle = unsafe {
        CreateMutexW(std::ptr::null(), /*binitialowner*/ 0, name.as_ptr())
    };
    let error = unsafe { GetLastError() };
    ensure!(
        !handle.is_null(),
        "Console proxy configuration lock is unavailable: {error}"
    );
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let waited = unsafe {
        WaitForSingleObject(handle.as_raw_handle(), /*dwmilliseconds*/ 5_000)
    };
    ensure!(
        matches!(waited, WAIT_OBJECT_0 | WAIT_ABANDONED),
        "Console proxy setup or admission is in progress; retry after it completes"
    );
    Ok(ConfigurationGuard(handle))
}

pub(crate) struct Lease {
    pub slot: ConsoleProxySlot,
    pub state: PathBuf,
    path: PathBuf,
    file: Option<File>,
    started: bool,
    _mutex: OwnedHandle,
}

impl Lease {
    pub fn acquire(state: &Path, config: &RemoteNetworkProxyConfig) -> Result<Self> {
        let _configuration = configuration_guard()?;
        ensure!(
            std::fs::read(pool_marker(state)).ok().as_deref() == Some(b"1\n"),
            "Windows managed proxy setup is required; run `mcp-console-sandbox setup --managed-proxy` with the same state directory"
        );
        ConsoleProxySlot::validate_owner(state)?;
        for index in 0..ConsoleProxySlot::COUNT {
            let slot = ConsoleProxySlot::new(index)?;
            if slot.settings().allow_local_binding != config.allow_local_binding {
                continue;
            }
            let name: Vec<u16> = format!("Global\\McpConsoleProxyLease{index}\0")
                .encode_utf16()
                .collect();
            let handle = unsafe {
                CreateMutexW(std::ptr::null(), /*binitialowner*/ 0, name.as_ptr())
            };
            let last_error = unsafe { GetLastError() };
            if handle.is_null() {
                continue;
            }
            let mutex = unsafe { OwnedHandle::from_raw_handle(handle) };
            if last_error == ERROR_ALREADY_EXISTS {
                continue;
            }
            let path = state
                .join(".sandbox-secrets")
                .join(format!("proxy-slot-{index}.lease"));
            let file = match File::options().write(true).create_new(true).open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("claim Console proxy lease"),
            };
            return Ok(Self {
                slot,
                state: state.join("proxy-slots").join(slot.index().to_string()),
                path,
                file: Some(file),
                started: false,
                _mutex: mutex,
            });
        }
        anyhow::bail!(
            "Console proxy slots are busy or quarantined after unconfirmed retirement; no account or port fallback is permitted"
        )
    }

    pub fn release(mut self) -> Result<()> {
        self.file.take();
        std::fs::remove_file(&self.path).context("release retired Console proxy lease")
    }

    pub fn mark_spawn_attempted(&mut self) {
        self.started = true;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Before native launch there is no workload whose retirement could be ambiguous.
        // After that boundary, only the explicit confirmed-cleanup path may release a lease.
        if !self.started && self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) struct Prepared {
    pub handle: NetworkProxyHandle,
    pub restricting_sid: String,
}

pub(crate) async fn prepare(
    config: RemoteNetworkProxyConfig,
    slot: ConsoleProxySlot,
    environment: &mut HashMap<String, String>,
) -> Result<Prepared> {
    let account = codex_windows_sandbox::sandbox_name("CodexSandboxOffline");
    let sid = codex_windows_sandbox::string_from_sid_bytes(&codex_windows_sandbox::resolve_sid(
        &account,
    )?)
    .map_err(anyhow::Error::msg)?;
    let proxy = NetworkProxy::builder()
        .state(Arc::new(NetworkProxyState::from_remote_launch_config(
            RemoteNetworkProxyLaunchConfig::new(config),
            codex_network_proxy::Platform::native(),
        )?))
        .windows_isolated_ingress(slot.ports(), sid)
        .build()
        .await?;
    let handle = proxy.run().await?;
    environment.retain(|name, _| {
        ![
            "CODEX_NETWORK_PROXY_CREDENTIAL_BROKER_ACTIVE",
            "CODEX_NETWORK_PROXY_BROKERED_CREDENTIALS",
            "CODEX_NETWORK_PROXY_ATTRIBUTION_TOKEN",
        ]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
    });
    let prepared =
        proxy.prepare_for_optional_environment(Default::default(), /*environment_id*/ None)?;
    // Windows has one variable per case-insensitive name, including mixed-case workload input.
    for (key, value) in prepared.env {
        environment.retain(|name, _| !name.eq_ignore_ascii_case(&key));
        environment.insert(key, value);
    }
    Ok(Prepared {
        handle,
        restricting_sid: proxy
            .network_proxy_restricting_sid(/*environment_id*/ None)
            .context("managed Windows proxy route is unavailable")?,
    })
}
