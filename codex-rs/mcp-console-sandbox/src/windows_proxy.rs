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

/// Resolve existing junctions even when the final policy path has not been created yet.
pub(crate) fn canonical_policy_path(
    path: &Path,
) -> Result<codex_utils_absolute_path::AbsolutePathBuf> {
    let mut ancestor = path;
    let mut suffix = PathBuf::new();
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(root) => {
                return Ok(
                    codex_utils_absolute_path::AbsolutePathBuf::from_absolute_path(
                        root.join(suffix),
                    )?,
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix = PathBuf::from(
                    ancestor
                        .file_name()
                        .context("policy path has no existing ancestor")?,
                )
                .join(suffix);
                ancestor = ancestor.parent().context("policy path has no parent")?;
            }
            Err(error) => return Err(error).context("resolve Windows policy path"),
        }
    }
}

/// MXC runs as the host user, outside the legacy accounts' secrets-deny group.
/// Protect requested/default state and the registered pool even with broad workload grants.
pub(crate) fn protect_state(
    filesystem: &mut codex_protocol::permissions::FileSystemSandboxPolicy,
    state: &Path,
) -> Result<codex_protocol::permissions::FileSystemSandboxPolicy> {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::permissions::FileSystemSandboxKind;
    use codex_protocol::permissions::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let default_state =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
            .join("mcp-console");
    let mut roots = vec![state.to_path_buf(), default_state];
    roots.extend(ConsoleProxySlot::registered_state_directory()?);
    let mut denied = FileSystemSandboxPolicy::restricted(Vec::new());
    for root in roots {
        ensure!(
            root.parent().is_some(),
            "MXC cannot protect a drive-root Console state directory; use elevated mode or a dedicated state directory"
        );
        let canonical = canonical_policy_path(&root)?;
        ensure!(
            canonical.parent().is_some(),
            "MXC cannot protect a drive-root Console state directory"
        );
        denied.entries.push(FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(root)?.into(),
            FileSystemAccessMode::Deny,
        ));
        denied.entries.push(FileSystemSandboxEntry::new(
            canonical.into(),
            FileSystemAccessMode::Deny,
        ));
    }
    // Even externally managed or otherwise unrestricted files must exclude control state.
    if filesystem.kind == FileSystemSandboxKind::ExternalSandbox {
        *filesystem = FileSystemSandboxPolicy::unrestricted();
    }
    filesystem.preserve_deny_read_restrictions_from(&denied);
    Ok(denied)
}

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
}

impl Lease {
    pub fn acquire(state: &Path, config: &RemoteNetworkProxyConfig) -> Result<Self> {
        let _configuration = configuration_guard()?;
        ensure!(
            std::fs::read(pool_marker(state)).ok().as_deref() == Some(b"1\n"),
            "Windows managed proxy setup is required; run `mcp-console-sandbox setup` with the same state directory"
        );
        ConsoleProxySlot::validate_owner(state)?;
        for index in 0..ConsoleProxySlot::COUNT {
            let slot = ConsoleProxySlot::new(index)?;
            if slot.settings().allow_local_binding != config.allow_local_binding {
                continue;
            }
            // The protected owner record pins every companion to this directory.
            // Atomic creation is both admission and crash quarantine; a second
            // per-slot kernel lock would duplicate the same ownership decision.
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
    pub proxy: NetworkProxy,
    pub context: codex_network_proxy::ManagedNetworkSandboxContext,
    pub handle: NetworkProxyHandle,
}

pub(crate) enum Owner<'a> {
    Account(ConsoleProxySlot),
    Job(&'a codex_utils_pty::JobObject),
}

pub(crate) async fn prepare(
    config: RemoteNetworkProxyConfig,
    owner: Owner<'_>,
    environment: &mut HashMap<String, String>,
) -> Result<Prepared> {
    let mut state = NetworkProxyState::from_remote_launch_config(
        RemoteNetworkProxyLaunchConfig::new(config),
        codex_network_proxy::Platform::native(),
    )?;
    let mut builder = NetworkProxy::builder();
    match owner {
        Owner::Account(slot) => {
            let account = codex_windows_sandbox::sandbox_name("CodexSandboxOffline");
            let sid = codex_windows_sandbox::string_from_sid_bytes(
                &codex_windows_sandbox::resolve_sid(&account)?,
            )
            .map_err(anyhow::Error::msg)?;
            let [http_port, socks_port] = slot.ports();
            let mut config = state.current_cfg().await?;
            config.proxy_url = format!("http://127.0.0.1:{http_port}");
            config.socks_url = format!("socks5://127.0.0.1:{socks_port}");
            state
                .replace_config_state(codex_network_proxy::build_config_state(
                    config,
                    Default::default(),
                    codex_network_proxy::Platform::native(),
                )?)
                .await?;
            builder = builder.windows_client_sid(sid);
        }
        Owner::Job(job) => {
            // The duplicated handle owns the same kernel object, not a workload-selected name.
            let handle =
                unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(job.as_raw_handle()) };
            state.set_windows_client_job(handle.try_clone_to_owned()?);
            builder = builder.managed_proxy_routing(
                codex_network_proxy::ManagedProxyRouting::DedicatedListeners,
            );
        }
    }
    let proxy = builder.state(Arc::new(state)).build().await?;
    if let Owner::Account(slot) = owner {
        // Fixed firewall exceptions cannot follow the upstream allocator's fallback.
        ensure!(
            [proxy.http_addr().port(), proxy.socks_addr().port()] == slot.ports(),
            "provisioned Console proxy port is unavailable; no port fallback is permitted"
        );
    }
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
        proxy,
        context: prepared.sandbox_context,
    })
}
