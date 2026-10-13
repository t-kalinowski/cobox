//! Console proxies admit a workload's Job or its exclusively leased sandbox account.

use anyhow::Result;
use anyhow::ensure;
use codex_network_proxy::ManagedNetworkSandboxContext;
use codex_network_proxy::ManagedProxyRouting;
use codex_network_proxy::NetworkProxy;
use codex_network_proxy::NetworkProxyHandle;
use codex_network_proxy::NetworkProxyState;
use codex_network_proxy::RemoteNetworkProxyConfig;
use codex_network_proxy::RemoteNetworkProxyLaunchConfig;
use codex_utils_pty::JobObject;
use codex_windows_sandbox::ConsoleProxySlot;
use std::collections::HashMap;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::BorrowedHandle;
use std::sync::Arc;

pub(crate) struct Prepared {
    pub proxy: NetworkProxy,
    pub handle: NetworkProxyHandle,
    pub context: ManagedNetworkSandboxContext,
}

// Console supports only TCP proxies on Windows. Reject unsupported modes before
// selecting a backend so unsupported transports never reach native launch.
pub(crate) fn validate(config: &RemoteNetworkProxyConfig) -> Result<()> {
    ensure!(config.enabled, "proxy.enabled must be true");
    ensure!(
        !config.enable_socks5 || !config.enable_socks5_udp,
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

pub(crate) enum Owner<'a> {
    Account(ConsoleProxySlot),
    Job(&'a JobObject),
}

pub(crate) async fn start(
    config: RemoteNetworkProxyConfig,
    owner: Owner<'_>,
    environment: &mut HashMap<String, String>,
) -> Result<Prepared> {
    validate(&config)?;
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
            let handle = unsafe { BorrowedHandle::borrow_raw(job.as_raw_handle()) };
            state.set_windows_client_job(handle.try_clone_to_owned()?);
            builder = builder.managed_proxy_routing(ManagedProxyRouting::DedicatedListeners);
        }
    }
    let proxy = builder.state(Arc::new(state)).build().await?;
    if let Owner::Account(slot) = owner {
        ensure!(
            [proxy.http_addr().port(), proxy.socks_addr().port()] == slot.ports(),
            "provisioned Console proxy port is unavailable; no port fallback is permitted"
        );
    }
    let prepared =
        proxy.prepare_for_optional_environment(Default::default(), /*environment_id*/ None)?;
    codex_network_proxy::strip_managed_proxy_env(environment);
    environment.retain(|name, value| {
        !(codex_network_proxy::PROXY_ENV_KEYS
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
            || (codex_network_proxy::CUSTOM_CA_ENV_KEYS
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
                && codex_network_proxy::is_managed_mitm_ca_trust_bundle_path(value)))
    });
    for (key, value) in prepared.env {
        environment.retain(|name, _| !name.eq_ignore_ascii_case(&key));
        environment.insert(key, value);
    }
    let handle = proxy.run().await?;
    Ok(Prepared {
        proxy,
        handle,
        context: prepared.sandbox_context,
    })
}
