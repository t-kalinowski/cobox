//! Dedicated Codex proxy listeners admit only members of this workload's Job.

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
use codex_windows_sandbox::environment_transport::environment_key_eq;
use std::collections::HashMap;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::BorrowedHandle;
use std::sync::Arc;

pub(crate) struct Prepared {
    pub proxy: NetworkProxy,
    pub handle: NetworkProxyHandle,
    pub context: ManagedNetworkSandboxContext,
}

// Reject unsupported transports before creating native MXC resources.
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

pub(crate) async fn start(
    config: RemoteNetworkProxyConfig,
    job: &JobObject,
    environment: &mut HashMap<String, String>,
) -> Result<Prepared> {
    validate(&config)?;
    let mut state = NetworkProxyState::from_remote_launch_config(
        RemoteNetworkProxyLaunchConfig::new(config),
        codex_network_proxy::Platform::native(),
    )?;
    let handle = unsafe { BorrowedHandle::borrow_raw(job.as_raw_handle()) };
    state.set_windows_client_job(handle.try_clone_to_owned()?);
    let proxy = NetworkProxy::builder()
        .state(Arc::new(state))
        .managed_proxy_routing(ManagedProxyRouting::DedicatedListeners)
        .build()
        .await?;
    let prepared =
        proxy.prepare_for_optional_environment(Default::default(), /*environment_id*/ None)?;
    codex_network_proxy::strip_managed_proxy_env(environment);
    environment.retain(|name, value| {
        !(codex_network_proxy::PROXY_ENV_KEYS
            .iter()
            .any(|reserved| environment_key_eq(name.as_ref(), reserved))
            || (codex_network_proxy::CUSTOM_CA_ENV_KEYS
                .iter()
                .any(|reserved| environment_key_eq(name.as_ref(), reserved))
                && codex_network_proxy::is_managed_mitm_ca_trust_bundle_path(value)))
    });
    for (key, value) in prepared.env {
        environment.retain(|name, _| !environment_key_eq(name.as_ref(), &key));
        environment.insert(key, value);
    }
    let handle = proxy.run().await?;
    Ok(Prepared {
        proxy,
        handle,
        context: prepared.sandbox_context,
    })
}
