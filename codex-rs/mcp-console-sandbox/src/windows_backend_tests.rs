use super::*;
use codex_network_proxy::NetworkProxyConfig;
use pretty_assertions::assert_eq;

#[test]
fn disabled_proxy_does_not_affect_windows_backend_selection() -> anyhow::Result<()> {
    let proxy = RemoteNetworkProxyConfig::from_effective_config(&NetworkProxyConfig {
        enabled: false,
        allow_local_binding: Some(false),
        ..Default::default()
    })?;
    let permissions = PermissionProfile::read_only();
    for preference in [
        WindowsSandboxPreference::Auto,
        WindowsSandboxPreference::Mxc,
        WindowsSandboxPreference::Elevated,
        WindowsSandboxPreference::Unelevated,
    ] {
        let select = |proxy| {
            select_windows_sandbox(
                preference,
                &permissions,
                proxy,
                /*host_mxc_restriction*/ None,
            )
            .map_err(|error| error.to_string())
        };
        assert_eq!(
            select(Some(&proxy)),
            select(/*proxy*/ None),
            "{preference:?}"
        );
    }
    Ok(())
}

#[test]
fn enabled_proxy_without_local_binding_excludes_mxc() -> anyhow::Result<()> {
    let mut proxy = RemoteNetworkProxyConfig::from_effective_config(&NetworkProxyConfig {
        enabled: false,
        enable_socks5_udp: false,
        allow_local_binding: Some(false),
        ..Default::default()
    })?;
    proxy.enabled = true;
    let permissions = PermissionProfile::read_only();
    assert_eq!(
        select_windows_sandbox(
            WindowsSandboxPreference::Auto,
            &permissions,
            Some(&proxy),
            /*host_mxc_restriction*/ None,
        )?,
        (
            SandboxType::WindowsRestrictedToken,
            WindowsSandboxLevel::Elevated
        )
    );
    let error = select_windows_sandbox(
        WindowsSandboxPreference::Mxc,
        &permissions,
        Some(&proxy),
        /*host_mxc_restriction*/ None,
    )
    .unwrap_err();
    assert!(error.to_string().contains("allow_local_binding=false"));
    Ok(())
}
