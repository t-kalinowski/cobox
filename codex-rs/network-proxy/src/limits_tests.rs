use super::*;
use crate::NetworkProxy;
use crate::NetworkProxyLimits;
use crate::RemoteNetworkProxyConfig;
use crate::RemoteNetworkProxyLaunchConfig;
use pretty_assertions::assert_eq;
use std::cell::Cell;

fn limited_state(
    allowed: &[&str],
    denied: &[&str],
    limits: NetworkProxyLimits,
) -> Result<NetworkProxyState> {
    let mut config = NetworkProxyConfig {
        enabled: true,
        // Domain-only tests must not depend on external DNS.
        allow_local_binding: Some(true),
        ..NetworkProxyConfig::default()
    };
    config.set_allowed_domains(allowed.iter().map(|entry| (*entry).to_string()).collect());
    config.set_denied_domains(denied.iter().map(|entry| (*entry).to_string()).collect());
    NetworkProxyState::from_remote_launch_config_with_limits(
        RemoteNetworkProxyLaunchConfig::new(RemoteNetworkProxyConfig::from_effective_config(
            &config,
        )?),
        crate::Platform::native(),
        limits,
    )
}

#[tokio::test]
async fn launch_limits_intersect_glob_matches_without_granting_access() -> Result<()> {
    let state = limited_state(
        &["api?.posit.co"],
        &[],
        NetworkProxyLimits {
            allowed_domains: Some(vec!["*1.posit.co".to_string()]),
            ..NetworkProxyLimits::default()
        },
    )?;
    for (host, expected) in [
        ("api1.posit.co", HostBlockDecision::Allowed),
        ("API1.POSIT.CO.", HostBlockDecision::Allowed),
        (
            "api2.posit.co",
            HostBlockDecision::Blocked(HostBlockReason::Denied),
        ),
        (
            "other1.posit.co",
            HostBlockDecision::Blocked(HostBlockReason::NotAllowed),
        ),
    ] {
        assert_eq!(state.host_blocked(host, 443).await?, expected, "{host}");
    }
    Ok(())
}

#[tokio::test]
async fn launch_limits_capture_the_dedicated_proxy_endpoints() -> Result<()> {
    let state = limited_state(
        &["*"],
        &[],
        NetworkProxyLimits {
            allowed_domains: Some(vec!["*.example.com".to_string()]),
            ..Default::default()
        },
    )?;
    let proxy = NetworkProxy::builder()
        .state(Arc::new(state))
        .managed_proxy_routing(crate::ManagedProxyRouting::DedicatedListeners)
        .build()
        .await?;
    let prepared =
        proxy.prepare_for_optional_environment(Default::default(), /*environment_id*/ None)?;
    assert_eq!(
        prepared.sandbox_context.proxy_only_endpoints,
        Some(vec![proxy.http_addr(), proxy.socks_addr()])
    );
    Ok(())
}

#[tokio::test]
async fn launch_limits_distinguish_omitted_and_empty_allowlists() -> Result<()> {
    let unrestricted = limited_state(&["*"], &[], NetworkProxyLimits::default())?;
    assert_eq!(
        unrestricted.host_blocked("api.posit.co", 443).await?,
        HostBlockDecision::Allowed
    );

    let deny_all = limited_state(
        &["*"],
        &[],
        NetworkProxyLimits {
            allowed_domains: Some(Vec::new()),
            ..NetworkProxyLimits::default()
        },
    )?;
    assert_eq!(
        deny_all.host_blocked("api.posit.co", 443).await?,
        HostBlockDecision::Blocked(HostBlockReason::Denied)
    );

    let no_requested_access = limited_state(
        &[],
        &[],
        NetworkProxyLimits {
            allowed_domains: Some(vec!["*".to_string()]),
            ..NetworkProxyLimits::default()
        },
    )?;
    assert_eq!(
        no_requested_access
            .host_blocked("api.posit.co", 443)
            .await?,
        HostBlockDecision::Blocked(HostBlockReason::NotAllowed)
    );
    Ok(())
}

#[tokio::test]
async fn launch_limits_survive_domain_edits_cloning_and_state_replacement() -> Result<()> {
    let state = limited_state(
        &["*"],
        &["user-denied.posit.co"],
        NetworkProxyLimits {
            allowed_domains: Some(vec!["*.posit.co".to_string()]),
            denied_domains: vec!["blocked.posit.co".to_string()],
            ..NetworkProxyLimits::default()
        },
    )?;
    for host in ["user-denied.posit.co", "blocked.posit.co"] {
        assert_eq!(
            state.host_blocked(host, 443).await?,
            HostBlockDecision::Blocked(HostBlockReason::Denied)
        );
    }

    // Upserting an ordinary allow can remove an ordinary deny, but cannot
    // remove either an immutable deny or the independent allowlist cap.
    state.add_allowed_domain("blocked.posit.co").await?;
    state.add_allowed_domain("outside.example").await?;
    for host in ["blocked.posit.co", "outside.example"] {
        assert_eq!(
            state.host_blocked(host, 443).await?,
            HostBlockDecision::Blocked(HostBlockReason::Denied)
        );
    }

    let mut replacement = state.current_cfg().await?;
    replacement.set_denied_domains(Vec::new());
    replacement.set_allowed_domains(vec!["*".to_string()]);
    replacement.allow_upstream_proxy = true;
    state
        .replace_config_state(build_config_state(
            replacement,
            NetworkProxyConstraints::default(),
            crate::Platform::native(),
        )?)
        .await?;
    let cloned = state.clone();
    assert!(!cloned.allow_upstream_proxy().await?);
    assert!(!cloned.current_cfg().await?.allow_upstream_proxy);
    for host in ["blocked.posit.co", "outside.example"] {
        assert_eq!(
            cloned.host_blocked(host, 443).await?,
            HostBlockDecision::Blocked(HostBlockReason::Denied)
        );
    }
    assert_eq!(
        cloned.host_blocked("allowed.posit.co", 443).await?,
        HostBlockDecision::Allowed
    );
    assert_eq!(
        cloned.current_patterns().await?.1,
        vec!["blocked.posit.co".to_string()]
    );
    Ok(())
}

#[tokio::test]
async fn launch_limits_block_approvals_before_dns() -> Result<()> {
    let state = limited_state(
        &["*"],
        &[],
        NetworkProxyLimits {
            allowed_domains: Some(vec!["*.posit.co".to_string()]),
            denied_domains: vec!["blocked.posit.co".to_string()],
            allow_local_binding: Some(false),
        },
    )?;
    let lookups = Cell::new(0);
    for host in ["outside.example", "blocked.posit.co"] {
        for authorization in [
            HostAuthorization::RequireAllowlist,
            HostAuthorization::Approved,
        ] {
            let decision = state
                .host_blocked_with_lookup(host, 443, Some(true), authorization, |_host, _port| {
                    lookups.set(lookups.get() + 1);
                    async { Ok(vec!["8.8.8.8:443".parse().unwrap()]) }
                })
                .await?;
            assert_eq!(
                decision,
                HostBlockDecision::Blocked(HostBlockReason::Denied)
            );
        }
    }
    assert_eq!(lookups.get(), 0);
    Ok(())
}

#[tokio::test]
async fn launch_limits_cap_local_binding_in_runtime_and_sandbox_settings() -> Result<()> {
    let state = Arc::new(limited_state(
        &["*"],
        &[],
        NetworkProxyLimits {
            allow_local_binding: Some(false),
            ..NetworkProxyLimits::default()
        },
    )?);
    let proxy = NetworkProxy::builder()
        .state(Arc::clone(&state))
        .managed_by_codex(false)
        .build()
        .await?;
    assert!(!state.allow_local_binding().await?);
    assert!(!state.current_cfg().await?.allow_local_binding());
    assert!(!proxy.allow_local_binding());

    let mut replacement = state.current_cfg().await?;
    replacement.allow_local_binding = Some(true);
    proxy
        .replace_config_state(build_config_state(
            replacement,
            NetworkProxyConstraints::default(),
            crate::Platform::native(),
        )?)
        .await?;
    assert!(!state.allow_local_binding().await?);
    assert!(!state.current_cfg().await?.allow_local_binding());
    assert!(!proxy.allow_local_binding());

    // A permissive cap cannot turn on an ordinary false setting.
    let mut config = NetworkProxyConfig {
        enabled: true,
        allow_local_binding: Some(false),
        ..NetworkProxyConfig::default()
    };
    config.set_allowed_domains(vec!["*".to_string()]);
    let state = NetworkProxyState::from_remote_launch_config_with_limits(
        RemoteNetworkProxyLaunchConfig::new(RemoteNetworkProxyConfig::from_effective_config(
            &config,
        )?),
        crate::Platform::native(),
        NetworkProxyLimits {
            allow_local_binding: Some(true),
            ..NetworkProxyLimits::default()
        },
    )?;
    assert!(!state.allow_local_binding().await?);
    Ok(())
}

#[tokio::test]
async fn launch_limits_cannot_be_lost_by_remote_export() -> Result<()> {
    let state = Arc::new(limited_state(
        &["*"],
        &[],
        NetworkProxyLimits {
            allowed_domains: Some(vec!["*.posit.co".to_string()]),
            ..NetworkProxyLimits::default()
        },
    )?);
    let proxy = NetworkProxy::builder()
        .state(state)
        .managed_by_codex(false)
        .build()
        .await?;
    assert!(
        proxy
            .remote_launch_config(LocalBindingPolicy::DefaultFalse)
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn launch_limits_validate_patterns_without_starting_a_proxy() {
    for limits in [
        NetworkProxyLimits {
            allowed_domains: Some(vec!["example.com/path".to_string()]),
            ..NetworkProxyLimits::default()
        },
        NetworkProxyLimits {
            denied_domains: vec!["*".to_string()],
            ..NetworkProxyLimits::default()
        },
    ] {
        assert!(limits.validate().is_err());
        assert!(limited_state(&["*"], &[], limits).is_err());
    }
    assert!(
        NetworkProxyLimits {
            allowed_domains: Some(Vec::new()),
            ..NetworkProxyLimits::default()
        }
        .validate()
        .is_ok()
    );
}
