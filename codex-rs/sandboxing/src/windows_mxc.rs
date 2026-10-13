//! Native Windows MXC capability discovery and availability metrics.
//! Probing is cached upstream; reporting happens at most once per process.

use codex_network_proxy::RemoteNetworkProxyConfig;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use crate::SandboxType;

static AVAILABILITY_RECORDED: AtomicBool = AtomicBool::new(false);

pub(super) fn record_availability_once() {
    // Probe actual PSEC create/close support; symbol presence alone also
    // succeeds on transitional Windows builds where MXC is not enabled.
    let available = codex_mxc_sandbox::is_available();
    if let Some(metrics) = codex_otel::global()
        && !AVAILABILITY_RECORDED.swap(true, Ordering::Relaxed)
    {
        let _ = metrics.counter(
            "codex.windows_mxc.available",
            /*inc*/ 1,
            &[("available", if available { "true" } else { "false" })],
        );
    }
}
/// An embedding application's requested Windows backend; Auto prefers compatible MXC.
#[derive(Clone, Copy, Debug, Default)]
pub enum WindowsSandboxPreference {
    #[default]
    Auto,
    Mxc,
    Elevated,
    Unelevated,
}

/// Resolve the backend before preparing native resources. A host can exclude MXC
/// when its own persistent state is incompatible with host-identity execution.
/// Launch errors must be returned to the caller, never retried with another backend.
pub fn select_windows_sandbox(
    preference: WindowsSandboxPreference,
    permissions: &PermissionProfile,
    proxy: Option<&RemoteNetworkProxyConfig>,
    host_mxc_restriction: Option<&str>,
) -> anyhow::Result<(SandboxType, WindowsSandboxLevel)> {
    let restriction = host_mxc_restriction.or_else(|| {
        proxy.filter(|proxy| !proxy.allow_local_binding).map(|_| {
            "MXC cannot enforce allow_local_binding=false: native host-loopback access is bidirectional"
        })
    });
    let compatible = matches!(
        preference,
        WindowsSandboxPreference::Auto | WindowsSandboxPreference::Mxc
    ) && restriction.is_none()
        && codex_mxc_sandbox::is_available_for(permissions);
    match preference {
        WindowsSandboxPreference::Auto if compatible => {
            Ok((SandboxType::WindowsMxc, WindowsSandboxLevel::Disabled))
        }
        WindowsSandboxPreference::Mxc => {
            anyhow::ensure!(
                compatible,
                "{}",
                restriction
                    .unwrap_or("MXC is unavailable for this filesystem policy on this executor")
            );
            Ok((SandboxType::WindowsMxc, WindowsSandboxLevel::Disabled))
        }
        WindowsSandboxPreference::Auto | WindowsSandboxPreference::Elevated => Ok((
            SandboxType::WindowsRestrictedToken,
            WindowsSandboxLevel::Elevated,
        )),
        WindowsSandboxPreference::Unelevated => Ok((
            SandboxType::WindowsRestrictedToken,
            WindowsSandboxLevel::RestrictedToken,
        )),
    }
}
