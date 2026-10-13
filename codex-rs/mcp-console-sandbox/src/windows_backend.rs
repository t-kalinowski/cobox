//! Console backend preferences over Codex's native capability and launch APIs.

use codex_network_proxy::RemoteNetworkProxyConfig;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_protocol::models::SandboxEnforcement;
use codex_sandboxing::SandboxManager;
use codex_sandboxing::SandboxType;
use codex_sandboxing::SandboxablePreference;

#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WindowsSandboxPreference {
    #[default]
    Auto,
    Mxc,
    Elevated,
    Unelevated,
}

// Resolve Console policy before preparing resources. Launch errors are never
// retried through another backend; shared Codex APIs own sandbox enforcement.
pub(crate) fn select_windows_sandbox(
    preference: WindowsSandboxPreference,
    permissions: &PermissionProfile,
    proxy: Option<&RemoteNetworkProxyConfig>,
    host_mxc_restriction: Option<&str>,
) -> anyhow::Result<(SandboxType, WindowsSandboxLevel)> {
    if let Some(proxy) = proxy.filter(|proxy| proxy.enabled) {
        crate::windows_proxy::validate(proxy)?;
    }
    if !SandboxManager::default().should_sandbox(
        permissions,
        match permissions.enforcement() {
            SandboxEnforcement::External => SandboxablePreference::Auto,
            SandboxEnforcement::Managed | SandboxEnforcement::Disabled => {
                SandboxablePreference::Require
            }
        },
        proxy.is_some_and(|proxy| proxy.enabled),
    ) {
        return Ok((SandboxType::None, WindowsSandboxLevel::Disabled));
    }
    let restriction = host_mxc_restriction.or_else(|| {
        proxy.filter(|proxy| proxy.enabled && !proxy.allow_local_binding).map(|_| {
            "MXC cannot enforce allow_local_binding=false: native host-loopback access is bidirectional"
        })
    });
    let compatible = matches!(
        preference,
        WindowsSandboxPreference::Auto | WindowsSandboxPreference::Mxc
    ) && restriction.is_none()
        && codex_sandboxing::windows_mxc_available_for(permissions);
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

#[cfg(test)]
#[path = "windows_backend_tests.rs"]
mod tests;
