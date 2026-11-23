use crate::NetworkProxyConfig;
use crate::domain_matcher::DomainPatternSet;
use crate::policy::compile_allowlist;
use crate::policy::compile_denylist;
use anyhow::Context;
use anyhow::Result;

/// Immutable restrictions supplied by the host for one executor-local proxy.
///
/// These restrict the ordinary policy without granting access. In particular, an
/// omitted allowlist imposes no cap, while an empty allowlist permits no domains.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkProxyLimits {
    pub allowed_domains: Option<Vec<String>>,
    pub denied_domains: Vec<String>,
    pub allow_local_binding: Option<bool>,
}

impl NetworkProxyLimits {
    /// Validate limits even when the requested sandbox has no network access.
    pub fn validate(&self) -> Result<()> {
        self.compile().map(|_| ())
    }

    pub(crate) fn compile(&self) -> Result<CompiledNetworkProxyLimits> {
        let allowed_domains = self
            .allowed_domains
            .as_ref()
            .map(|patterns| compile_allowlist(patterns))
            .transpose()
            .context("invalid network limits allowlist")?;
        let denied_domains =
            compile_denylist(&self.denied_domains).context("invalid network limits denylist")?;
        Ok(CompiledNetworkProxyLimits {
            policy: self.clone(),
            allowed_domains,
            denied_domains,
        })
    }
}

pub(crate) struct CompiledNetworkProxyLimits {
    pub(crate) policy: NetworkProxyLimits,
    pub(crate) allowed_domains: Option<DomainPatternSet>,
    pub(crate) denied_domains: DomainPatternSet,
}

impl CompiledNetworkProxyLimits {
    pub(crate) fn has_domain_limits(&self) -> bool {
        self.allowed_domains.is_some() || !self.policy.denied_domains.is_empty()
    }

    pub(crate) fn has_restrictions(&self) -> bool {
        self.has_domain_limits() || self.policy.allow_local_binding == Some(false)
    }

    /// Preserve the separate allow matcher: arbitrary glob intersections cannot
    /// be represented by intersecting the pattern strings in two allowlists.
    pub(crate) fn apply_to_config(&self, config: &mut NetworkProxyConfig) {
        if self.has_domain_limits() {
            // The upstream endpoint is not subject to destination checks.
            config.allow_upstream_proxy = false;
        }
        if self.policy.allow_local_binding == Some(false) {
            config.allow_local_binding = Some(false);
        }
        if !self.policy.denied_domains.is_empty() {
            let mut denied_domains = config.denied_domains().unwrap_or_default();
            denied_domains.extend(self.policy.denied_domains.iter().cloned());
            config.set_denied_domains(denied_domains);
        }
    }
}
