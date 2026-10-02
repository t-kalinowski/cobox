use serde::Deserialize;
use std::path::PathBuf;

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsSandboxMode {
    Disabled,
    /// Administrator-approved setup with dedicated sandbox accounts.
    Elevated,
    /// No administrator setup; restricted token under the current user.
    Unelevated,
}

#[cfg(windows)]
impl From<WindowsSandboxMode> for codex_protocol::config_types::WindowsSandboxLevel {
    fn from(mode: WindowsSandboxMode) -> Self {
        match mode {
            WindowsSandboxMode::Disabled => Self::Disabled,
            WindowsSandboxMode::Elevated => Self::Elevated,
            WindowsSandboxMode::Unelevated => Self::RestrictedToken,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lifecycle {
    pub parent_pid: Option<i32>,
    pub sigterm: Sigterm,
    pub private_tmp: Option<PrivateTmp>,
    pub cleanup_timeout_ms: Option<u64>,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Sigterm {
    #[default]
    Forward,
    Retire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTmp {
    pub parent: Option<PathBuf>,
    pub environment: Vec<String>,
}

impl Lifecycle {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.parent_pid.is_none_or(|pid| pid > 1),
            "parent_pid must be greater than 1"
        );
        anyhow::ensure!(
            self.cleanup_timeout_ms
                .is_none_or(|ms| (1..=60000).contains(&ms)),
            "cleanup_timeout_ms must be 1..=60000"
        );
        if let Some(temporary) = &self.private_tmp {
            anyhow::ensure!(
                temporary
                    .parent
                    .as_ref()
                    .is_none_or(|path| path.is_absolute()),
                "private_tmp.parent must be absolute"
            );
            for name in &temporary.environment {
                anyhow::ensure!(
                    !name.is_empty() && !name.contains(['=', '\0']),
                    "invalid private_tmp environment name"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxBackend {
    #[default]
    Bubblewrap,
    Landlock,
}
