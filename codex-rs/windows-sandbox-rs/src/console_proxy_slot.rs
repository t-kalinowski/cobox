//! Immutable Console proxy identities. Only explicit setup changes their firewall rules.

use crate::WindowsSandboxProduct;
use crate::WindowsSandboxProvisioningSettings;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::borrow::Cow;
use std::path::Path;
use std::sync::OnceLock;

static SLOT: OnceLock<ConsoleProxySlot> = OnceLock::new();
const OWNER_KEY: &str = r"SOFTWARE\McpConsole\SandboxProxy";
const COMPLETED_VALUE: &str = "PoolSetupComplete";
pub(crate) const COMPLETION_FILE: &str = "console-proxy-pool-completion";

/// Reservation prevents conflicting setup; only completed provisioning admits MXC.
pub(crate) enum PoolSetupState {
    Pending,
    Complete,
}

impl PoolSetupState {
    pub(crate) fn persist(self) -> Result<()> {
        self.persist_at(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            OWNER_KEY,
        )
    }

    fn persist_at(self, root: windows_sys::Win32::System::Registry::HKEY, key: &str) -> Result<()> {
        use windows_sys::Win32::System::Registry::*;
        let value = match self {
            Self::Pending => 0_u32,
            Self::Complete => 1,
        };
        let status = unsafe {
            RegSetKeyValueW(
                root,
                crate::to_wide(key).as_ptr(),
                crate::to_wide(COMPLETED_VALUE).as_ptr(),
                REG_DWORD,
                (&raw const value).cast(),
                std::mem::size_of_val(&value) as u32,
            )
        };
        ensure!(status == 0, "persist Console pool setup state: {status}");
        Ok(())
    }
}

fn require_completed_pool(
    root: windows_sys::Win32::System::Registry::HKEY,
    key: &str,
) -> Result<()> {
    use windows_sys::Win32::System::Registry::*;
    let mut value = 0_u32;
    let mut size = std::mem::size_of_val(&value) as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            crate::to_wide(key).as_ptr(),
            crate::to_wide(COMPLETED_VALUE).as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&raw mut value).cast(),
            &mut size,
        )
    };
    ensure!(
        status == 0 && value == 1,
        "Console pool registration is incomplete or predates completion tracking; run explicit `mcp-console-sandbox setup` with the registered state directory before using MXC (registry status: {status})"
    );
    Ok(())
}

/// One account pair with fixed ports and local-access policy, leased by one companion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleProxySlot(u8);

impl ConsoleProxySlot {
    /// Two strict slots and two slots with native loopback access.
    pub const COUNT: u8 = 4;

    pub fn new(index: u8) -> Result<Self> {
        ensure!(index < Self::COUNT, "invalid Console proxy slot");
        Ok(Self(index))
    }

    /// Select before any native operation, once per companion or helper process.
    pub fn initialize(self) -> Result<()> {
        WindowsSandboxProduct::Console.initialize()?;
        ensure!(
            *SLOT.get_or_init(|| self) == self,
            "Console proxy slot was already selected differently"
        );
        Ok(())
    }

    pub fn current() -> Option<Self> {
        SLOT.get().copied()
    }

    pub fn index(self) -> u8 {
        self.0
    }

    pub fn ports(self) -> [u16; 2] {
        [43180 + u16::from(self.0) * 2, 43181 + u16::from(self.0) * 2]
    }

    pub fn settings(self) -> WindowsSandboxProvisioningSettings {
        WindowsSandboxProvisioningSettings {
            proxy_ports: self.ports().to_vec(),
            allow_local_binding: self.0 >= Self::COUNT / 2,
        }
    }

    /// A machine has one pool owner and one durable lease directory, even after a crash.
    pub fn validate_owner(state: &Path) -> Result<()> {
        let record = Self::owner(state)?;
        let caller = crate::runtime_ownership::current_setup_user()?;
        let caller_sid = crate::string_from_sid_bytes(&crate::resolve_sid(&caller)?)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            record.user_sid == caller_sid,
            "Console proxy pool belongs to a different user"
        );
        Ok(())
    }

    /// Protected machine registration, independent of any session's requested state directory.
    /// Host-identity sandboxes must deny access to this pool's credentials and lease records.
    /// Older base-only installations must register and refresh credentials explicitly first.
    pub fn registered_state_directory() -> Result<Option<std::path::PathBuf>> {
        if let Some(record) = crate::installation_record::load_from(OWNER_KEY)? {
            require_completed_pool(
                windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                OWNER_KEY,
            )?;
            return Ok(Some(record.codex_home));
        }
        use windows_sys::Win32::NetworkManagement::NetManagement::*;
        for name in [crate::OFFLINE_USERNAME, crate::ONLINE_USERNAME] {
            let mut info = std::ptr::null_mut();
            let status = unsafe {
                NetUserGetInfo(
                    std::ptr::null(),
                    crate::to_wide(WindowsSandboxProduct::Console.name(name).as_ref()).as_ptr(),
                    /*level*/ 0,
                    &mut info,
                )
            };
            if !info.is_null() {
                unsafe { NetApiBufferFree(info.cast()) };
            }
            ensure!(
                status == NERR_UserNotFound,
                "MXC cannot protect unregistered Console credentials (account query: {status}); run explicit `mcp-console-sandbox setup` with the existing legacy state directory"
            );
        }
        Ok(None)
    }

    pub(crate) fn owner(state: &Path) -> Result<crate::installation_record::InstallationRecord> {
        let record = crate::installation_record::load_from(OWNER_KEY)?.context(
            "Console proxy ownership is not provisioned; run `mcp-console-sandbox setup`",
        )?;
        ensure!(
            record.codex_home == std::fs::canonicalize(state)?,
            "Console proxy pool belongs to a different state directory"
        );
        Ok(record)
    }

    /// Explicitly provision the complete pool with one UAC request.
    pub fn provision_pool(request: crate::SandboxSetupRequest<'_>) -> Result<()> {
        ensure!(
            WindowsSandboxProduct::current() == WindowsSandboxProduct::Console
                && Self::current().is_none(),
            "Console pool setup requires the base Console identity"
        );
        if crate::installation_record::load_from(OWNER_KEY)?.is_some() {
            Self::validate_owner(request.codex_home)?;
        }
        for index in 0..Self::COUNT {
            let state = request
                .codex_home
                .join("proxy-slots")
                .join(index.to_string());
            std::fs::create_dir_all(crate::sandbox_bin_dir(&state))?;
        }
        crate::setup::run_elevated_setup_inner(
            request,
            /*offline_proxy_settings_override*/ None,
            crate::setup::SetupScope::ConsoleProxyPool,
        )
    }

    pub(crate) fn verify_completion(state: &Path, nonce: &str) -> Result<()> {
        ensure!(
            std::fs::read(crate::sandbox_secrets_dir(state).join(COMPLETION_FILE))
                .ok()
                .as_deref()
                == Some(nonce.as_bytes()),
            "Console proxy setup helper did not confirm this pool request; replace adjacent Console helpers and run explicit setup again"
        );
        Ok(())
    }

    pub(crate) fn check_setup_exit(
        self,
        base: &Path,
        status: std::process::ExitStatus,
    ) -> Result<()> {
        if status.success() {
            return Ok(());
        }
        let child = base.join("proxy-slots").join(self.index().to_string());
        let (code, detail) = match crate::read_setup_error_report(&child) {
            Ok(Some(report)) => (report.code, report.message),
            Ok(None) => (
                crate::SetupErrorCode::OrchestratorHelperExitNonzero,
                "helper did not write a setup error report".to_owned(),
            ),
            Err(error) => (
                crate::SetupErrorCode::OrchestratorHelperReportReadFailed,
                error.to_string(),
            ),
        };
        let report = crate::SetupErrorReport {
            code,
            message: format!(
                "Console proxy slot {} provisioning failed ({status}); inspect {}: {detail}",
                self.index(),
                crate::setup_error_path(&child).display(),
            ),
        };
        crate::write_setup_error_report(base, &report)?;
        Err(crate::SetupFailure::from_report(report).into())
    }

    pub(crate) fn provision_owner(base: &Path, real_user: &str) -> Result<()> {
        let base = std::fs::canonicalize(base)?;
        let user_sid = crate::string_from_sid_bytes(&crate::resolve_sid(real_user)?)
            .map_err(anyhow::Error::msg)?;
        if let Some(record) = crate::installation_record::load_from(OWNER_KEY)? {
            ensure!(
                record.user_sid == user_sid && record.codex_home == base,
                "Console proxy pool belongs to a different user or state directory; preserve its lease records"
            );
            return Ok(());
        }
        use windows_sys::Win32::System::Registry::*;
        let mut key = 0;
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                crate::to_wide(OWNER_KEY).as_ptr(),
                /*reserved*/ 0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        ensure!(
            status == 0,
            "create Console proxy ownership record: {status}"
        );
        unsafe { RegCloseKey(key) };
        crate::installation_record::save_to(
            OWNER_KEY,
            &crate::installation_record::InstallationRecord {
                user_sid,
                codex_home: base,
                session_id: 0,
                desktop_installation: None,
                runtime: None,
            },
        )
    }

    pub(crate) fn helper_argument(self) -> String {
        format!("--console-proxy-slot={}", self.0)
    }

    /// Helpers take this only from their trusted invocation, never the target environment.
    pub fn initialize_helper() -> Result<()> {
        WindowsSandboxProduct::Console.initialize()?;
        if let Some(argument) = std::env::args()
            .find_map(|arg| arg.strip_prefix("--console-proxy-slot=").map(str::to_owned))
        {
            Self::new(argument.parse()?)?.initialize()?;
        }
        Ok(())
    }

    pub(crate) fn name<'a>(self, name: &'a str) -> Cow<'a, str> {
        match name {
            "codex-windows-sandbox-setup.exe" | "codex-command-runner.exe" => {
                WindowsSandboxProduct::Console.name(name)
            }
            "CodexSandboxOffline" => Cow::Owned(format!("McpConsoleProxyOff{}", self.0)),
            "CodexSandboxOnline" => Cow::Owned(format!("McpConsoleProxyOn{}", self.0)),
            _ => Cow::Owned(
                name.replace("Codex", &format!("ConsoleP{}", self.0))
                    .replace("codex", &format!("console_p{}", self.0)),
            ),
        }
    }
}

#[cfg(test)]
#[path = "console_proxy_slot_tests.rs"]
mod tests;
