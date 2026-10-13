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
