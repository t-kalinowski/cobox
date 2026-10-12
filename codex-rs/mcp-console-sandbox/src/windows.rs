//! Standalone Windows commands; security and provisioning stay in the shared backend.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::ResolvedWindowsSandboxPermissions;
use codex_windows_sandbox::SandboxSetupRequest;
use codex_windows_sandbox::WindowsSandboxProduct;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::windows_cli::Action;
use crate::windows_cli::Cli;

pub(crate) fn run() -> Result<i32> {
    if std::env::args_os()
        .nth(/*n*/ 1)
        .is_some_and(|arg| arg == codex_sandboxing::CODEX_WINDOWS_MXC_ARG1)
    {
        codex_sandboxing::run_windows_mxc_main();
    }
    if std::env::args_os()
        .nth(/*n*/ 1)
        .is_some_and(|arg| arg == "--config-env")
    {
        return crate::windows_console::run();
    }
    let cli = Cli::parse();
    WindowsSandboxProduct::Console.initialize()?;
    let state_dir = match cli.state_dir {
        Some(path) => path,
        None => AbsolutePathBuf::from_absolute_path_checked(
            PathBuf::from(
                std::env::var_os("LOCALAPPDATA")
                    .context("LOCALAPPDATA is unavailable; pass --state-dir")?,
            )
            .join("mcp-console"),
        )?,
    };
    let _configuration = if matches!(cli.action, Action::Setup) {
        Some(crate::windows_proxy::configuration_guard()?)
    } else {
        None
    };
    if matches!(cli.action, Action::Setup) {
        for index in 0..codex_windows_sandbox::ConsoleProxySlot::COUNT {
            anyhow::ensure!(
                !state_dir
                    .as_path()
                    .join(".sandbox-secrets")
                    .join(format!("proxy-slot-{index}.lease"))
                    .exists(),
                "proxy slot {index} is leased or quarantined; setup cannot replace an unretired workload"
            );
        }
    }
    let settings = codex_windows_sandbox::WindowsSandboxProvisioningSettings::default();
    let configured = codex_windows_sandbox::check_sandbox_setup(state_dir.as_path())?
        && codex_windows_sandbox::sandbox_setup_is_complete_with_settings(
            state_dir.as_path(),
            &settings,
        );
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .context("executable has no parent directory")?;
    let helpers_available = [
        "mcp-console-sandbox-setup.exe",
        "mcp-console-sandbox-runner.exe",
    ]
    .iter()
    .all(|name| directory.join(name).is_file());
    if matches!(cli.action, Action::Status) {
        let (mut filesystem, network) = PermissionProfile::read_only().to_runtime_permissions();
        let mxc_state_protection =
            crate::windows_proxy::protect_state(&mut filesystem, state_dir.as_path());
        let mxc_available = mxc_state_protection.is_ok()
            && codex_sandboxing::windows_mxc_available_for(
                &PermissionProfile::from_runtime_permissions(&filesystem, network),
            );
        println!(
            "{}",
            serde_json::json!({
                "state_dir": state_dir,
                "configured": configured,
                "mxc_available": mxc_available,
                "mxc_state_error": mxc_state_protection.err().map(|error| error.to_string()),
                "helpers_available": helpers_available,
                "managed_proxy_provisioned": std::fs::read(crate::windows_proxy::pool_marker(state_dir.as_path())).ok().as_deref() == Some(b"1\n")
                    && codex_windows_sandbox::ConsoleProxySlot::validate_owner(state_dir.as_path()).is_ok(),
                "offline_account": codex_windows_sandbox::sandbox_name("CodexSandboxOffline"),
                "online_account": codex_windows_sandbox::sandbox_name("CodexSandboxOnline"),
            })
        );
        return Ok(if configured && helpers_available {
            0
        } else {
            1
        });
    }
    if !helpers_available {
        bail!(
            "setup requires adjacent mcp-console-sandbox-setup.exe and mcp-console-sandbox-runner.exe"
        );
    }
    if matches!(cli.action, Action::Setup) {
        // Create the helper directory as the caller, before UAC. Its owner
        // must be able to refresh the protected DACL on ordinary launches.
        std::fs::create_dir_all(codex_windows_sandbox::sandbox_bin_dir(state_dir.as_path()))
            .context("create caller-owned sandbox helper directory")?;
        let permissions = ResolvedWindowsSandboxPermissions::try_from_permission_profile(
            &PermissionProfile::read_only(),
        )?;
        let request = SandboxSetupRequest {
            permissions: &permissions,
            command_cwd: state_dir.as_path(),
            env_map: &HashMap::new(),
            codex_home: state_dir.as_path(),
            proxy_enforced: false,
        };
        let marker = crate::windows_proxy::pool_marker(state_dir.as_path());
        if marker.exists() {
            std::fs::remove_file(&marker)?;
        }
        codex_windows_sandbox::ConsoleProxySlot::provision_pool(request)?;
        std::fs::write(marker, b"1\n")?;
    }
    if !codex_windows_sandbox::check_sandbox_setup(state_dir.as_path())? {
        bail!("sandbox setup did not produce current records and enabled accounts");
    }
    println!("Console sandbox is configured at {}", state_dir.display());
    Ok(0)
}
