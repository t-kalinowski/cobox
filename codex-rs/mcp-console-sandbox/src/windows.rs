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
        .nth(1)
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
    let configured = codex_windows_sandbox::check_sandbox_setup(state_dir.as_path())?;
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
        println!(
            "{}",
            serde_json::json!({
                "state_dir": state_dir,
                "configured": configured,
                "helpers_available": helpers_available,
                "offline_account": "McpConsoleSandboxOff",
                "online_account": "McpConsoleSandboxOn",
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
    if !configured {
        // Create the helper directory as the caller, before UAC. Its owner
        // must be able to refresh the protected DACL on ordinary launches.
        std::fs::create_dir_all(codex_windows_sandbox::sandbox_bin_dir(state_dir.as_path()))
            .context("create caller-owned sandbox helper directory")?;
        let permissions = ResolvedWindowsSandboxPermissions::try_from_permission_profile(
            &PermissionProfile::read_only(),
        )?;
        codex_windows_sandbox::run_elevated_setup(SandboxSetupRequest {
            permissions: &permissions,
            command_cwd: state_dir.as_path(),
            env_map: &HashMap::new(),
            codex_home: state_dir.as_path(),
            proxy_enforced: false,
        })?;
    }
    if !codex_windows_sandbox::check_sandbox_setup(state_dir.as_path())? {
        bail!("sandbox setup did not produce current records and enabled accounts");
    }
    println!("Console sandbox is configured at {}", state_dir.display());
    Ok(0)
}
