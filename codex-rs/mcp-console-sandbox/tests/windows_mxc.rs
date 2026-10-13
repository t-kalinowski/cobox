#![cfg(windows)]

use anyhow::Result;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_sandboxing::*;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::process::Command;

fn proxy(allow_local_binding: bool, allow_destination: bool) -> Value {
    json!({"enabled":true,"enableSocks5":true,"enableSocks5Udp":false,
        "allowUpstreamProxy":false,"dangerouslyAllowAllUnixSockets":false,"mode":"full",
        "domains":{"127.0.0.1":if allow_destination {"allow"} else {"deny"}},
        "allowLocalBinding":allow_local_binding})
}

#[test]
fn public_backend_selection_preserves_legacy_ownership_without_provisioning() -> Result<()> {
    let root = tempfile::tempdir()?;
    let accounts = ["McpConsoleSandboxOff", "McpConsoleSandboxOn"]
        .into_iter()
        .map(codex_windows_sandbox::local_user_flags)
        .collect::<Result<Vec<_>>>()?;
    let available = accounts.iter().all(Option::is_none) && windows_mxc_available();
    for (mode, strict_proxy) in [
        (None, false),
        (Some("auto"), false),
        (Some("mxc"), false),
        (Some("auto"), true),
        (Some("mxc"), true),
    ] {
        let mut policy = json!({"extends":":read-only","network":"restricted",
            "windows_state_dir":root.path().join("unprovisioned")});
        if let Some(mode) = mode {
            policy["windows_sandbox_level"] = json!(mode);
        }
        if strict_proxy {
            policy["proxy"] = proxy(
                /*allow_local_binding*/ false, /*allow_destination*/ true,
            );
        }
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env("CONSOLE_POLICY", policy.to_string())
            .args([
                "--config-env",
                "CONSOLE_POLICY",
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "if defined CONSOLE_POLICY (exit /b 42) else echo MXC_OK",
            ])
            .output()?;
        if available && !strict_proxy {
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (Some(0), b"MXC_OK\r\n".to_vec(), vec![])
            );
        } else {
            assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
            let diagnostic = String::from_utf8(output.stderr)?;
            let expected = if mode == Some("mxc") {
                "MXC"
            } else if strict_proxy {
                "legacy Windows sandbox"
            } else {
                "mcp-console-sandbox setup"
            };
            assert!(diagnostic.contains(expected), "{diagnostic}");
        }
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    let strict = serde_json::from_value(proxy(
        /*allow_local_binding*/ false, /*allow_destination*/ true,
    ))?;
    assert_eq!(
        select_windows_sandbox(
            WindowsSandboxPreference::Auto,
            &PermissionProfile::read_only(),
            Some(&strict),
            /*host_mxc_restriction*/ None
        )?,
        (
            SandboxType::WindowsRestrictedToken,
            WindowsSandboxLevel::Elevated
        )
    );
    assert!(
        select_windows_sandbox(
            WindowsSandboxPreference::Mxc,
            &PermissionProfile::read_only(),
            Some(&strict),
            /*host_mxc_restriction*/ None
        )
        .unwrap_err()
        .to_string()
        .contains("allow_local_binding=false")
    );
    Ok(())
}

#[test]
fn managed_proxy_rejects_configuration_transport_collisions_before_launch() -> Result<()> {
    let root = tempfile::tempdir()?;
    for name in [
        "hTtP_pRoXy",
        "NoDe_UsE_EnV_PrOxY",
        "CoDeX_NeTwOrK_PrOxY_AtTrIbUtIoN",
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(
                name,
                json!({"extends":":read-only", "windows_sandbox_level":"mxc",
                    "windows_state_dir":root.path().join("state"),
                    "proxy":proxy(/*allow_local_binding*/ true, /*allow_destination*/ true)})
                .to_string(),
            )
            .args([
                "--config-env",
                name,
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "echo launched",
            ])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let diagnostic = String::from_utf8(output.stderr)?;
        assert!(
            diagnostic.contains("configuration transport conflicts with managed proxy environment"),
            "{diagnostic}"
        );
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn mxc_does_not_validate_unused_legacy_setup_records() -> Result<()> {
    let root = tempfile::tempdir()?;
    let secrets = root.path().join(".sandbox-secrets");
    std::fs::create_dir(&secrets)?;
    let users = secrets.join("sandbox_users.json");
    let foreign = json!({"version":0,
        "offline":{"username":"CodexSandboxOffline","password":""},
        "online":{"username":"CodexSandboxOnline","password":""}})
    .to_string();
    std::fs::write(&users, &foreign)?;
    let accounts = ["McpConsoleSandboxOff", "McpConsoleSandboxOn"]
        .into_iter()
        .map(codex_windows_sandbox::local_user_flags)
        .collect::<Result<Vec<_>>>()?;
    let available = accounts.iter().all(Option::is_none) && windows_mxc_available();
    for mode in ["mxc", "elevated"] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(
                "CONSOLE_POLICY",
                json!({"extends":":read-only", "windows_sandbox_level":mode,
                    "windows_state_dir":root.path()})
                .to_string(),
            )
            .args([
                "--config-env",
                "CONSOLE_POLICY",
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "echo MXC_OK",
            ])
            .output()?;
        if mode == "mxc" && available {
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (Some(0), b"MXC_OK\r\n".to_vec(), vec![])
            );
        } else {
            assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
            let diagnostic = String::from_utf8(output.stderr)?;
            let expected = if mode == "elevated" {
                "sandbox state belongs to a different product"
            } else if accounts.iter().any(Option::is_some) {
                "legacy Console sandbox accounts exist"
            } else {
                "MXC is unavailable"
            };
            assert!(diagnostic.contains(expected), "{diagnostic}");
        }
        assert_eq!(std::fs::read_to_string(&users)?, foreign);
        assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
        assert_eq!(std::fs::read_dir(&secrets)?.count(), 1);
    }
    Ok(())
}
