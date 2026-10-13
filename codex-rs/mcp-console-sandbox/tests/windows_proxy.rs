#![cfg(windows)]

use anyhow::Context;
use anyhow::Result;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

#[path = "../src/windows_proxy_lock.rs"]
mod windows_proxy_lock;

#[path = "windows_proxy/smoke_tests.rs"]
mod smoke;

#[test]
fn legacy_environment_admission_observes_the_setup_barrier() -> anyhow::Result<()> {
    use codex_utils_cargo_bin::cargo_bin;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::process::Command;
    let state = tempfile::tempdir()?;
    std::fs::create_dir(state.path().join(".sandbox-secrets"))?;
    let guard = windows_proxy_lock::configuration_guard(state.path())?;
    let mut command = Command::new(cargo_bin("mcp-console-sandbox")?);
    let policy = json!({"extends":":read-only", "network":"restricted",
        "windows_sandbox_level":"elevated", "windows_state_dir":state.path()});
    command
        .env("CONSOLE_POLICY", policy.to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(cargo_bin("mcp-console-sandbox-fixture")?)
        .arg("context");
    let blocked = command.output()?;
    assert_eq!((blocked.status.code(), blocked.stdout), (Some(1), vec![]));
    assert!(String::from_utf8(blocked.stderr)?.contains("setup or admission is in progress"));
    drop(guard);
    let unprovisioned = command.output()?;
    assert_eq!(
        (unprovisioned.status.code(), unprovisioned.stdout),
        (Some(1), vec![])
    );
    let error = String::from_utf8(unprovisioned.stderr)?;
    assert!(
        error.contains("Windows sandbox setup is required"),
        "{error}"
    );
    assert!(
        !error.contains("setup or admission is in progress"),
        "{error}"
    );
    Ok(())
}

#[test]
fn managed_proxy_rejects_transport_name_collisions_before_launch() -> Result<()> {
    let root = tempfile::tempdir()?;
    for name in [
        "hTtP_pRoXy",
        "NoDe_UsE_EnV_PrOxY",
        "CoDeX_NeTwOrK_PrOxY_AtTrIbUtIoN",
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(name, json!({
                "extends": ":read-only", "proxy": proxy(),
                "windows_sandbox_level": "elevated", "windows_state_dir": root.path().join("state")
            }).to_string())
            .args(["--config-env", name, "--", "cmd.exe", "/d", "/c", "echo launched"])
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

fn proxy() -> Value {
    json!({
        "enabled": true, "enableSocks5": true, "enableSocks5Udp": false,
        "allowUpstreamProxy": false, "dangerouslyAllowAllUnixSockets": false,
        "mode": "full", "domains": {"127.0.0.1": "allow", "localhost": "allow"}, "allowLocalBinding": false,
    })
}

#[test]
fn proxy_capabilities_and_provisioning_are_checked_before_launch() -> Result<()> {
    let root = tempfile::tempdir()?;
    for (overrides, level, diagnostic) in [
        (
            json!({"enableSocks5Udp": true}),
            "elevated",
            "SOCKS5 UDP is not supported",
        ),
        (
            json!({"unixSockets": {"C:\\socket": "allow"}}),
            "elevated",
            "Unix sockets are not supported",
        ),
        (
            json!({"unixSockets": {"C:\\socket": "deny"}}),
            "elevated",
            "Unix sockets are not supported",
        ),
        (
            json!({"dangerouslyAllowAllUnixSockets": true}),
            "elevated",
            "Unix sockets are not supported",
        ),
        (
            json!({}),
            "unelevated",
            "managed proxy requires MXC or the elevated Windows sandbox",
        ),
        (
            json!({}),
            "elevated",
            "proxy setup is required; run `mcp-console-sandbox setup`",
        ),
    ] {
        let mut policy = proxy();
        policy
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().unwrap().clone());
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(
                "CONSOLE_POLICY",
                json!({
                    "extends": ":read-only", "network": "enabled", "proxy": policy,
                    "windows_sandbox_level": level, "windows_state_dir": root.path().join("state"),
                })
                .to_string(),
            )
            .args([
                "--config-env",
                "CONSOLE_POLICY",
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "echo launched",
            ])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[path = "windows_proxy/support.rs"]
mod support;
use support::*;
#[path = "windows_proxy/mxc_tests.rs"]
mod mxc;
#[path = "windows_proxy/network_tests.rs"]
mod network;
