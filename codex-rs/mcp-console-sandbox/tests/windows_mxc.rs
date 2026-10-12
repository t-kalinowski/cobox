#![cfg(windows)]

use anyhow::Result;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::process::Command;

#[test]
fn mxc_selection_at_the_environment_boundary_does_not_provision() -> Result<()> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("unprovisioned");
    let status = Command::new(cargo_bin("mcp-console-sandbox")?)
        .args(["--state-dir", state.to_str().unwrap(), "status"])
        .output()?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    let available = status["mxc_available"].as_bool().expect("MXC capability");
    for selection in [None, Some("auto"), Some("mxc")] {
        let mut config = json!({"extends": ":read-only", "network": "restricted",
            "windows_state_dir": state,
            "environment": {"CoDeX_HoMe": root.path().join("workload-home")}});
        if let Some(selection) = selection {
            config["windows_sandbox_level"] = json!(selection);
        }
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env("CONSOLE_POLICY", config.to_string())
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
        if available {
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (Some(0), b"MXC_OK\r\n".to_vec(), vec![])
            );
        } else {
            assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
            let diagnostic = String::from_utf8(output.stderr)?;
            assert!(
                if selection == Some("mxc") {
                    diagnostic.contains("MXC is unavailable")
                        || diagnostic.contains("MXC cannot enforce")
                } else {
                    diagnostic.contains("mcp-console-sandbox setup")
                },
                "{diagnostic}"
            );
        }
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn explicit_mxc_rejects_incompatible_network_policy_before_launch() -> Result<()> {
    let root = tempfile::tempdir()?;
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .env(
            "CONSOLE_POLICY",
            json!({"extends": ":read-only", "network": "restricted",
            "windows_sandbox_level": "mxc", "windows_state_dir": root.path().join("state"),
            "proxy": {"enabled": true, "enableSocks5": true, "enableSocks5Udp": false,
                "allowUpstreamProxy": false, "dangerouslyAllowAllUnixSockets": false,
                "mode": "full", "domains": {"localhost": "allow"}, "allowLocalBinding": false}})
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
    let diagnostic = String::from_utf8(output.stderr)?;
    assert!(
        diagnostic.contains("allow_local_binding=false"),
        "{diagnostic}"
    );
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn mxc_rejects_grants_that_reopen_control_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    for grant in [
        json!({"filesystem":{"kind":"restricted","entries":[
            {"path":{"type":"path","path":state.join(".sandbox-secrets/canary")},"access":"write"}
        ]}}),
        json!({"filesystem":{"kind":"restricted","entries":[
        {"path":{"type":"special","value":{"kind":"tmpdir"}},"access":"write"}
    ]},"environment":{"tEmP":state.join("private")}}),
    ] {
        let mut policy = json!({"extends":":read-only","network":"restricted",
            "windows_sandbox_level":"mxc","windows_state_dir":state});
        policy
            .as_object_mut()
            .unwrap()
            .extend(grant.as_object().unwrap().clone());
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env("CONSOLE_POLICY", policy.to_string())
            .args([
                "--config-env",
                "CONSOLE_POLICY",
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "echo escaped",
            ])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let diagnostic = String::from_utf8(output.stderr)?;
        assert!(
            diagnostic.contains("must not reopen Console control state")
                || diagnostic.contains("MXC is unavailable")
                || diagnostic.contains("MXC cannot"),
            "{diagnostic}"
        );
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn mxc_rejects_junction_grants_and_cleans_prelaunch_storage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    let alias = root.path().join("alias");
    let temporary = root.path().join("private");
    std::fs::create_dir(&state)?;
    std::fs::create_dir(&temporary)?;
    std::fs::write(state.join("canary"), b"not a credential")?;
    let link = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&alias)
        .arg(&state)
        .output()?;
    assert!(link.status.success(), "junction positive control: {link:?}");
    assert!(std::fs::File::open(alias.join("canary")).is_ok());
    for child in ["canary", "not-created-yet/child"] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(
                "CONSOLE_POLICY",
                json!({"extends":":read-only","network":"restricted",
                    "windows_sandbox_level":"mxc","windows_state_dir":state,
                    "filesystem":{"kind":"restricted","entries":[
                        {"path":{"type":"path","path":alias.join(child)},"access":"read"}
                    ]},"lifecycle":{"private_tmp":{"parent":temporary,"environment":["TEMP"]}}
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
                "echo escaped",
            ])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let diagnostic = String::from_utf8(output.stderr)?;
        assert!(
            diagnostic.contains("must not reopen Console control state")
                || diagnostic.contains("MXC is unavailable")
                || diagnostic.contains("MXC cannot"),
            "{diagnostic}"
        );
        assert_eq!(std::fs::read_dir(&temporary)?.count(), 0);
    }
    std::fs::remove_dir(&alias)?;
    Ok(())
}

#[test]
fn mxc_rejects_drive_root_control_state() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let volume = cwd.ancestors().last().unwrap();
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .env(
            "CONSOLE_POLICY",
            json!({"extends":":read-only","network":"restricted",
            "windows_sandbox_level":"mxc","windows_state_dir":volume})
            .to_string(),
        )
        .args([
            "--config-env",
            "CONSOLE_POLICY",
            "--",
            "cmd.exe",
            "/d",
            "/c",
            "echo escaped",
        ])
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
    let diagnostic = String::from_utf8(output.stderr)?;
    assert!(
        diagnostic.contains("drive-root")
            || diagnostic.contains("unregistered Console credentials"),
        "{diagnostic}"
    );
    Ok(())
}
