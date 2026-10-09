#![cfg(windows)]

use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::process::Command;

#[test]
fn inherited_drive_directory_metadata_does_not_prevent_launch() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let sandbox = cargo_bin("mcp-console-sandbox")?;
    let fixture = cargo_bin("mcp-console-sandbox-fixture")?;
    let policy = json!({
        "extends": ":read-only",
        "network": "enabled",
        "windows_sandbox_level": "unelevated",
        "windows_state_dir": root.path().join("state"),
    });
    // Windows callers can carry per-drive working directories as hidden entries.
    let output = Command::new(&sandbox)
        .current_dir(root.path())
        .env("=C:", root.path())
        .env("CONSOLE_POLICY", policy.to_string())
        .env("CONSOLE_INHERITED", "retained")
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(&fixture)
        .arg("context")
        .output()?;
    assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
    let context: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(context["environment"]["CONSOLE_INHERITED"], "retained");
    assert!(context["environment"].get("CONSOLE_POLICY").is_none());
    assert!(
        context["environment"]
            .as_object()
            .unwrap()
            .keys()
            .all(|name| !name.starts_with('='))
    );

    let mut invalid = policy;
    invalid["environment"] = json!({"=C:": root.path()});
    let output = Command::new(sandbox)
        .env("CONSOLE_POLICY", invalid.to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(fixture)
        .arg("context")
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
    assert!(String::from_utf8(output.stderr)?.contains("invalid target environment name"));
    Ok(())
}

#[test]
fn invalid_state_path_fails_before_creating_state() -> anyhow::Result<()> {
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .args(["status", "--state-dir", "relative"])
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(2), vec![]));
    assert!(String::from_utf8(output.stderr)?.contains("path is not absolute"));
    Ok(())
}
