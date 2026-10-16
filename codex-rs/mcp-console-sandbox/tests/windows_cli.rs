#![cfg(windows)]

#[path = "windows_mxc_support/mod.rs"]
mod mxc_support;

use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::process::Command;

#[test]
fn unicode_environment_duplicates_are_rejected_before_native_setup() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = json!({
        "extends": ":read-only",
        "environment": {"Å_VALUE": "first", "å_VALUE": "second"},
        "lifecycle": {
            "cleanup_timeout_ms": 100,
            "private_tmp": {"parent": root.path(), "environment": ["TMPDIR"]}
        }
    });
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .env("CONSOLE_POLICY", config.to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--", "cmd.exe"])
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
    let diagnostic = String::from_utf8(output.stderr)?;
    assert!(
        diagnostic.contains("duplicate Windows environment variable"),
        "{diagnostic}"
    );
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn transport_export_collisions_are_rejected_before_native_setup() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    for (host_name, selected_name, export_name) in [
        ("Å_POLICY", "å_POLICY", "Å_POLICY"),
        ("CONSOLE_POLICY", "console_policy", "CONSOLE_POLICY"),
        (
            "CONSOLE_POLICY",
            "CONSOLE_POLICY",
            "mcp_console_sandbox_config",
        ),
    ] {
        let config = json!({
            "extends": ":read-only",
            "lifecycle": {
                "cleanup_timeout_ms": 100,
                "private_tmp": {"parent": root.path(), "environment": [export_name]}
            }
        });
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(host_name, config.to_string())
            .args(["--config-env", selected_name, "--", "cmd.exe"])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let diagnostic = String::from_utf8(output.stderr)?;
        assert!(
            diagnostic.contains("configuration transport variable cannot be exported"),
            "{export_name}: {diagnostic}"
        );
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn unicode_environment_overrides_and_transport_exclusions_are_applied() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    for inherit in [false, true] {
        let config = json!({
            "extends": ":read-only",
            "network": "enabled",
            "inherit_environment": inherit,
            "environment": {
                "å_VALUE": "target-value",
                "Å_POLICY": "must not reach the target",
                "å_PRIVATE": "target-private",
                "mcp_console_sandbox_config": "must not reach the target"
            },
            "lifecycle": {
                "private_tmp": {"parent": root.path(), "environment": ["Å_PRIVATE"]}
            }
        });
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env("Å_VALUE", "host-value")
            .env("Å_PRIVATE", "host-private")
            .env("Å_POLICY", config.to_string())
            .args(["--config-env", "å_POLICY", "--"])
            .arg(cargo_bin("mcp-console-sandbox-fixture")?)
            .arg("context")
            .output()?;
        assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
        let context: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let environment = context["environment"].as_object().unwrap();
        assert_eq!(environment["å_VALUE"], "target-value");
        assert!(!environment.contains_key("Å_VALUE"));
        assert!(!environment.contains_key("Å_POLICY"));
        assert!(!environment.contains_key("å_POLICY"));
        assert!(!environment.contains_key("mcp_console_sandbox_config"));
        assert!(!environment.contains_key("å_PRIVATE"));
        let private = std::path::Path::new(environment["Å_PRIVATE"].as_str().unwrap());
        assert_eq!(private.file_name().unwrap(), "data");
        assert!(private.starts_with(root.path()));
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn inherited_drive_directory_metadata_does_not_prevent_launch() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let sandbox = cargo_bin("mcp-console-sandbox")?;
    let fixture = cargo_bin("mcp-console-sandbox-fixture")?;
    let policy = json!({
        "extends": ":read-only",
        "network": "enabled",
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
