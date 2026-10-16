#![cfg(windows)]

#[path = "windows_mxc_support/mod.rs"]
mod mxc_support;

use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::process::Command;

#[test]
fn unsupported_policy_fails_before_launch_or_state_creation() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    for (overrides, diagnostic) in [
        (
            json!({"proxy":{
                "enabled":true,"enableSocks5":true,"enableSocks5Udp":false,
                "allowUpstreamProxy":false,"dangerouslyAllowAllUnixSockets":false,
                "mode":"full","domains":null,"unixSockets":null,"allowLocalBinding":false
            }}),
            "allow_local_binding=false",
        ),
        (
            json!({"linux_backend":"bubblewrap"}),
            "linux_backend is supported only",
        ),
        (
            json!({"macos_seatbelt_profile_extension":"(allow default)"}),
            "supported only on macOS",
        ),
        (
            json!({"lifecycle":{"cleanup_timeout_ms":100}}),
            "cleanup_timeout_ms is not configurable",
        ),
        (
            json!({"lifecycle":{"private_tmp":{"parent":root.path(),"environment":["console_policy"]}}}),
            "transport variable cannot be exported",
        ),
        (
            json!({"environment":{"CASE_VALUE":"one","case_value":"two"}}),
            "duplicate Windows environment variable",
        ),
    ] {
        let mut config = json!({
            "extends":":read-only", "network":"enabled",

        });
        if let (Some(config), Some(overrides)) = (config.as_object_mut(), overrides.as_object()) {
            config.extend(overrides.clone());
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
                "echo launched",
            ])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains(diagnostic), "{overrides}: {stderr}");
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn root_exit_does_not_wait_for_caller_stdin_eof() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    use std::os::windows::io::AsRawHandle;
    use std::process::Stdio;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let root = tempfile::tempdir()?;
    let config = json!({
        "extends": ":read-only", "network": "enabled",

        "lifecycle": {"private_tmp": {"parent": root.path(), "environment": ["TMPDIR"]}},
    });
    for code in [0i32, 125, -1, -1_073_741_819] {
        let mut child = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env("CONSOLE_POLICY", config.to_string())
            .args([
                "--config-env",
                "CONSOLE_POLICY",
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "exit",
            ])
            .arg(code.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let finished = unsafe { WaitForSingleObject(child.as_raw_handle(), 10_000) };
        if finished != WAIT_OBJECT_0 {
            child.kill()?;
        }
        let output = child.wait_with_output()?;
        assert_eq!(
            finished, WAIT_OBJECT_0,
            "runner waited for caller stdin EOF"
        );
        assert_eq!(
            (output.status.code(), output.stdout, output.stderr),
            (Some(code), vec![], vec![])
        );
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn console_configuration_runs_with_private_storage() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let config = json!({
        "extends": ":read-only",
        "network": "enabled",

        "environment": { "test_case_value": "target" },
        "lifecycle": { "private_tmp": { "parent": root.path(), "environment": ["TMPDIR", "TEMP", "TMP"] } },
    });
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .current_dir(root.path())
        .env("CONSOLE_POLICY", config.to_string())
        .env("TEST_CASE_VALUE", "host")
        .args(["--config-env", "CONSOLE_POLICY", "--", "cmd.exe", "/d", "/c",
               "echo works>%TMPDIR%\\result.txt&type %TMPDIR%\\result.txt&echo %TEST_CASE_VALUE%&if defined CONSOLE_POLICY exit /b 42"])
        .output()?;
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"works\r\ntarget\r\n".to_vec(), vec![])
    );
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn target_environment_is_applied_after_mxc_setup() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let temporary = root.path().join("caller-temp");
    std::fs::create_dir(&temporary)?;
    let configured = json!({
        "TMPDIR": temporary,
        "Temp": temporary,
        "tMp": temporary,
        "LOCALAPPDATA": "target-local-data",
        "SystemDrive": "target-system-drive",
        "CONSOLE_UNICODE": "日本語🧊".repeat(5000),
    });
    for (inherit, expected) in [
        (false, json!({})),
        (false, configured.clone()),
        (true, configured),
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .current_dir(root.path())
            .env("CONSOLE_HOST_ONLY", "must not reach a cleared workload")
            .env(
                "CONSOLE_POLICY",
                json!({
                    "extends": ":read-only", "network": "enabled",
                    "inherit_environment": inherit, "environment": expected,
                })
                .to_string(),
            )
            .args(["--config-env", "CONSOLE_POLICY", "--"])
            .arg(cargo_bin("mcp-console-sandbox-fixture")?)
            .arg("context")
            .output()?;
        assert_eq!(
            (output.status.code(), output.stderr),
            (Some(0), vec![]),
            "inherit_environment={inherit}"
        );
        let context: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let environment = context["environment"].as_object().unwrap();
        for (name, value) in expected.as_object().unwrap() {
            assert_eq!(environment.get(name), Some(value), "{name}");
        }
        assert!(environment.keys().all(|name| {
            name != "CONSOLE_POLICY" && !name.starts_with("CODEX_SANDBOX_LAUNCH_")
        }));
        if !inherit {
            assert_eq!(environment, expected.as_object().unwrap());
        }
    }
    Ok(())
}

#[test]
fn environment_transport_preserves_target_arguments() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let arguments = [
        "--target-option",
        "--help",
        "--other-option",
        "",
        "two words",
        "quote\"inside",
        "trailing\\",
        "日本語",
    ];
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .current_dir(root.path())
        .env(
            "CONSOLE_POLICY",
            json!({
                "extends": ":read-only", "network": "enabled",

            })
            .to_string(),
        )
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(cargo_bin("mcp-console-sandbox-fixture")?)
        .arg("arguments")
        .args(arguments)
        .output()?;
    assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout)?,
        json!(arguments)
    );
    Ok(())
}

#[test]
fn invalid_configuration_fails_before_creating_state() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    for (payload, diagnostic) in [
        ("not-json".to_owned(), "invalid configuration JSON (Syntax"),
        (
            json!({"unsupported": null}).to_string(),
            "invalid configuration JSON (Data",
        ),
        (
            json!({"extends": ":read-only", "workspace": "relative"}).to_string(),
            "invalid configuration JSON (Data",
        ),
        (
            json!({"extends": ":read-only", "environment": []}).to_string(),
            "invalid configuration JSON (Data",
        ),
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env("LOCALAPPDATA", root.path())
            .env("CONSOLE_POLICY", payload)
            .args(["--config-env", "CONSOLE_POLICY", "--", "cmd.exe"])
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}
