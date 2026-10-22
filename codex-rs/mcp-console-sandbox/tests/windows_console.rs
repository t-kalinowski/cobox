#![cfg(windows)]

#[path = "windows_mxc_support/mod.rs"]
mod mxc_support;

use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::process::Command;

#[test]
fn unsupported_policy_fails_preflight_without_mxc() -> anyhow::Result<()> {
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
            json!({"environment":{"CASE_VALUE":"one","case_value":"two"}}),
            "duplicate Windows environment variable",
        ),
    ] {
        let mut config = json!({
            "extends":":read-only", "network":"enabled",
            "lifecycle":{"private_tmp":{"parent":root.path(),"environment":["TMPDIR"]}},
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
fn private_storage_rejects_configuration_transport_alias() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let config = json!({
        "extends":":read-only", "network":"enabled",
        "lifecycle":{"private_tmp":{"parent":root.path(),"environment":["console_policy"]}},
    });
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .env("CONSOLE_POLICY", config.to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--", "cmd.exe"])
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
    let diagnostic = String::from_utf8(output.stderr)?;
    assert!(
        diagnostic.contains("transport variable cannot be exported"),
        "{diagnostic}"
    );
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
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
                "mcp_console_sandbox_target_stale",
                "must not reach the workload",
            )
            .env("CoDeX_SaNdBoX_LaUnCh_stale", "must not reach the workload")
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
            let name = name.to_ascii_uppercase();
            name != "CONSOLE_POLICY"
                && !name.starts_with("CODEX_SANDBOX_LAUNCH_")
                && !name.starts_with("MCP_CONSOLE_SANDBOX_TARGET_")
        }));
        if !inherit {
            assert_eq!(environment, expected.as_object().unwrap());
        }
    }
    Ok(())
}

#[test]
fn cleared_target_environment_ignores_non_unicode_host_variables() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let invalid = OsString::from_wide(&[0xd800]);
    for (name, value) in [
        (invalid.clone(), OsString::from("host-only")),
        (OsString::from("CONSOLE_NON_UNICODE"), invalid),
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .env(name, value)
            .env(
                "CONSOLE_POLICY",
                json!({
                    "extends": ":read-only", "network": "enabled",
                    "inherit_environment": false,
                })
                .to_string(),
            )
            .args(["--config-env", "CONSOLE_POLICY", "--"])
            .arg(cargo_bin("mcp-console-sandbox-fixture")?)
            .arg("context")
            .output()?;
        assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
        let context: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(context["environment"], json!({}));
    }
    Ok(())
}

#[test]
fn workspace_profile_protects_metadata_without_creating_directories() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    for (name, existing) in [".git", ".agents", ".codex", ".aws", ".claude"]
        .into_iter()
        .flat_map(|name| {
            [false, true]
                .into_iter()
                .map(move |existing| (name, existing))
        })
    {
        let root = tempfile::tempdir()?;
        let metadata = root.path().join(name);
        let target = if existing {
            std::fs::create_dir_all(&metadata)?;
            let target = metadata.join("settings.json");
            std::fs::write(&target, "readable")?;
            target
        } else {
            metadata.clone()
        };
        let config = json!({
            "extends": ":workspace", "workspace": root.path(),
            "workspace_options": {"exclude_tmpdir_env_var": true, "exclude_slash_tmp": true},
        });
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .current_dir(root.path())
            .env("CONSOLE_POLICY", config.to_string())
            .args(["--config-env", "CONSOLE_POLICY", "--"])
            .arg(cargo_bin("mcp-console-sandbox-fixture")?)
            .arg("probe-write")
            .arg(&target)
            .output()?;
        assert_eq!(
            (
                output.status.code(),
                String::from_utf8(output.stdout)?,
                output.stderr
            ),
            (Some(0), "write denied\n".to_owned(), vec![])
        );
        if existing {
            assert_eq!(std::fs::read_to_string(target)?, "readable");
        } else {
            assert!(!metadata.exists());
        }
    }
    Ok(())
}

#[test]
fn workspace_profile_allows_directory_and_descendant_write_overrides() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    for grant in [".claude/settings.json", ".claude"] {
        let root = tempfile::tempdir()?;
        let metadata = root.path().join(".claude");
        std::fs::create_dir(&metadata)?;
        let settings = metadata.join("settings.json");
        let other = metadata.join("other.json");
        std::fs::write(&settings, "readable")?;
        std::fs::write(&other, "readable")?;
        let config = json!({
            "extends": ":workspace", "workspace": root.path(),
            "workspace_options": {"exclude_tmpdir_env_var": true, "exclude_slash_tmp": true},
            "filesystem": {"kind":"restricted","entries":[{
                "path":{"type":"path","path":root.path().join(grant)},"access":"write"
            }]}
        });
        for target in [&settings, &other] {
            let allowed = target == &settings || grant == ".claude";
            let output = Command::new(cargo_bin("mcp-console-sandbox")?)
                .current_dir(root.path())
                .env("CONSOLE_POLICY", config.to_string())
                .args(["--config-env", "CONSOLE_POLICY", "--"])
                .arg(cargo_bin("mcp-console-sandbox-fixture")?)
                .arg("probe-write")
                .arg(target)
                .output()?;
            assert_eq!(
                (
                    output.status.code(),
                    String::from_utf8(output.stdout)?,
                    output.stderr
                ),
                (
                    Some(0),
                    if allowed {
                        "write allowed\n"
                    } else {
                        "write denied\n"
                    }
                    .to_owned(),
                    vec![]
                )
            );
            assert_eq!(
                std::fs::read_to_string(target)?,
                if allowed { "escaped" } else { "readable" }
            );
        }
    }
    Ok(())
}

#[test]
fn tmpdir_grants_use_target_variables_and_preserve_read_only_overrides() -> anyhow::Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let target_tmp = root.path().join("target-temp");
    let readonly = target_tmp.join("readonly");
    let helper_tmp = root.path().join("helper-temp");
    std::fs::create_dir(&target_tmp)?;
    std::fs::create_dir(&readonly)?;
    std::fs::create_dir(&helper_tmp)?;
    std::fs::create_dir(root.path().join("workspace"))?;
    for allowed in [true, false] {
        let mut config = json!({
            "extends": ":workspace", "workspace": root.path().join("workspace"),
            "inherit_environment": false,
            "environment": {"Temp": target_tmp, "tMp": target_tmp},
        });
        if !allowed {
            config["filesystem"] = json!({"kind":"restricted","entries":[{
                "path":{"type":"path","path":readonly},"access":"read"
            }]});
        }
        let marker = format!("target-{allowed}.txt");
        let target_path = if allowed { &target_tmp } else { &readonly }.join(marker);
        for (operation, path, expected_code) in [
            ("write", target_path.clone(), if allowed { 0 } else { 1 }),
            ("probe-write", helper_tmp.join("forbidden.txt"), 0),
        ] {
            let output = Command::new(cargo_bin("mcp-console-sandbox")?)
                .current_dir(root.path())
                .env("TEMP", &helper_tmp)
                .env("TMP", &helper_tmp)
                .env("CONSOLE_POLICY", config.to_string())
                .args(["--config-env", "CONSOLE_POLICY", "--"])
                .arg(cargo_bin("mcp-console-sandbox-fixture")?)
                .arg(operation)
                .arg(&path)
                .output()?;
            assert_eq!(output.status.code(), Some(expected_code), "{output:?}");
        }
        assert_eq!(target_path.exists(), allowed);
        assert!(!helper_tmp.join("forbidden.txt").exists());
    }
    Ok(())
}

#[test]
fn target_relay_rejects_invalid_transport_without_echoing_it() -> anyhow::Result<()> {
    let payload = "not-json-with-private-workload-data";
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .arg("--__mcp-console-target")
        .env("MCP_CONSOLE_SANDBOX_TARGET_CODEX_SANDBOX_LAUNCH_COUNT", "1")
        .env(
            "MCP_CONSOLE_SANDBOX_TARGET_CODEX_SANDBOX_LAUNCH_BYTES",
            payload.len().to_string(),
        )
        .env("MCP_CONSOLE_SANDBOX_TARGET_CODEX_SANDBOX_LAUNCH_0", payload)
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
    let diagnostic = String::from_utf8(output.stderr)?;
    assert!(diagnostic.contains("invalid Windows target request"));
    assert!(!diagnostic.contains(payload));
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
