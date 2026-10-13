#![cfg(windows)]

#[path = "windows_mxc_support/mod.rs"]
mod mxc_support;

use anyhow::Result;
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

fn console(policy: Value) -> Result<Command> {
    let mut command = Command::new(cargo_bin("mcp-console-sandbox")?);
    command.env("CONSOLE_POLICY", policy.to_string()).args([
        "--config-env",
        "CONSOLE_POLICY",
        "--",
        "cmd.exe",
        "/d",
        "/c",
    ]);
    Ok(command)
}

#[test]
fn mxc_does_not_require_localappdata_or_a_state_directory() -> Result<()> {
    let available = mxc_support::available()?;
    for mode in ["auto", "mxc"] {
        let output = console(json!({"extends":":read-only", "windows_sandbox_level":mode}))?
            .env_remove("LOCALAPPDATA")
            .arg("echo MXC_OK")
            .output()?;
        if available {
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (Some(0), b"MXC_OK\r\n".to_vec(), vec![])
            );
        } else {
            assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
            let error = String::from_utf8(output.stderr)?;
            assert!(
                error.contains(if mode == "auto" {
                    "LOCALAPPDATA"
                } else {
                    "MXC is unavailable"
                }),
                "{error}"
            );
        }
    }
    Ok(())
}

#[test]
fn public_mxc_proxy_projects_environment_and_enforces_allow_and_deny() -> Result<()> {
    use std::io::Read;
    use std::io::Write;
    if !mxc_support::available()? {
        return Ok(());
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/", listener.local_addr()?);
    let origin = std::thread::spawn(move || -> Result<()> {
        let (mut connection, _) = listener.accept()?;
        connection.set_read_timeout(Some(std::time::Duration::from_secs(/*secs*/ 5)))?;
        anyhow::ensure!(
            connection.read(&mut [0; 4096])? > 0,
            "expected an HTTP request"
        );
        connection.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nMXC_OK",
        )?;
        Ok(())
    });
    for allowed in [true, false] {
        let output = console(json!({"extends":":read-only", "windows_sandbox_level":"mxc",
                "proxy":proxy(/*allow_local_binding*/ true, allowed)}))?
            .env_remove("LOCALAPPDATA")
            .env("hTtP_pRoXy", "http://127.0.0.1:1")
            .arg(format!("curl.exe --disable --silent --show-error --fail --max-time 5 --noproxy \"\" --proxy \"%HTTP_PROXY%\" {url}"))
            .output()?;
        assert_eq!(
            (output.status.code(), output.stdout),
            if allowed {
                (Some(0), b"MXC_OK".to_vec())
            } else {
                (Some(22), vec![])
            },
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !allowed {
            assert!(String::from_utf8(output.stderr)?.contains("403"));
        }
    }
    origin.join().expect("origin thread")?;
    Ok(())
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
        let output = console(policy)?
            .arg("if defined CONSOLE_POLICY (exit /b 42) else echo MXC_OK")
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
    Ok(())
}

#[test]
fn unsupported_proxy_modes_fail_before_launch_or_state_creation() -> Result<()> {
    let root = tempfile::tempdir()?;
    for (key, value, diagnostic) in [
        ("enableSocks5Udp", json!(true), "SOCKS5 UDP"),
        (
            "dangerouslyAllowAllUnixSockets",
            json!(true),
            "Unix sockets",
        ),
        (
            "unixSockets",
            json!({"/tmp/proxy.sock": "allow"}),
            "Unix sockets",
        ),
    ] {
        let mut proxy = proxy(
            /*allow_local_binding*/ true, /*allow_destination*/ true,
        );
        proxy[key] = value;
        for mode in ["auto", "mxc", "elevated", "unelevated"] {
            let output = console(json!({"extends":":read-only", "windows_sandbox_level":mode,
                        "windows_state_dir":root.path().join("state"), "proxy":proxy,
                        "lifecycle":{"private_tmp":{"parent":root.path(),"environment":["TMP"]}}}))?
            .arg("echo launched")
            .output()?;
            assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
            let error = String::from_utf8(output.stderr)?;
            assert!(error.contains(diagnostic), "{mode}: {error}");
            assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
        }
    }
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
        let output = console(json!({"extends":":read-only", "windows_sandbox_level":mode,
                    "windows_state_dir":root.path()}))?
        .arg("echo MXC_OK")
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
