#![cfg(windows)]

#[path = "windows_mxc_support/mod.rs"]
mod mxc_support;

use anyhow::Result;
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
fn writable_roots_cover_complete_subtrees_across_launches() -> Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let writable = directory.path().join("writable");
    std::fs::create_dir(&writable)?;
    std::fs::write(writable.join("read-only"), "unchanged")?;
    std::fs::write(writable.join("secret"), "private")?;
    let policy = json!({"filesystem":{"kind":"restricted","entries":[
        {"path":{"type":"special","value":{"kind":"root"}},"access":"read"},
        {"path":{"type":"path","path":writable},"access":"write"},
        {"path":{"type":"path","path":writable.join("read-only")},"access":"read"},
        {"path":{"type":"path","path":writable.join("secret")},"access":"deny"}
    ]},"network":"restricted"});
    let script = r#"
$ErrorActionPreference = 'Stop'
$root = Join-Path (Get-Location) 'writable'
foreach ($name in '.git', '.agents', '.codex', '.aws') {
    if ($env:TEST_LAUNCH -eq '1' -and [IO.Directory]::Exists((Join-Path $root $name))) { throw 'unexpected metadata directory' }
    foreach ($nested in 'ordinary', '.git', '.agents', '.codex', '.aws') {
        $path = Join-Path (Join-Path $root $name) $nested
        [IO.Directory]::CreateDirectory($path) | Out-Null
        $value = Join-Path $path 'value'
        if ($env:TEST_LAUNCH -eq '2' -and [IO.File]::ReadAllText($value) -ne '1') { throw 'previous write lost' }
        [IO.File]::WriteAllText($value, $env:TEST_LAUNCH)
        if ([IO.File]::ReadAllText($value) -ne $env:TEST_LAUNCH) { throw 'write failed' }
        $remove = Join-Path $path 'remove'
        [IO.File]::WriteAllText($remove, 'disposable')
        [IO.File]::Delete($remove)
    }
}
foreach ($path in (Join-Path $root 'read-only'), (Join-Path $root 'secret'), (Join-Path (Get-Location) 'outside')) {
    $denied = $false
    try { [IO.File]::WriteAllText($path, 'escaped') } catch [UnauthorizedAccessException] { $denied = $true }
    if (-not $denied) { throw "unexpected write: $path" }
}
$denied = $false
try { [IO.File]::ReadAllText((Join-Path $root 'secret')) | Out-Null } catch [UnauthorizedAccessException] { $denied = $true }
if (-not $denied) { throw 'unexpected secret read' }
Write-Output 'complete subtree writable; explicit exclusions retained'
"#;
    for launch in [1, 2] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .current_dir(directory.path())
            .env("CONSOLE_POLICY", policy.to_string())
            .env("TEST_LAUNCH", launch.to_string())
            .args([
                "--config-env",
                "CONSOLE_POLICY",
                "--",
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .output()?;
        assert_eq!(
            (
                output.status.code(),
                String::from_utf8(output.stdout)?,
                String::from_utf8(output.stderr)?
            ),
            (
                Some(0),
                "complete subtree writable; explicit exclusions retained\r\n".to_owned(),
                String::new()
            )
        );
        assert_eq!(std::fs::read(writable.join("read-only"))?, b"unchanged");
        assert_eq!(std::fs::read(writable.join("secret"))?, b"private");
        assert!(!directory.path().join("outside").exists());
    }
    Ok(())
}

#[test]
fn mxc_launch_uses_the_default_policy() -> Result<()> {
    let available = mxc_support::available()?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        let mut summary = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(
            summary,
            "- Native MXC: {}.",
            if available {
                "available; runtime contracts execute"
            } else {
                "unavailable; runtime contracts skipped; unsupported-host rejection checked"
            }
        )?;
    }
    // Exercise the shipping layout independently of other Cargo artifacts.
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("mcp-console-sandbox.exe");
    std::fs::copy(cargo_bin("mcp-console-sandbox")?, &executable)?;
    let output = Command::new(executable)
        .current_dir(directory.path())
        .env(
            "CONSOLE_POLICY",
            json!({"extends":":read-only"}).to_string(),
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
    if available {
        assert_eq!(
            (output.status.code(), output.stdout, output.stderr),
            (Some(0), b"MXC_OK\r\n".to_vec(), vec![])
        );
    } else {
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        assert!(String::from_utf8(output.stderr)?.contains("WINDOWS.html#native-sandbox"));
    }
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn required_validation_fails_when_native_mxc_is_unavailable() -> Result<()> {
    if codex_sandboxing::windows_mxc_available() {
        return Ok(());
    }
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "mxc_launch_uses_the_default_policy",
            "--nocapture",
        ])
        .env("MCP_CONSOLE_SANDBOX_REQUIRE_MXC", "1")
        .output()?;
    assert!(!output.status.success(), "{output:?}");
    let diagnostic = format!(
        "{}{}",
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?
    );
    assert!(
        diagnostic.contains("required native MXC validation is unavailable"),
        "{diagnostic}"
    );
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
        let output = console(json!({"extends":":read-only", "proxy":proxy(/*allow_local_binding*/ true, allowed)}))?
                .env("hTtP_pRoXy", "http://127.0.0.1:1")
            .arg(format!("curl.exe --disable --silent --show-error --fail --max-time 5 --noproxy localhost --proxy %HTTP_PROXY% {url}"))
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
        let output = console(json!({"extends":":read-only", "proxy":proxy,
                        "lifecycle":{"private_tmp":{"parent":root.path(),"environment":["TMP"]}}}))?
        .arg("echo launched")
        .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains(diagnostic), "{error}");
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn disabled_proxy_matches_absent_proxy() -> Result<()> {
    if !mxc_support::available()? {
        return Ok(());
    }
    let mut disabled = proxy(
        /*allow_local_binding*/ false, /*allow_destination*/ false,
    );
    disabled["enabled"] = json!(false);
    disabled["enableSocks5Udp"] = json!(true);
    disabled["dangerouslyAllowAllUnixSockets"] = json!(true);
    for selected in [Value::Null, disabled] {
        let output =
            console(json!({"extends":":read-only", "network":"enabled", "proxy":selected}))?
                .env_remove("HTTP_PROXY")
                .arg("if defined HTTP_PROXY (exit /b 42) else echo PROXY_DISABLED")
                .output()?;
        assert_eq!(
            (output.status.code(), output.stdout, output.stderr),
            (Some(0), b"PROXY_DISABLED\r\n".to_vec(), vec![])
        );
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
                json!({"extends":":read-only",
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
