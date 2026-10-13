use super::*;
use anyhow::Context;
use pretty_assertions::assert_eq;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::time::Duration;

// This test executable is also the real sandbox workload. No production helper
// or later acceptance-fixture layer is needed to verify initial proxy activation.
#[test]
fn child() -> Result<()> {
    let Ok(destination) = std::env::var("CONSOLE_PROXY_SMOKE_ORIGIN") else {
        return Ok(());
    };
    if let Some(guard) = std::env::var_os("CONSOLE_PROXY_SMOKE_GUARD") {
        let error = std::fs::File::options()
            .read(true)
            .write(true)
            .open(guard)
            .err()
            .context("workload opened the protected admission lock")?;
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
    let endpoint = std::env::var("HTTP_PROXY")?;
    assert_eq!(std::env::var("HTTPS_PROXY")?, endpoint);
    assert_eq!(std::env::var("NODE_USE_ENV_PROXY")?, "1");
    assert_ne!(std::env::var("NO_PROXY")?, "*");
    assert!(std::env::vars().all(|(name, _)| {
        ![
            "CONSOLE_POLICY",
            "CODEX_NETWORK_PROXY_ATTRIBUTION",
            "CODEX_NETWORK_PROXY_BROKERED_CREDENTIALS",
            "CODEX_NETWORK_PROXY_CREDENTIAL_BROKER_ACTIVE",
            "OPENAI_API_KEY",
        ]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
    }));
    assert_eq!(std::env::var("GH_TOKEN")?, "workload-override");
    let mut stream =
        TcpStream::connect(endpoint.strip_prefix("http://").context("HTTP proxy URL")?)?;
    stream.set_read_timeout(Some(Duration::from_secs(/*secs*/ 5)))?;
    write!(
        stream,
        "GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("allowed"), "{response}");
    println!("RETIRED_PROXY={endpoint}");
    Ok(())
}

fn managed_proxy_smoke(level: &str) -> Result<()> {
    let root = tempfile::tempdir_in(std::env::var_os("PUBLIC").context("PUBLIC")?)?;
    let workload = root.path().join("smoke.exe");
    std::fs::copy(std::env::current_exe()?, &workload)?;
    let temporary = root.path().join("private");
    std::fs::create_dir(&temporary)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = listener.local_addr()?;
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || -> Result<usize> {
        let mut requests = 0;
        while matches!(
            stopped.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(Duration::from_secs(/*secs*/ 5)))?;
                    let mut request = [0; 4096];
                    let size = stream.read(&mut request)?;
                    anyhow::ensure!(size > 0, "origin received an empty request");
                    stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed",
                    )?;
                    requests += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(/*millis*/ 10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(requests)
    });
    // Host control proves the origin is reachable before relying on sandbox results.
    let mut control = TcpStream::connect(origin)?;
    control.set_read_timeout(Some(Duration::from_secs(/*secs*/ 5)))?;
    control.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    control.read_to_string(&mut response)?;
    assert!(response.ends_with("allowed"));
    let mut policy = proxy();
    policy["allowLocalBinding"] = json!(true);
    let mut configuration = json!({
        "extends": ":read-only", "network": "restricted", "proxy": policy,
        "windows_sandbox_level": level,
        "environment": {"hTtP_pRoXy": "http://127.0.0.1:9", "hTtPs_PrOxY": "http://127.0.0.1:9",
            "nO_pRoXy": "*", "NoDe_UsE_EnV_PrOxY": "0", "CoDeX_NeTwOrK_PrOxY_AtTrIbUtIoN": "workload-token"},
        "lifecycle": {"private_tmp": {"parent": temporary, "environment": ["TMPDIR"]}}
    });
    if level == "mxc" {
        configuration["windows_state_dir"] = json!(root.path().join("unprovisioned"));
    } else if let Some(state) = std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR") {
        configuration["windows_state_dir"] = json!(state.to_str().context("test state Unicode")?);
    }
    let mut command = Command::new(cargo_bin("mcp-console-sandbox")?);
    if level == "elevated" {
        let state = std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or(
                std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA")?)
                    .join("mcp-console"),
            );
        let guard = state.join(".sandbox-secrets/console-proxy-configuration.lock");
        let _host_control = std::fs::File::options()
            .read(true)
            .write(true)
            .open(&guard)?;
        command.env("CONSOLE_PROXY_SMOKE_GUARD", guard);
    }
    let output = command
        .current_dir(root.path())
        .env("USERPROFILE", root.path())
        .env("HOME", root.path())
        .env("CONSOLE_POLICY", configuration.to_string())
        .env("CONSOLE_PROXY_SMOKE_ORIGIN", origin.to_string())
        .env("CODEX_NETWORK_PROXY_ATTRIBUTION", "inherited-token")
        .env(
            "CODEX_NETWORK_PROXY_BROKERED_CREDENTIALS",
            json!([["OPENAI_API_KEY", "inherited-dummy"], ["GH_TOKEN", "other-dummy"]]).to_string(),
        )
        .env("oPeNaI_ApI_kEy", "inherited-dummy")
        .env("GH_TOKEN", "workload-override")
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(workload)
        .args(["--exact", "smoke::child", "--nocapture"])
        .output();
    let _ = stop.send(());
    let count = server
        .join()
        .map_err(|_| anyhow::anyhow!("origin thread panicked"))??;
    let output = output?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(count, 2);
    assert_eq!(std::fs::read_dir(temporary)?.count(), 0);
    let stdout = String::from_utf8(output.stdout)?;
    let endpoint = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RETIRED_PROXY=http://"))
        .context("workload proxy endpoint")?;
    assert!(
        TcpStream::connect_timeout(&endpoint.parse()?, Duration::from_millis(/*millis*/ 200))
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "requires native MXC with deny-path support"]
fn mxc_allowed_request_and_confirmed_proxy_retirement() -> Result<()> {
    managed_proxy_smoke("mxc")
}

#[test]
#[ignore = "requires explicitly provisioned Console managed-proxy accounts"]
fn elevated_allowed_request_and_confirmed_proxy_retirement() -> Result<()> {
    managed_proxy_smoke("elevated")
}
