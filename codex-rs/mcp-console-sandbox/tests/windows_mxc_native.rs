#![cfg(windows)]

use anyhow::Result;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_sandboxing::*;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[path = "../src/windows_proxy.rs"]
mod windows_proxy;

fn proxy(allow_local_binding: bool, allow_destination: bool) -> Value {
    json!({"enabled":true,"enableSocks5":true,"enableSocks5Udp":false,
        "allowUpstreamProxy":false,"dangerouslyAllowAllUnixSockets":false,"mode":"full",
        "domains":{"127.0.0.1":if allow_destination {"allow"} else {"deny"}},
        "allowLocalBinding":allow_local_binding})
}

#[tokio::test]
#[ignore = "requires a usable native MXC runtime and curl.exe"]
async fn native_mxc_uses_job_owned_proxy_allow_and_deny() -> Result<()> {
    anyhow::ensure!(windows_mxc_available(), "native MXC is unavailable");
    let root = tempfile::tempdir()?;
    let cwd = AbsolutePathBuf::try_from(root.path().join("command-cwd"))?;
    std::fs::create_dir(cwd.as_path())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/", listener.local_addr()?);
    let origin = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await?;
        let received = connection.read(&mut [0; 4096]).await?;
        anyhow::ensure!(received > 0, "expected an HTTP request at the test origin");
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nMXC_OK")
            .await?;
        Ok::<_, anyhow::Error>(())
    });
    for allowed in [true, false] {
        let job = Arc::new(codex_utils_pty::JobObject::create_without_breakaway()?);
        let mut env: std::collections::HashMap<_, _> = std::env::vars().collect();
        env.insert("hTtP_PrOxY".into(), "http://127.0.0.1:1".into());
        let proxy = windows_proxy::start(
            serde_json::from_value(proxy(/*allow_local_binding*/ true, allowed))?,
            &job,
            &mut env,
        )
        .await?;
        let projected: Vec<_> = env
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("HTTP_PROXY"))
            .collect();
        assert_eq!(projected.len(), 1);
        assert_ne!(projected[0].1, "http://127.0.0.1:1");
        let permissions = PermissionProfile::read_only();
        let executable = cargo_bin("mcp-console-sandbox")?;
        // Only this known test command bypasses Console's legacy-account admission gate.
        let prepared = SandboxManager::default().transform(SandboxTransformRequest {
            command: SandboxCommand {
                program: "curl.exe".into(),
                args: vec![
                    "--disable".into(),
                    "--silent".into(),
                    "--show-error".into(),
                    "--fail".into(),
                    "--max-time".into(),
                    "5".into(),
                    "--noproxy".into(),
                    String::new(),
                    "--proxy".into(),
                    format!("http://{}", proxy.proxy.http_addr()),
                    url.clone(),
                ],
                cwd: cwd.clone().into(),
                env,
                managed_network: Some(proxy.context.clone()),
                additional_permissions: None,
            },
            permissions: &permissions,
            sandbox: SandboxType::WindowsMxc,
            enforce_managed_network: true,
            environment_id: None,
            network: Some(&proxy.proxy),
            sandbox_policy_cwd: &cwd.clone().into(),
            sandbox_exe: Some(&executable),
            use_legacy_landlock: false,
            windows_sandbox_level: WindowsSandboxLevel::Disabled,
        })?;
        let mut spawned = spawn_process_with_windows_context(
            SpawnRequest {
                command: &prepared.command,
                cwd: cwd.as_path(),
                env: &prepared.env,
                arg0: &prepared.arg0,
                sandbox: prepared.sandbox,
                windows_sandbox: None,
                tty: false,
                stdin_open: true,
                inherited_fds: codex_utils_pty::ChildFds::Inherited(&[]),
            },
            WindowsSandboxLaunchContext {
                state_dir: root.path(),
                job: Some(job),
            },
        )
        .await?;
        let receipt =
            tokio::time::timeout(Duration::from_secs(/*secs*/ 20), spawned.exit_rx).await??;
        let mut output = Vec::new();
        while let Some(bytes) = spawned.stdout_rx.recv().await {
            output.extend(bytes);
        }
        let mut error = Vec::new();
        while let Some(bytes) = spawned.stderr_rx.recv().await {
            error.extend(bytes);
        }
        assert_eq!(
            (receipt, output),
            if allowed {
                (0, b"MXC_OK".to_vec())
            } else {
                (22, vec![])
            },
            "{}",
            String::from_utf8_lossy(&error)
        );
        if !allowed {
            assert!(String::from_utf8_lossy(&error).contains("403"));
        }
        proxy.handle.shutdown().await?;
    }
    origin.await??;
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}
