//! Public environment transport against explicitly provisioned Console accounts.
#![cfg(windows)]

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires completed Console setup, adjacent helpers, and exclusive account access"]
fn provisioned_launch_preserves_host_policy_and_target_temp_grants() -> Result<()> {
    let state = PathBuf::from(
        std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR")
            .context("select the already provisioned Console state directory")?,
    );
    let marker = state.join(".sandbox/setup_marker.json");
    let original = std::fs::read(&marker)?;
    // Keep the executable, cwd and probes in PUBLIC so native ACL preparation
    // does not need to traverse the owner's profile.
    let public = std::env::var_os("PUBLIC").context("PUBLIC directory")?;
    let root = tempfile::tempdir_in(public)?;
    let executable = root.path().join("console-environment-native.exe");
    std::fs::copy(std::env::current_exe()?, &executable)?;
    for overrides in [false, true] {
        let paths: Vec<_> = ["host-temp", "host-tmp", "target-temp", "target-tmp"]
            .map(|name| root.path().join(format!("{name}-{overrides}")))
            .into_iter()
            .collect();
        for path in &paths {
            std::fs::create_dir(path)?;
            let control = path.join("host-control");
            std::fs::write(&control, b"host write control")?;
            std::fs::remove_file(control)?;
        }
        let cases = paths
            .iter()
            .enumerate()
            .map(|(index, path)| (path.join("workload-write"), overrides && index >= 2))
            .collect::<Vec<_>>();
        let mut environment = json!({"CONSOLE_TEMP_CASES": serde_json::to_string(&cases)?});
        if overrides {
            environment["tEmP"] = json!(paths[2]);
            environment["TmP"] = json!(paths[3]);
        }
        let config = json!({
            "filesystem": {"kind":"restricted", "entries":[
                {"path":{"type":"special","value":{"kind":"root"}}, "access":"read"},
                {"path":{"type":"special","value":{"kind":"tmpdir"}}, "access":"write"},
            ]},
            "network":"restricted", "windows_backend":"elevated",
            "windows_state_dir":state, "inherit_environment":false,
            "environment":environment,
        });
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .current_dir(root.path())
            .env("USERPROFILE", root.path())
            .env("HOME", root.path())
            .env("CONSOLE_POLICY", config.to_string())
            .env("TEMP", &paths[0])
            .env("TMP", &paths[1])
            .env("HTTP_PROXY", "http://127.0.0.1:44991")
            .env("HTTPS_PROXY", "http://127.0.0.1:44992")
            .env("ALL_PROXY", "socks5://127.0.0.1:44993")
            .env("CODEX_NETWORK_ALLOW_LOCAL_BINDING", "1")
            .args(["--config-env", "CONSOLE_POLICY", "--"])
            .arg(&executable)
            .args(["--exact", "target_temp_write_probe", "--nocapture"])
            .output()?;
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        ensure!(
            String::from_utf8(output.stdout)?.contains("TEMP_BOUNDARY_OK"),
            "missing workload result"
        );
        assert_eq!(
            std::fs::read(&marker)?,
            original,
            "ordinary launch changed provisioning"
        );
    }
    Ok(())
}

#[test]
fn target_temp_write_probe() -> Result<()> {
    let Ok(cases) = std::env::var("CONSOLE_TEMP_CASES") else {
        return Ok(());
    };
    let cases: Vec<(PathBuf, bool)> = serde_json::from_str(&cases)?;
    for (path, allowed) in cases {
        let outcome = std::fs::write(&path, b"workload write").map_err(|error| error.kind());
        assert_eq!(
            outcome,
            if allowed {
                Ok(())
            } else {
                Err(std::io::ErrorKind::PermissionDenied)
            },
            "{path:?}"
        );
    }
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "CODEX_NETWORK_ALLOW_LOCAL_BINDING",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "host {name} reached target"
        );
    }
    println!("TEMP_BOUNDARY_OK");
    Ok(())
}
