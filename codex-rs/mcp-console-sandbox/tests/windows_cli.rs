#![cfg(windows)]

use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use std::process::Command;

#[test]
fn invalid_state_path_fails_before_creating_state() -> anyhow::Result<()> {
    let output = Command::new(cargo_bin("mcp-console-sandbox")?)
        .args(["status", "--state-dir", "relative"])
        .output()?;
    assert_eq!((output.status.code(), output.stdout), (Some(2), vec![]));
    assert!(String::from_utf8(output.stderr)?.contains("path is not absolute"));
    Ok(())
}

#[test]
fn removed_run_interface_fails_clearly() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    for argument in [
        "run",
        "--command-cwd",
        "--workspace-root",
        "--permission-profile",
        "--env-json",
        "--windows-sandbox-level",
        "--windows-sandbox-private-desktop",
        "--preserve-proxy-settings",
        "--proxy-enforced",
        "--network-proxy-restricting-sid",
        "--read-roots-json",
        "--read-roots-include-platform-defaults",
        "--write-roots-json",
        "--deny-read-paths-json",
        "--deny-write-paths-json",
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox")?)
            .arg("--state-dir")
            .arg(&state)
            .arg(argument)
            .output()?;
        assert_eq!((output.status.code(), output.stdout), (Some(2), vec![]));
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains(argument)
                && (stderr.contains("unrecognized subcommand")
                    || stderr.contains("unexpected argument")),
            "{stderr}"
        );
        assert!(!state.exists());
    }
    Ok(())
}
