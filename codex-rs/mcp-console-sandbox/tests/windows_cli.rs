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
