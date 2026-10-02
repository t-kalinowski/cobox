#![cfg(windows)]

use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::process::Command;

#[test]
fn root_exit_does_not_wait_for_caller_stdin_eof() -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::process::Stdio;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let root = tempfile::tempdir()?;
    let config = json!({
        "version": 2, "extends": ":read-only", "network": "enabled",
        "windows_sandbox_level": "restricted-token",
        "windows_state_dir": root.path().join("state"),
    });
    for code in [0i32, -1_073_741_819] {
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
    }
    Ok(())
}

#[test]
fn console_configuration_runs_with_private_storage() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = json!({
        "version": 2,
        "extends": ":read-only",
        "network": "enabled",
        "windows_sandbox_level": "restricted-token",
        "windows_state_dir": root.path().join("state"),
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
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}
