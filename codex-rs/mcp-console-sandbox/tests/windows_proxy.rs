#![cfg(windows)]

#[path = "../src/windows_proxy_lock.rs"]
mod windows_proxy_lock;

#[test]
fn legacy_environment_admission_observes_the_setup_barrier() -> anyhow::Result<()> {
    use codex_utils_cargo_bin::cargo_bin;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::process::Command;
    let state = tempfile::tempdir()?;
    std::fs::create_dir(state.path().join(".sandbox-secrets"))?;
    let guard = windows_proxy_lock::configuration_guard(state.path())?;
    let mut command = Command::new(cargo_bin("mcp-console-sandbox")?);
    let policy = json!({"extends":":read-only", "network":"restricted",
        "windows_sandbox_level":"elevated", "windows_state_dir":state.path()});
    command
        .env("CONSOLE_POLICY", policy.to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(cargo_bin("mcp-console-sandbox-fixture")?)
        .arg("context");
    let blocked = command.output()?;
    assert_eq!((blocked.status.code(), blocked.stdout), (Some(1), vec![]));
    assert!(String::from_utf8(blocked.stderr)?.contains("setup or admission is in progress"));
    drop(guard);
    let unprovisioned = command.output()?;
    assert_eq!(
        (unprovisioned.status.code(), unprovisioned.stdout),
        (Some(1), vec![])
    );
    let error = String::from_utf8(unprovisioned.stderr)?;
    assert!(
        error.contains("Windows sandbox setup is required"),
        "{error}"
    );
    assert!(
        !error.contains("setup or admission is in progress"),
        "{error}"
    );
    Ok(())
}
