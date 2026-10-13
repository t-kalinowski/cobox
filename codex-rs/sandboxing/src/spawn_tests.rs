use super::*;
use pretty_assertions::assert_eq;
use std::sync::Arc;

#[tokio::test]
async fn restricted_token_rejects_caller_owned_job_before_preparing_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    let command = [
        "cmd.exe".into(),
        "/d".into(),
        "/c".into(),
        "echo ran>marker".into(),
    ];
    let result = spawn_process_with_windows_context(
        SpawnRequest {
            command: &command,
            cwd: root.path(),
            env: &HashMap::new(),
            arg0: &None,
            sandbox: SandboxType::WindowsRestrictedToken,
            windows_sandbox: None,
            tty: false,
            stdin_open: true,
            inherited_fds: codex_utils_pty::ChildFds::Inherited(&[]),
        },
        WindowsSandboxLaunchContext {
            state_dir: &state,
            job: Some(Arc::new(
                codex_utils_pty::JobObject::create_without_breakaway()?,
            )),
        },
    )
    .await;
    assert_eq!(
        result.unwrap_err().to_string(),
        "host-owned Jobs require an MXC pipe session with open stdin"
    );
    assert!(!state.exists());
    assert!(!root.path().join("marker").exists());
    Ok(())
}
