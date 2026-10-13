use super::*;
use pretty_assertions::assert_eq;
use std::process::Stdio;
use std::time::Duration;

#[tokio::test]
async fn supervised_job_rejects_unsafe_flags_before_spawn() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use winapi::um::jobapi2::SetInformationJobObject;
    use winapi::um::winnt::*;
    let root = tempfile::tempdir()?;
    for flags in [
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
        0,
    ] {
        let job = Arc::new(crate::JobObject::create()?);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = flags;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    job.as_raw_handle().cast(),
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            },
            0
        );
        let result = spawn_process_in_job(
            "cmd.exe",
            &["/d".into(), "/c".into(), "echo escaped>marker".into()],
            root.path(),
            &std::env::vars().collect(),
            job,
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "supervised Windows Job must disable breakaway and kill all members on close"
        );
        assert!(!root.path().join("marker").exists());
    }
    Ok(())
}

#[tokio::test]
async fn supervised_job_retires_members_and_preserves_receipt_presence() -> Result<()> {
    let root = tempfile::tempdir()?;
    let env = std::env::vars().collect();
    for observation_failure in [false, true] {
        let job = Arc::new(crate::JobObject::create_without_breakaway()?);
        if observation_failure {
            // A prior completion-port association makes retirement observation fail.
            crate::retire_job(&job)?;
        }
        let mut command = tokio::process::Command::new("cmd.exe");
        command
            .args(["/d", "/c", "set /p held="])
            .stdin(Stdio::piped());
        let mut held = job.spawn_contained(&mut command)?;
        let _stdin = held.stdin.take();
        let spawned = spawn_process_in_job(
            "cmd.exe",
            &["/d".into(), "/c".into(), "exit 125".into()],
            root.path(),
            &env,
            Arc::clone(&job),
        )
        .await?;
        let receipt = tokio::time::timeout(Duration::from_secs(/*secs*/ 5), spawned.exit_rx)
            .await?
            .ok();
        let expected = (!observation_failure).then_some(/*t*/ 125);
        assert_eq!((receipt, spawned.session.exit_code()), (expected, expected));
        // Retained Job/session handles prevent kill-on-last-close from hiding leaks.
        assert!(
            !tokio::time::timeout(Duration::from_secs(/*secs*/ 2), held.wait())
                .await??
                .success()
        );
        let repeated = spawn_process_in_job(
            "cmd.exe",
            &["/d".into(), "/c".into(), "echo escaped>marker".into()],
            root.path(),
            &env,
            job,
        )
        .await;
        assert_eq!(
            repeated.unwrap_err().to_string(),
            "a supervised Windows Job can only launch one workload"
        );
        assert!(!root.path().join("marker").exists());
    }
    Ok(())
}

#[test]
fn process_fallback_interrupt_terminates_root() -> anyhow::Result<()> {
    let mut child = std::process::Command::new("ping.exe")
        .args(["-n", "60", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut terminator = PipeChildTerminator {
        windows: WindowsChildTerminator::Process(child.id()),
    };

    terminator.signal(ProcessSignal::Interrupt)?;

    assert!(!child.wait()?.success());
    Ok(())
}
