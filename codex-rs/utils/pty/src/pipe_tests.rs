use super::*;
use pretty_assertions::assert_eq;
use std::process::Stdio;

#[tokio::test]
async fn supervised_assignment_failure_never_resumes_the_workload() -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use winapi::um::jobapi2::SetInformationJobObject;
    use winapi::um::winnt::*;
    let job = Arc::new(crate::JobObject::create_without_breakaway()?);
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
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
    let mut command = tokio::process::Command::new("cmd.exe");
    command
        .args(["/d", "/c", "pause"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    let mut held = job.spawn_contained(&mut command)?;
    let root = tempfile::tempdir()?;
    let marker = root.path().join("escaped");
    let result = spawn_process_in_job(
        "cmd.exe",
        &["/d".into(), "/c".into(), "echo escaped>escaped".into()],
        root.path(),
        &std::env::vars().collect(),
        job,
    )
    .await;
    held.kill().await?;
    held.wait().await?;
    assert!(result.is_err());
    assert!(!marker.exists());
    Ok(())
}

#[tokio::test]
async fn supervised_job_withholds_receipt_when_retirement_cannot_be_confirmed() -> anyhow::Result<()>
{
    // A prior completion-port association makes the retirement barrier fail.
    // This is a real kernel failure, not a synthetic target exit-code sentinel.
    let job = Arc::new(crate::JobObject::create_without_breakaway()?);
    crate::retire_job(&job)?;
    let spawned = spawn_process_in_job(
        "cmd.exe",
        &["/d".into(), "/c".into(), "exit 0".into()],
        &std::env::current_dir()?,
        &std::env::vars().collect(),
        job,
    )
    .await?;
    assert!(spawned.exit_rx.await.is_err());
    assert_eq!(spawned.session.exit_code(), None);
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
