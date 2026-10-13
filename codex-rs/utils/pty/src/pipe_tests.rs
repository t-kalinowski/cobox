use super::*;
use pretty_assertions::assert_eq;
use std::process::Stdio;
use std::time::Duration;

#[tokio::test]
async fn supervised_job_rejects_breakaway_and_non_terminating_jobs_before_spawn()
-> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use winapi::um::jobapi2::SetInformationJobObject;
    use winapi::um::winnt::*;
    let root = tempfile::tempdir()?;
    let env = std::env::vars().collect();
    for flags in [
        None, // The public constructor permits explicit breakaway.
        Some(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
        Some(0), // Native mutation can also remove kill-on-close.
    ] {
        let job = Arc::new(crate::JobObject::create()?);
        if let Some(flags) = flags {
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
        }
        let result = spawn_process_in_job(
            "cmd.exe",
            &["/d".into(), "/c".into(), "echo escaped>marker".into()],
            root.path(),
            &env,
            job,
        )
        .await;
        let error = match result {
            Ok(spawned) => {
                tokio::time::timeout(Duration::from_secs(/*secs*/ 5), spawned.exit_rx).await??;
                anyhow::bail!("unsafe Job admitted: {flags:?}");
            }
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "supervised Windows Job must disable breakaway and kill all members on close"
        );
        assert!(!root.path().join("marker").exists());
    }
    Ok(())
}

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
    let mut command = tokio::process::Command::new("cmd.exe");
    command
        .args(["/d", "/c", "set /p held="])
        .stdin(Stdio::piped());
    let mut held = job.spawn_contained(&mut command)?;
    let spawned = spawn_process_in_job(
        "cmd.exe",
        &["/d".into(), "/c".into(), "exit 0".into()],
        &std::env::current_dir()?,
        &std::env::vars().collect(),
        Arc::clone(&job),
    )
    .await?;
    assert!(spawned.exit_rx.await.is_err());
    assert_eq!(spawned.session.exit_code(), None);
    // Retain both the host Job and session: kill-on-last-close cannot mask a leak.
    let _stdin = held.stdin.take();
    assert!(
        !tokio::time::timeout(Duration::from_secs(/*secs*/ 2), held.wait())
            .await??
            .success()
    );
    Ok(())
}

#[tokio::test]
async fn supervised_wait_failure_still_terminates_job_members() -> anyhow::Result<()> {
    let job = Arc::new(crate::JobObject::create_without_breakaway()?);
    let mut command = tokio::process::Command::new("cmd.exe");
    command
        .args(["/d", "/c", "set /p held="])
        .stdin(Stdio::piped());
    let mut held = job.spawn_contained(&mut command)?;
    let _stdin = held.stdin.take();
    let result =
        finish_supervised_wait(Err(io::Error::other("root wait failed")), Arc::clone(&job)).await;
    assert_eq!(result.unwrap_err().to_string(), "root wait failed");
    assert!(
        !tokio::time::timeout(Duration::from_secs(/*secs*/ 2), held.wait())
            .await??
            .success()
    );
    Ok(())
}

#[tokio::test]
async fn supervised_job_rejects_overlapping_and_later_launches() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let job = Arc::new(crate::JobObject::create_without_breakaway()?);
    let env = std::env::vars().collect();
    let mut first = spawn_process_in_job(
        "cmd.exe",
        &[
            "/d".into(),
            "/c".into(),
            "set /p held= & echo survived".into(),
        ],
        root.path(),
        &env,
        Arc::clone(&job),
    )
    .await?;
    let args = ["/d".into(), "/c".into(), "echo ran>marker".into()];
    let second = spawn_process_in_job("cmd.exe", &args, root.path(), &env, Arc::clone(&job)).await;
    assert_eq!(
        second.unwrap_err().to_string(),
        "a supervised Windows Job can only launch one workload"
    );
    first
        .session
        .writer_sender()
        .send(b"continue\r\n".to_vec())
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(/*secs*/ 5), first.exit_rx).await??,
        0
    );
    let mut output = Vec::new();
    while let Some(bytes) = first.stdout_rx.recv().await {
        output.extend(bytes);
    }
    assert!(String::from_utf8_lossy(&output).contains("survived"));
    let third = spawn_process_in_job("cmd.exe", &args, root.path(), &env, job).await;
    assert_eq!(
        third.unwrap_err().to_string(),
        "a supervised Windows Job can only launch one workload"
    );
    assert!(!root.path().join("marker").exists());
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
