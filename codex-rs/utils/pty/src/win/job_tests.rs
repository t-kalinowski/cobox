//! Verifies console suppression through contained launches and both containment fallbacks.

use super::*;
use pretty_assertions::assert_eq;
use std::os::windows::process::CommandExt;
use std::process::Stdio;
use std::time::Duration;
use winapi::um::winnt::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

#[tokio::test]
async fn background_launches_keep_consoles_hidden_when_containment_fails() -> anyhow::Result<()> {
    const TEST_NAME: &str =
        "win::job::tests::background_launches_keep_consoles_hidden_when_containment_fails";
    const PHASE: &str = "CODEX_TEST_BACKGROUND_JOB_PHASE";
    let executable = std::env::current_exe()?;
    match std::env::var(PHASE).as_deref() {
        Ok("probe") => {
            assert!(unsafe { winapi::um::wincon::GetConsoleWindow() }.is_null());
            println!("background probe completed");
            return Ok(());
        }
        Ok("hold") => {
            std::thread::sleep(Duration::from_secs(/*secs*/ 30));
            return Ok(());
        }
        Ok("parent") => {}
        _ => {
            let output = std::process::Command::new(executable)
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(PHASE, "parent")
                .creation_flags(winapi::um::winbase::DETACHED_PROCESS)
                .output()?;
            assert!(output.status.success(), "detached probe failed: {output:?}");
            return Ok(());
        }
    }

    // Fill a one-process job so assigning the next suspended child must fail.
    // The parent remains outside this job, allowing the uncontained retry to run.
    let full_job = JobObject::create()?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    let configured = unsafe {
        SetInformationJobObject(
            full_job.handle.as_raw_handle().cast(),
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of_mut!(limits).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    anyhow::ensure!(configured != 0, "{}", io::Error::last_os_error());
    let mut holder_command = Command::new(&executable);
    holder_command
        .args(["--exact", TEST_NAME])
        .env(PHASE, "hold");
    let mut holder = full_job.spawn_contained(&mut holder_command)?;

    for (case, job, expected_containment) in [
        (
            "creation failure",
            Err(io::Error::other("forced creation failure")),
            false,
        ),
        ("assignment failure", Ok(full_job), false),
        ("contained", JobObject::create(), true),
    ] {
        let mut command = Command::new(&executable);
        command
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(PHASE, "probe")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (child, job) = JobObject::spawn_background_with_job(&mut command, job)?;
        assert_eq!(job.is_some(), expected_containment, "{case}");
        let output =
            tokio::time::timeout(Duration::from_secs(/*secs*/ 10), child.wait_with_output())
                .await??;
        assert!(output.status.success(), "{case}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("background probe completed"));
    }
    tokio::time::timeout(Duration::from_secs(/*secs*/ 10), holder.wait()).await??;
    Ok(())
}

#[tokio::test]
async fn supervised_assignment_failure_terminates_suspended_child() -> anyhow::Result<()> {
    use std::sync::Arc;
    use winapi::shared::winerror::ERROR_ACCESS_DENIED;
    use winapi::um::handleapi::DuplicateHandle;
    use winapi::um::jobapi2::QueryInformationJobObject;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::JOB_OBJECT_QUERY;
    use winapi::um::winnt::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION;
    use winapi::um::winnt::JobObjectBasicAccountingInformation;

    const TEST_NAME: &str =
        "win::job::tests::supervised_assignment_failure_terminates_suspended_child";
    const PROBE_ROOT: &str = "CODEX_TEST_SUPERVISED_ASSIGNMENT_FAILURE_ROOT";
    if let Some(root) = std::env::var_os(PROBE_ROOT) {
        let root = std::path::PathBuf::from(root);
        let mut job = JobObject::create_without_breakaway()?;
        let mut query_handle = std::ptr::null_mut();
        let duplicated = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                job.as_raw_handle().cast(),
                GetCurrentProcess(),
                &mut query_handle,
                JOB_OBJECT_QUERY,
                /*bInheritHandle*/ 0,
                /*dwOptions*/ 0,
            )
        };
        anyhow::ensure!(duplicated != 0, "{}", io::Error::last_os_error());
        // Limit inspection succeeds, but assignment fails without the kernel killing
        // the child (as it would when a Job's active-process limit is exceeded).
        job.handle = unsafe { OwnedHandle::from_raw_handle(query_handle.cast()) };
        let Err(error) = crate::pipe::spawn_process_in_job(
            "cmd.exe",
            &["/d".into(), "/c".into(), "echo escaped>marker".into()],
            &root,
            &std::env::vars().collect(),
            Arc::new(job),
        )
        .await
        else {
            anyhow::bail!("query-only Job unexpectedly accepted assignment");
        };
        assert_eq!(
            error.downcast::<io::Error>()?.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32)
        );
        assert!(!root.join("marker").exists());
        println!("assignment failure observed");
        return Ok(());
    }

    let root = tempfile::tempdir()?;
    let log_path = root.path().join("probe.log");
    let log = std::fs::File::create(&log_path)?;
    // Only this test's subprocess and descendants belong to this outer Job. It
    // both exposes suspended leaks and cleans them up if an assertion fails.
    let outer_job = JobObject::create_without_breakaway()?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(PROBE_ROOT, root.path())
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let mut probe = outer_job.spawn_contained(&mut command)?;
    let status = tokio::time::timeout(Duration::from_secs(/*secs*/ 10), probe.wait()).await??;
    let output = std::fs::read_to_string(log_path)?;
    assert!(status.success(), "assignment probe failed: {output}");
    assert!(output.contains("assignment failure observed"), "{output}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(/*secs*/ 5);
    loop {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe {
            QueryInformationJobObject(
                outer_job.as_raw_handle().cast(),
                JobObjectBasicAccountingInformation,
                std::ptr::addr_of_mut!(accounting).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        };
        anyhow::ensure!(queried != 0, "{}", io::Error::last_os_error());
        if accounting.ActiveProcesses == 0 {
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "assignment failure left a suspended child in the test's outer Job"
        );
        tokio::time::sleep(Duration::from_millis(/*millis*/ 10)).await;
    }
    assert!(!root.path().join("marker").exists());
    Ok(())
}
