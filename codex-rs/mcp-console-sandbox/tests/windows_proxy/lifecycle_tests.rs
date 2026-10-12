use super::*;
use pretty_assertions::assert_eq;

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_descendants_retire_before_slot_reuse() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::System::Threading::*;
    let mut session = Session::start(proxy())?;
    let child = session.probe(json!({"op":"descendant"}))?;
    let lease_path = session.lease_path()?;
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            /*binherithandle*/ 0,
            child["pid"].as_u64().context("descendant pid")? as u32,
        )
    };
    anyhow::ensure!(
        !handle.is_null(),
        "open descendant: {}",
        std::io::Error::last_os_error()
    );
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    session.finish()?;
    assert_eq!(
        unsafe {
            WaitForSingleObject(handle.as_raw_handle(), /*dwmilliseconds*/ 0)
        },
        windows_sys::Win32::Foundation::WAIT_OBJECT_0
    );
    let replacement = Session::start(proxy())?;
    assert_eq!(replacement.lease_path()?, lease_path);
    replacement.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_owner_death_cancels_and_releases_resources() -> Result<()> {
    let mut owner = Command::new("cmd.exe")
        .args(["/d", "/c", "pause"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let mut session =
        Session::start_with(proxy(), json!({"lifecycle":{"parent_pid":owner.id()}}), &[])?;
    let endpoint = session.http_endpoint()?.to_owned();
    let lease_path = session.lease_path()?;
    let child = session.probe(json!({"op":"descendant"}))?;
    let processes = observe_processes(&[&session.ready["pid"], &child["pid"]])?;
    owner.kill()?;
    owner.wait()?;
    let status = wait_for_exit(&mut session.child)?;
    assert_ne!(
        status.code(),
        Some(125),
        "owner death lacked native retirement"
    );
    assert_eq!(std::fs::read_to_string(session.error.path())?, "");
    assert_processes_retired(&processes);
    assert!(TcpStream::connect(endpoint.strip_prefix("http://").unwrap()).is_err());
    let replacement = Session::start(proxy())?;
    assert_eq!(replacement.lease_path()?, lease_path);
    replacement.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_companion_loss_retires_job_but_quarantines_its_slot() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::System::Threading::*;
    let mut first = Session::start(proxy())?;
    let child = first.probe(json!({"op":"descendant"}))?;
    let mut processes = Vec::new();
    for pid in [&first.ready["pid"], &child["pid"]] {
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE,
                /*binherithandle*/ 0,
                pid.as_u64().context("process id")? as u32,
            )
        };
        anyhow::ensure!(
            !handle.is_null(),
            "observe workload: {}",
            std::io::Error::last_os_error()
        );
        processes.push(unsafe { OwnedHandle::from_raw_handle(handle) });
    }
    let temporary = std::path::PathBuf::from(
        first.ready["environment"]["TMPDIR"]
            .as_str()
            .context("temporary")?,
    );
    let endpoint = first.http_endpoint()?.to_owned();
    first.child.kill()?;
    assert!(!wait_for_exit(&mut first.child)?.success());
    for process in processes {
        assert_eq!(
            unsafe {
                WaitForSingleObject(process.as_raw_handle(), /*dwmilliseconds*/ 10_000)
            },
            windows_sys::Win32::Foundation::WAIT_OBJECT_0
        );
    }
    assert!(
        temporary.exists(),
        "killed companion cannot acknowledge cleanup"
    );
    assert!(TcpStream::connect(endpoint.strip_prefix("http://").unwrap()).is_err());
    let second = Session::start(proxy())?;
    let error = Session::start(proxy())
        .err()
        .context("unconfirmed slot reused")?;
    assert!(
        error.to_string().contains("busy or quarantined"),
        "{error:#}"
    );
    second.finish()?;
    // This fixture creates exactly the two observed Job members. The independent observer
    // confirmed both deaths; only now may this test clean up its deliberately killed session.
    std::fs::remove_dir_all(temporary.parent().context("private storage parent")?)?;
    std::fs::remove_file(first.lease_path()?)?;
    Session::start(proxy())?.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_cleanup_failure_quarantines_slot_until_resources_are_retired() -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
    let mut first = Session::start(proxy())?;
    let child = first.probe(json!({"op":"descendant"}))?;
    let processes = observe_processes(&[&first.ready["pid"], &child["pid"]])?;
    let temporary = std::path::PathBuf::from(
        first.ready["environment"]["TMPDIR"]
            .as_str()
            .context("temporary")?,
    );
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(temporary.join("held-by-descendant"))?;
    first.child.stdin.take();
    assert_eq!(wait_for_exit(&mut first.child)?.code(), Some(1));
    let error = std::fs::read_to_string(first.error.path())?;
    assert!(
        error.contains("remove retired Windows private storage"),
        "{error}"
    );
    assert_processes_retired(&processes);
    let second = Session::start(proxy())?;
    let error = Session::start(proxy())
        .err()
        .context("quarantined slot was reused")?;
    assert!(
        error.to_string().contains("busy or quarantined"),
        "{error:#}"
    );
    second.finish()?;
    // The diagnostic above is reachable only after native Job retirement. Complete the
    // deliberately blocked cleanup, then retire this test's own durable quarantine record.
    drop(held);
    std::fs::remove_dir_all(temporary.parent().context("private storage parent")?)?;
    std::fs::remove_file(first.lease_path()?)?;
    Session::start(proxy())?.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_helper_loss_withholds_retirement_receipt() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::System::Threading::*;
    let mut first = Session::start(proxy())?;
    let child = first.probe(json!({"op":"descendant"}))?;
    let processes = observe_processes(&[&first.ready["pid"], &child["pid"]])?;
    let runner = first.probe(json!({"op":"parent-pid"}))?;
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE,
            /*binherithandle*/ 0,
            runner.as_u64().context("runner pid")? as u32,
        )
    };
    anyhow::ensure!(
        !handle.is_null(),
        "open native helper for loss probe: {}",
        std::io::Error::last_os_error()
    );
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    anyhow::ensure!(
        unsafe {
            TerminateProcess(handle.as_raw_handle(), /*uexitcode*/ 91)
        } != 0,
        "terminate native helper"
    );
    assert_eq!(wait_for_exit(&mut first.child)?.code(), Some(125));
    assert_processes_retired(&processes);
    let temporary = std::path::PathBuf::from(
        first.ready["environment"]["TMPDIR"]
            .as_str()
            .context("temporary")?,
    );
    assert!(temporary.exists());
    assert!(first.lease_path()?.exists());
    let second = Session::start(proxy())?;
    assert!(Session::start(proxy()).is_err());
    second.finish()?;
    std::fs::remove_dir_all(temporary.parent().context("private storage parent")?)?;
    std::fs::remove_file(first.lease_path()?)?;
    Ok(())
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_prelaunch_failure_does_not_consume_a_slot() -> Result<()> {
    for _ in 0..3 {
        let error =
            Session::start_with(proxy(), json!({"lifecycle":{"parent_pid":2147483647}}), &[])
                .err()
                .context("invalid owner accepted")?;
        assert!(
            error.to_string().contains("cannot monitor sandbox owner"),
            "{error:#}"
        );
    }
    let first = Session::start(proxy())?;
    let second = Session::start(proxy())?;
    second.finish()?;
    first.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_nonzero_exit_receipts_release_the_same_slot() -> Result<()> {
    let mut expected = None;
    for code in [125, -1, 0] {
        let mut session = Session::start(proxy())?;
        let lease = session.lease_path()?;
        if let Some(expected) = &expected {
            assert_eq!(&lease, expected);
        }
        expected = Some(lease.clone());
        writeln!(
            session.child.stdin.as_mut().context("stdin")?,
            "{}",
            json!({"op":"exit", "code":code})
        )?;
        session.finish_with_code(code)?;
        assert!(!lease.exists());
    }
    Ok(())
}
