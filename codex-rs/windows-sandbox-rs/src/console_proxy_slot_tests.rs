use super::COMPLETION_FILE;
use super::ConsoleProxySlot;
use super::PoolSetupState;
use super::require_completed_pool;

#[test]
fn failed_slot_reports_its_diagnostic_to_the_outer_launcher() -> anyhow::Result<()> {
    use pretty_assertions::assert_eq;
    use std::os::windows::process::ExitStatusExt;
    let base = tempfile::tempdir()?;
    let slot = ConsoleProxySlot::new(/*index*/ 2)?;
    let child = base.path().join("proxy-slots").join("2");
    crate::write_setup_error_report(
        &child,
        &crate::SetupErrorReport {
            code: crate::SetupErrorCode::HelperSandboxLockFailed,
            message: "slot secrets ACL could not be installed".into(),
        },
    )?;
    slot.check_setup_exit(base.path(), std::process::ExitStatus::from_raw(/*raw*/ 0))?;
    assert!(crate::read_setup_error_report(base.path())?.is_none());
    let error = slot
        .check_setup_exit(base.path(), std::process::ExitStatus::from_raw(/*raw*/ 1))
        .expect_err("slot failure must not report pool completion");
    let report =
        crate::read_setup_error_report(base.path())?.expect("outer launcher failure report");
    assert_eq!(report.code, crate::SetupErrorCode::HelperSandboxLockFailed);
    assert!(
        report.message.contains("slot 2")
            && report
                .message
                .contains("slot secrets ACL could not be installed")
            && report
                .message
                .contains(&crate::setup_error_path(&child).display().to_string()),
        "{report:?}"
    );
    assert!(error.to_string().contains(&report.message), "{error:#}");
    crate::setup_error::clear_setup_error_report(&child)?;
    slot.check_setup_exit(base.path(), std::process::ExitStatus::from_raw(/*raw*/ 1))
        .expect_err("an early helper failure must identify the slot without a child report");
    let report = crate::read_setup_error_report(base.path())?.expect("fallback failure report");
    assert_eq!(
        report.code,
        crate::SetupErrorCode::OrchestratorHelperExitNonzero
    );
    assert!(
        report.message.contains("slot 2") && report.message.contains("helper did not write"),
        "{report:?}"
    );
    Ok(())
}

#[test]
fn pool_completion_requires_this_requests_receipt() -> anyhow::Result<()> {
    let state = tempfile::tempdir()?;
    let directory = crate::sandbox_secrets_dir(state.path());
    std::fs::create_dir_all(&directory)?;
    // An older helper can report base setup success without writing any receipt.
    assert!(ConsoleProxySlot::verify_completion(state.path(), "current-request").is_err());
    std::fs::write(directory.join(COMPLETION_FILE), b"previous-request")?;
    assert!(ConsoleProxySlot::verify_completion(state.path(), "current-request").is_err());
    std::fs::write(directory.join(COMPLETION_FILE), b"current-request")?;
    ConsoleProxySlot::verify_completion(state.path(), "current-request")
}

#[test]
fn reserved_pool_requires_completed_provisioning_for_admission() -> anyhow::Result<()> {
    use windows_sys::Win32::System::Registry::*;
    let directory = tempfile::tempdir()?;
    let key = format!(
        r"Software\McpConsole\Tests\{}",
        directory.path().file_name().unwrap().to_string_lossy()
    );
    let mut handle = 0;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            crate::to_wide(&key).as_ptr(),
            /*reserved*/ 0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    anyhow::ensure!(status == 0, "create isolated test registry key: {status}");
    unsafe { RegCloseKey(handle) };
    let result = (|| -> anyhow::Result<()> {
        anyhow::ensure!(
            require_completed_pool(HKEY_CURRENT_USER, &key).is_err(),
            "old registration admitted"
        );
        PoolSetupState::Pending.persist_at(HKEY_CURRENT_USER, &key)?;
        anyhow::ensure!(
            require_completed_pool(HKEY_CURRENT_USER, &key).is_err(),
            "pending migration admitted"
        );
        PoolSetupState::Complete.persist_at(HKEY_CURRENT_USER, &key)?;
        require_completed_pool(HKEY_CURRENT_USER, &key)?;
        PoolSetupState::Pending.persist_at(HKEY_CURRENT_USER, &key)?;
        anyhow::ensure!(
            require_completed_pool(HKEY_CURRENT_USER, &key).is_err(),
            "incomplete refresh admitted"
        );
        Ok(())
    })();
    unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, crate::to_wide(&key).as_ptr()) };
    result
}
