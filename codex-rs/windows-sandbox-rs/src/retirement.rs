//! Console generations require confirmed retirement of the native Job.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_utils_pty::JobObject;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::IO::*;
use windows_sys::Win32::System::JobObjects::*;

/// Terminates a Console workload and confirms that its non-breakaway Job is empty.
/// Callers must report failure instead of a successful cleanup receipt on error.
pub fn retire_console_job(job: &JobObject) -> Result<()> {
    let job_handle = job.as_raw_handle();
    let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 1) };
    ensure!(
        port != 0,
        "create Job completion port: {}",
        std::io::Error::last_os_error()
    );
    let port = unsafe { OwnedHandle::from_raw_handle(port as _) };
    let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: job_handle,
        CompletionPort: port.as_raw_handle() as _,
    };
    ensure!(
        unsafe {
            SetInformationJobObject(
                job_handle as _,
                JobObjectAssociateCompletionPortInformation,
                (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                std::mem::size_of_val(&association) as u32,
            )
        } != 0,
        "associate Job completion port: {}",
        std::io::Error::last_os_error()
    );
    job.terminate().context("terminate Console Job")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                QueryInformationJobObject(
                    job_handle as _,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&accounting) as u32,
                    std::ptr::null_mut(),
                )
            } != 0,
            "query retired Job: {}",
            std::io::Error::last_os_error()
        );
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "Console Job still has active processes after termination"
        );
        let (mut message, mut key, mut overlapped) = (0, 0, std::ptr::null_mut());
        // Wake on native Job notifications. The following query is the receipt;
        // a missing notification is checked once more at the explicit deadline.
        unsafe {
            GetQueuedCompletionStatus(
                port.as_raw_handle() as _,
                &mut message,
                &mut key,
                &mut overlapped,
                remaining.as_millis().max(1) as u32,
            );
        }
    }
}
