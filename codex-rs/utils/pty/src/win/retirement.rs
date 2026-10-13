//! Confirmed retirement shared by sandboxed Windows launchers.

use crate::JobObject;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::time::Duration;
use std::time::Instant;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::CreateIoCompletionPort;
use winapi::um::ioapiset::GetQueuedCompletionStatus;
use winapi::um::jobapi2::QueryInformationJobObject;
use winapi::um::jobapi2::SetInformationJobObject;
use winapi::um::winnt::JOBOBJECT_ASSOCIATE_COMPLETION_PORT;
use winapi::um::winnt::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION;
use winapi::um::winnt::JobObjectAssociateCompletionPortInformation;
use winapi::um::winnt::JobObjectBasicAccountingInformation;

/// Terminates a workload and confirms that its non-breakaway Job is empty.
/// Callers must report failure instead of a successful cleanup receipt on error.
pub fn retire_job(job: &JobObject) -> Result<()> {
    let job_handle = job.as_raw_handle();
    let port = (|| -> Result<OwnedHandle> {
        let port = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                std::ptr::null_mut(),
                /*CompletionKey*/ 0,
                /*NumberOfConcurrentThreads*/ 1,
            )
        };
        ensure!(
            !port.is_null(),
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
                    (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT)
                        .cast_mut()
                        .cast(),
                    std::mem::size_of_val(&association) as u32,
                )
            } != 0,
            "associate Job completion port: {}",
            std::io::Error::last_os_error()
        );
        Ok(port)
    })();
    // Setup failures withhold the receipt, but must still stop the workload.
    job.terminate().context("terminate Job")?;
    let port = port?;
    let deadline = Instant::now() + Duration::from_secs(/*secs*/ 5);
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
            "Job still has active processes after termination"
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
                remaining.as_millis().max(/*other*/ 1) as u32,
            );
        }
    }
}
