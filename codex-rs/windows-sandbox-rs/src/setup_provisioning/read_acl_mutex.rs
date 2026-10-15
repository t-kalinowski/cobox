use crate::to_wide;
use anyhow::Result;
use std::ffi::OsStr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::WAIT_ABANDONED;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::ReleaseMutex;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const READ_ACL_MUTEX_NAME: &str = "Local\\CodexSandboxReadAcl";

pub(super) struct ReadAclMutexGuard {
    handle: HANDLE,
}

impl Drop for ReadAclMutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

// Foreground metadata grants and background read grants share this lock.
// Every helper waits for its turn so a foreground grant cannot suppress a
// queued helper's content grants merely by keeping the mutex object alive.
pub(super) fn acquire_read_acl_mutex() -> Result<ReadAclMutexGuard> {
    let name = to_wide(OsStr::new(READ_ACL_MUTEX_NAME));
    let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(anyhow::anyhow!("CreateMutexW failed: {}", unsafe {
            GetLastError()
        }));
    }
    match unsafe { WaitForSingleObject(handle, INFINITE) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(ReadAclMutexGuard { handle }),
        _ => {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            Err(anyhow::anyhow!("wait for read ACL mutex failed: {error}"))
        }
    }
}
