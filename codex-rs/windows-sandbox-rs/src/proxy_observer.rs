//! Query-only access for the trusted Console proxy to attribute dedicated-account clients.

use crate::token::LocalSid;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;

/// Grants the trusted host query access to this token and objects created with its default DACL.
///
/// # Safety
/// The caller must own a valid token with READ_CONTROL, WRITE_DAC and TOKEN_ADJUST_DEFAULT.
pub unsafe fn allow_console_proxy_observer(token: HANDLE, state: &std::path::Path) -> Result<()> {
    let base = state
        .parent()
        .and_then(std::path::Path::parent)
        .context("Console proxy slot state")?;
    let owner = crate::ConsoleProxySlot::owner(base)?;
    let sid = LocalSid::from_string(&owner.user_sid)?;
    let mut needed = 0;
    unsafe {
        GetTokenInformation(
            token,
            TokenDefaultDacl,
            null_mut(),
            /*tokeninformationlength*/ 0,
            &mut needed,
        )
    };
    let mut buffer = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenDefaultDacl,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0,
        "read proxy token default DACL: {}",
        std::io::Error::last_os_error()
    );
    let default_dacl = unsafe { (*(buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>())).DefaultDacl };
    for (access, default) in [(GENERIC_READ, true), (TOKEN_QUERY, false)] {
        let mut descriptor = null_mut();
        let mut dacl = default_dacl;
        if !default {
            let status = unsafe {
                GetSecurityInfo(
                    token,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut dacl,
                    null_mut(),
                    &mut descriptor,
                )
            };
            ensure!(status == ERROR_SUCCESS, "read proxy token DACL: {status}");
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid.as_ptr().cast(),
            },
        };
        let mut updated = null_mut();
        let status = unsafe {
            SetEntriesInAclW(
                /*ccountofexplicitentries*/ 1,
                &entry,
                dacl,
                &mut updated,
            )
        };
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor as HLOCAL) };
        }
        ensure!(
            status == ERROR_SUCCESS,
            "extend proxy observer DACL: {status}"
        );
        let status = if default {
            let info = TOKEN_DEFAULT_DACL {
                DefaultDacl: updated,
            };
            if unsafe {
                SetTokenInformation(
                    token,
                    TokenDefaultDacl,
                    (&raw const info).cast(),
                    size_of::<TOKEN_DEFAULT_DACL>() as u32,
                )
            } == 0
            {
                unsafe { GetLastError() }
            } else {
                ERROR_SUCCESS
            }
        } else {
            unsafe {
                SetSecurityInfo(
                    token,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    updated,
                    null_mut(),
                )
            }
        };
        unsafe { LocalFree(updated as HLOCAL) };
        ensure!(status == ERROR_SUCCESS, "set proxy observer DACL: {status}");
    }
    Ok(())
}
