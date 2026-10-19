//! Remove retired private storage without losing native deletion errors.
//!
//! Win32 maps both a retained image section and an ACL denial to access denied.
//! Keep the native disposition status so only image/sharing failures are retried.
//! Opens and enumeration stay relative to retained handles, never through a
//! workload's reparse points; unlinking must not change a hard link's attributes.

use std::ffi::c_void;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION;
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
use windows_sys::Win32::Foundation::STATUS_CANNOT_DELETE;
use windows_sys::Win32::Foundation::STATUS_DELETE_PENDING;
use windows_sys::Win32::Foundation::STATUS_NO_MORE_FILES;
use windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND;
use windows_sys::Win32::Foundation::STATUS_OBJECT_PATH_NOT_FOUND;
use windows_sys::Win32::Foundation::UNICODE_STRING;

const DELETE: u32 = 0x0001_0000;
const FILE_LIST_DIRECTORY: u32 = 1;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_ALL: u32 = 7;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_NAMES_INFORMATION: i32 = 12;
const FILE_DISPOSITION_INFORMATION: i32 = 13;
const FILE_DISPOSITION_INFORMATION_EX: i32 = 64;
const FILE_DISPOSITION_DELETE: u32 = 1;
const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 2;
const FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE: u32 = 0x10;

#[repr(C)]
#[derive(Default)]
struct IoStatus {
    status: usize,
    information: usize,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenFile(
        file: *mut HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        io: *mut IoStatus,
        share: u32,
        options: u32,
    ) -> NTSTATUS;
    fn NtQueryDirectoryFile(
        file: HANDLE,
        event: HANDLE,
        apc: *const c_void,
        context: *const c_void,
        io: *mut IoStatus,
        information: *mut c_void,
        length: u32,
        class: i32,
        single: bool,
        name: *const UNICODE_STRING,
        restart: bool,
    ) -> NTSTATUS;
    fn NtSetInformationFile(
        file: HANDLE,
        io: *mut IoStatus,
        information: *const c_void,
        length: u32,
        class: i32,
    ) -> NTSTATUS;
}

enum Failure {
    Transient(io::Error),
    Permanent(io::Error),
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
            Self::Transient(error)
        } else {
            Self::Permanent(error)
        }
    }
}

fn native_error(status: NTSTATUS) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

pub(crate) fn remove(root: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(/*secs*/ 5);
    loop {
        match remove_tree(root) {
            Ok(()) => return Ok(()),
            Err(Failure::Transient(_)) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(/*millis*/ 10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(Failure::Transient(error) | Failure::Permanent(error)) => return Err(error),
        }
    }
}

fn remove_tree(root: &Path) -> Result<(), Failure> {
    let root = OpenOptions::new()
        .access_mode(DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT)
        .open(root)?;
    let metadata = root.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return delete(&root);
    }
    let mut directories = vec![root];
    // Aligned storage for one FILE_NAMES_INFORMATION record, including the
    // longest name representable by its native UNICODE_STRING.
    let mut buffer = vec![0_u64; 8194];
    while let Some(directory) = directories.pop() {
        let Some(name) = next_name(&directory, &mut buffer)? else {
            delete(&directory)?;
            continue;
        };
        let child = open_relative(&directory, &name, DELETE | FILE_READ_ATTRIBUTES)?;
        directories.push(directory);
        let Some(child) = child else {
            continue;
        };
        let metadata = child.metadata()?;
        if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            // An empty name reopens this same directory for enumeration. A
            // renamed/replaced pathname cannot redirect the retained handle.
            if let Some(directory) = open_relative(
                &child,
                &[],
                DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            )? {
                directories.push(directory);
            }
        } else {
            delete(&child)?;
        }
    }
    Ok(())
}

fn open_relative(directory: &File, name: &[u16], access: u32) -> Result<Option<File>, Failure> {
    let length = u16::try_from(size_of_val(name)).map_err(io::Error::other)?;
    let mut encoded: Vec<_> = name.iter().copied().chain(Some(0)).collect();
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: directory.as_raw_handle(),
        object_name: &name,
        attributes: 0,
        security_descriptor: ptr::null(),
        security_quality_of_service: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let status = unsafe {
        NtOpenFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut IoStatus::default(),
            FILE_SHARE_ALL,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    match status {
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND | STATUS_DELETE_PENDING => {
            Ok(None)
        }
        status if status < 0 => Err(native_error(status).into()),
        _ => Ok(Some(unsafe { File::from_raw_handle(handle) })),
    }
}

fn next_name(directory: &File, buffer: &mut [u64]) -> Result<Option<Vec<u16>>, Failure> {
    loop {
        let mut io = IoStatus::default();
        let status = unsafe {
            NtQueryDirectoryFile(
                directory.as_raw_handle(),
                /*event*/ ptr::null_mut(),
                /*apc*/ ptr::null(),
                /*context*/ ptr::null(),
                &mut io,
                buffer.as_mut_ptr().cast(),
                size_of_val(buffer) as u32,
                FILE_NAMES_INFORMATION,
                /*single*/ true,
                /*name*/ ptr::null(),
                /*restart*/ false,
            )
        };
        if status == STATUS_NO_MORE_FILES {
            return Ok(None);
        }
        if status < 0 {
            return Err(native_error(status).into());
        }
        // FILE_NAMES_INFORMATION has three u32 fields followed by UTF-16.
        let words = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u32>(), /*len*/ 3)
        };
        let length = words[2] as usize;
        assert!(
            length.is_multiple_of(2)
                && length + 12 <= io.information
                && io.information <= size_of_val(buffer)
        );
        let name = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u16>().add(/*count*/ 6), length / 2)
        };
        if name != [b'.' as u16] && name != [b'.' as u16, b'.' as u16] {
            return Ok(Some(name.to_vec()));
        }
    }
}

fn delete(file: &File) -> Result<(), Failure> {
    let flags = FILE_DISPOSITION_DELETE
        | FILE_DISPOSITION_POSIX_SEMANTICS
        | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    let mut io = IoStatus::default();
    let mut status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut io,
            (&raw const flags).cast(),
            size_of_val(&flags) as u32,
            FILE_DISPOSITION_INFORMATION_EX,
        )
    };
    if status >= 0 {
        return Ok(());
    }
    if matches!(
        native_error(status).raw_os_error().map(|code| code as u32),
        Some(ERROR_INVALID_FUNCTION | ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
    ) {
        // Match std's compatibility with filesystems lacking POSIX deletion.
        // This changes disposition only, never a surviving hard link's mode.
        let delete = true;
        status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io,
                (&raw const delete).cast(),
                size_of_val(&delete) as u32,
                FILE_DISPOSITION_INFORMATION,
            )
        };
        if status == STATUS_CANNOT_DELETE && file.metadata()?.permissions().readonly() {
            return Err(Failure::Permanent(native_error(status)));
        }
    }
    if status >= 0 {
        Ok(())
    } else if status == STATUS_CANNOT_DELETE {
        // Unlike STATUS_ACCESS_DENIED, this reports the retained image section
        // (read-only attributes were explicitly allowed by the native request).
        Err(Failure::Transient(native_error(status)))
    } else {
        Err(native_error(status).into())
    }
}
