//! Execute copied filesystem requests through descriptor-pinned paths.
//!
//! A notification is never continued after inspecting pointer arguments: the
//! caller can change them while the broker is running. Read-only `open` calls
//! and a small set of scalar-selected, non-filesystem ioctls are the exceptions;
//! their immutable syscall arguments establish that they cannot mutate paths.

use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::sync::Mutex;

use super::Outcome;
use super::Request;
use super::paths::Policy;
use super::paths::ResolvedPath;
use super::paths::capture_cwd;
use super::paths::capture_fd;

const XATTR_SIZE_MAX: usize = 65_536;
// Pathname bind has no *at form. Keep the workload's directory entries stable
// from lookup through native bind while retaining its original socket address.
// Host-side filesystem changes remain outside this serialization boundary.
static DIRECTORY_MUTATIONS: Mutex<()> = Mutex::new(());

fn changes_directory_entries(call: i64) -> bool {
    #[cfg(target_arch = "x86_64")]
    if matches!(
        call,
        libc::SYS_mkdir
            | libc::SYS_mknod
            | libc::SYS_symlink
            | libc::SYS_link
            | libc::SYS_unlink
            | libc::SYS_rmdir
            | libc::SYS_rename
    ) {
        return true;
    }
    matches!(
        call,
        libc::SYS_mkdirat
            | libc::SYS_mknodat
            | libc::SYS_symlinkat
            | libc::SYS_linkat
            | libc::SYS_unlinkat
            | libc::SYS_renameat
            | libc::SYS_renameat2
            | libc::SYS_bind
    )
}

/// Keep filter coverage and dispatch together so an added handler cannot be
/// accidentally left outside the notification filter.
pub(super) fn intercepted_syscalls() -> Vec<i64> {
    let mut calls = vec![
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchmodat2,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_bind,
        libc::SYS_ioctl,
    ];
    #[cfg(target_arch = "x86_64")]
    calls.extend([
        libc::SYS_open,
        libc::SYS_creat,
        libc::SYS_mkdir,
        libc::SYS_mknod,
        libc::SYS_symlink,
        libc::SYS_link,
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_rename,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ]);
    calls
}

pub(super) fn dispatch(request: &Request, policy: &Policy) -> io::Result<Outcome> {
    let a = request.args;
    let call = i64::from(request.syscall);
    let _directory_guard = if changes_directory_entries(call) {
        Some(DIRECTORY_MUTATIONS.lock().map_err(|_| errno(libc::EIO))?)
    } else {
        None
    };
    match call {
        libc::SYS_openat => open(request, policy, a[0] as i32, a[1], a[2], a[3]),
        libc::SYS_openat2 => openat2(request, policy),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_open => open(request, policy, libc::AT_FDCWD, a[0], a[1], a[2]),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_creat => open(
            request,
            policy,
            libc::AT_FDCWD,
            a[0],
            (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64,
            a[1],
        ),
        libc::SYS_mkdirat => mkdir(request, policy, a[0] as i32, a[1], a[2]),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mkdir => mkdir(request, policy, libc::AT_FDCWD, a[0], a[1]),
        libc::SYS_mknodat => mknod(request, policy, a[0] as i32, a[1], a[2], a[3]),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mknod => mknod(request, policy, libc::AT_FDCWD, a[0], a[1], a[2]),
        libc::SYS_symlinkat => symlink(request, policy, a[0], a[1] as i32, a[2]),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_symlink => symlink(request, policy, a[0], libc::AT_FDCWD, a[1]),
        libc::SYS_linkat => link(
            request,
            policy,
            a[0] as i32,
            a[1],
            a[2] as i32,
            a[3],
            a[4] as i32,
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_link => link(
            request,
            policy,
            libc::AT_FDCWD,
            a[0],
            libc::AT_FDCWD,
            a[1],
            0,
        ),
        libc::SYS_unlinkat => unlink(request, policy, a[0] as i32, a[1], a[2] as i32),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_unlink => unlink(request, policy, libc::AT_FDCWD, a[0], 0),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rmdir => unlink(request, policy, libc::AT_FDCWD, a[0], libc::AT_REMOVEDIR),
        libc::SYS_renameat => rename(request, policy, a[0] as i32, a[1], a[2] as i32, a[3], 0),
        libc::SYS_renameat2 => rename(
            request,
            policy,
            a[0] as i32,
            a[1],
            a[2] as i32,
            a[3],
            a[4] as u32,
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rename => rename(
            request,
            policy,
            libc::AT_FDCWD,
            a[0],
            libc::AT_FDCWD,
            a[1],
            0,
        ),
        libc::SYS_truncate => truncate(request, policy, a[0], a[1] as libc::off_t),
        libc::SYS_ftruncate => {
            let fd = duplicate_fd(request, a[0] as i32)?;
            policy.check_fd(&fd)?;
            request.is_valid()?;
            value(unsafe { libc::ftruncate(fd.as_raw_fd(), a[1] as libc::off_t) } as i64)
        }
        libc::SYS_fchmod => fd_chmod(request, policy, a[0] as i32, a[1] as libc::mode_t),
        libc::SYS_fchmodat => chmod(request, policy, a[0] as i32, a[1], a[2] as libc::mode_t, 0),
        libc::SYS_fchmodat2 => chmod(
            request,
            policy,
            a[0] as i32,
            a[1],
            a[2] as libc::mode_t,
            a[3] as i32,
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chmod => chmod(
            request,
            policy,
            libc::AT_FDCWD,
            a[0],
            a[1] as libc::mode_t,
            0,
        ),
        libc::SYS_fchown => fd_chown(
            request,
            policy,
            a[0] as i32,
            a[1] as libc::uid_t,
            a[2] as libc::gid_t,
        ),
        libc::SYS_fchownat => chown(
            request,
            policy,
            a[0] as i32,
            a[1],
            a[2] as libc::uid_t,
            a[3] as libc::gid_t,
            a[4] as i32,
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chown => chown(
            request,
            policy,
            libc::AT_FDCWD,
            a[0],
            a[1] as libc::uid_t,
            a[2] as libc::gid_t,
            0,
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lchown => chown(
            request,
            policy,
            libc::AT_FDCWD,
            a[0],
            a[1] as libc::uid_t,
            a[2] as libc::gid_t,
            libc::AT_SYMLINK_NOFOLLOW,
        ),
        libc::SYS_utimensat => utimens(request, policy, a[0] as i32, a[1], a[2], a[3] as i32),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_utime => legacy_times(request, policy, libc::AT_FDCWD, a[0], a[1], true),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_utimes => legacy_times(request, policy, libc::AT_FDCWD, a[0], a[1], false),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_futimesat => legacy_times(request, policy, a[0] as i32, a[1], a[2], false),
        libc::SYS_setxattr
        | libc::SYS_lsetxattr
        | libc::SYS_fsetxattr
        | libc::SYS_removexattr
        | libc::SYS_lremovexattr
        | libc::SYS_fremovexattr => xattr(request, policy),
        libc::SYS_bind => bind(request, policy),
        libc::SYS_ioctl => ioctl(a[1] as u32),
        _ => Err(errno(libc::EOPNOTSUPP)),
    }
}

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn value(result: i64) -> io::Result<Outcome> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Outcome::Value(result))
    }
}

fn owned(result: i32) -> io::Result<OwnedFd> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful syscall returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(result) })
    }
}

fn fd_path(fd: &OwnedFd) -> CString {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .unwrap_or_else(|_| panic!("descriptor path"))
}

fn resolve(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    path: &CStr,
    follow: bool,
) -> io::Result<ResolvedPath> {
    let resolved = policy.resolve(request.tid, dirfd, path, follow)?;
    request.is_valid()?;
    policy.check(&resolved)?;
    Ok(resolved)
}

fn existing(path: &ResolvedPath) -> io::Result<&OwnedFd> {
    path.existing.as_ref().ok_or_else(|| errno(libc::ENOENT))
}

fn file_type(fd: &OwnedFd) -> io::Result<libc::mode_t> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT)
}

fn copied<T: Copy>(request: &Request, address: u64) -> io::Result<T> {
    let bytes = request.read_bytes(address, size_of::<T>())?;
    // SAFETY: the copied buffer has exactly the requested object's size and
    // callers use this only for integer-only Linux syscall ABI structures.
    Ok(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

/// A worker owns its fs_struct before setting umask; masking mode manually
/// would incorrectly apply umask when the parent has a default ACL.
fn creation_umask(request: &Request) -> io::Result<()> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", request.tid))?;
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:\t"))
        .and_then(|mask| u32::from_str_radix(mask.trim(), 8).ok())
        .ok_or_else(|| errno(libc::EIO))?;
    request.is_valid()?;
    if unsafe { libc::unshare(libc::CLONE_FS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::umask(mask as libc::mode_t) };
    Ok(())
}

fn mutating_open(flags: i32) -> bool {
    flags & libc::O_PATH == 0
        && (flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_CREAT | libc::O_TRUNC) != 0
            || flags & libc::O_TMPFILE == libc::O_TMPFILE)
}

fn open(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    flags: u64,
    mode: u64,
) -> io::Result<Outcome> {
    let flags = flags as i32;
    if !mutating_open(flags) {
        return Ok(Outcome::Continue);
    }
    let path = request.read_cstring(address)?;
    open_copied(request, policy, dirfd, &path, flags, mode as libc::mode_t)
}

fn openat2(request: &Request, policy: &Policy) -> io::Result<Outcome> {
    // The kernel accepts future zero-filled tails, but this implementation
    // deliberately supports the current three-field ABI only.
    if request.args[3] != 24 {
        return Err(errno(libc::EOPNOTSUPP));
    }
    let how: [u64; 3] = copied(request, request.args[2])?;
    let path = request.read_cstring(request.args[1])?;
    if how[2] != 0 || how[0] > i32::MAX as u64 || how[1] & !0o7777 != 0 {
        return Err(errno(libc::EOPNOTSUPP));
    }
    let flags = how[0] as i32;
    let known = libc::O_ACCMODE
        | libc::O_APPEND
        | libc::O_ASYNC
        | libc::O_CLOEXEC
        | libc::O_CREAT
        | libc::O_DIRECT
        | libc::O_DIRECTORY
        | libc::O_DSYNC
        | libc::O_EXCL
        | libc::O_LARGEFILE
        | 0o100000 // The kernel O_LARGEFILE bit is hidden by 64-bit libc.
        | libc::O_NOATIME
        | libc::O_NOCTTY
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_PATH
        | libc::O_SYNC
        | libc::O_TMPFILE
        | libc::O_TRUNC;
    if flags & !known != 0
        || (how[1] != 0 && flags & libc::O_CREAT == 0 && flags & libc::O_TMPFILE != libc::O_TMPFILE)
        || (flags & libc::O_PATH != 0
            && flags & !(libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
                != 0)
    {
        return Err(errno(libc::EINVAL));
    }
    // Even read-only opens must be emulated here: flags were copied from
    // mutable caller memory, unlike the scalar flags of open/openat.
    open_copied(
        request,
        policy,
        request.args[0] as i32,
        &path,
        flags,
        how[1] as libc::mode_t,
    )
}

fn open_copied(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    path: &CStr,
    flags: i32,
    mode: libc::mode_t,
) -> io::Result<Outcome> {
    let exclusive_create = flags & (libc::O_CREAT | libc::O_EXCL) == libc::O_CREAT | libc::O_EXCL;
    let resolved = policy.resolve(
        request.tid,
        dirfd,
        path,
        (flags & libc::O_NOFOLLOW == 0 || path.to_bytes().ends_with(b"/")) && !exclusive_create,
    )?;
    request.is_valid()?;
    if mutating_open(flags) {
        policy.check(&resolved)?;
    }
    if flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE {
        creation_umask(request)?;
    }
    request.is_valid()?;
    let descriptor = if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        let directory = existing(&resolved)?;
        owned(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                flags | libc::O_CLOEXEC,
                mode,
            )
        })?
    } else {
        if resolved.trailing_slash && flags & libc::O_CREAT != 0 {
            return Err(errno(libc::EISDIR));
        }
        let name = if resolved.trailing_slash {
            CString::new(&resolved.name.to_bytes()[..resolved.name.to_bytes().len() - 1])
                .unwrap_or_else(|_| panic!("resolved basename"))
        } else {
            resolved.name
        };
        // Keep O_CREAT and the real parent: reopening an existing inode through
        // procfs would bypass protected_regular/protected_fifos sticky-parent
        // checks. A replacement final symlink fails instead of being followed.
        let flags = flags
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if resolved.trailing_slash {
                libc::O_DIRECTORY
            } else {
                0
            };
        request.is_valid()?;
        owned(unsafe { libc::openat(resolved.parent.as_raw_fd(), name.as_ptr(), flags, mode) })?
    };
    Ok(Outcome::Opened(descriptor, flags & libc::O_CLOEXEC != 0))
}

fn mkdir(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    mode: u64,
) -> io::Result<Outcome> {
    let path = request.read_cstring(address)?;
    let target = resolve(request, policy, dirfd, &path, false)?;
    creation_umask(request)?;
    request.is_valid()?;
    value(unsafe {
        libc::mkdirat(
            target.parent.as_raw_fd(),
            target.name.as_ptr(),
            mode as libc::mode_t,
        )
    } as i64)
}

fn mknod(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    mode: u64,
    device: u64,
) -> io::Result<Outcome> {
    let path = request.read_cstring(address)?;
    let target = resolve(request, policy, dirfd, &path, false)?;
    creation_umask(request)?;
    request.is_valid()?;
    value(unsafe {
        libc::mknodat(
            target.parent.as_raw_fd(),
            target.name.as_ptr(),
            mode as libc::mode_t,
            device as libc::dev_t,
        )
    } as i64)
}

fn symlink(
    request: &Request,
    policy: &Policy,
    source_address: u64,
    dirfd: i32,
    target_address: u64,
) -> io::Result<Outcome> {
    let source = request.read_cstring(source_address)?;
    let path = request.read_cstring(target_address)?;
    let target = resolve(request, policy, dirfd, &path, false)?;
    request.is_valid()?;
    value(unsafe {
        libc::symlinkat(
            source.as_ptr(),
            target.parent.as_raw_fd(),
            target.name.as_ptr(),
        )
    } as i64)
}

fn link(
    request: &Request,
    policy: &Policy,
    olddir: i32,
    old_address: u64,
    newdir: i32,
    new_address: u64,
    flags: i32,
) -> io::Result<Outcome> {
    let old = request.read_cstring(old_address)?;
    let new = request.read_cstring(new_address)?;
    if flags & !(libc::AT_SYMLINK_FOLLOW | libc::AT_EMPTY_PATH) != 0 {
        return Err(errno(libc::EINVAL));
    }
    let destination = resolve(request, policy, newdir, &new, false)?;
    let source = if old.is_empty() && flags & libc::AT_EMPTY_PATH != 0 {
        let source = capture_fd(request.tid, olddir)?;
        request.is_valid()?;
        policy.check_fd(&source)?;
        source
    } else {
        let source = resolve(
            request,
            policy,
            olddir,
            &old,
            flags & libc::AT_SYMLINK_FOLLOW != 0,
        )?;
        existing(&source)?.try_clone()?
    };
    // Linux's proc fd link preserves the pinned inode and mount. Following
    // that magic link is also the unprivileged way to link an O_TMPFILE fd.
    let source_path = fd_path(&source);
    request.is_valid()?;
    value(unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source_path.as_ptr(),
            destination.parent.as_raw_fd(),
            destination.name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } as i64)
}

fn unlink(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    flags: i32,
) -> io::Result<Outcome> {
    if flags & !libc::AT_REMOVEDIR != 0 {
        return Err(errno(libc::EINVAL));
    }
    let path = request.read_cstring(address)?;
    let target = resolve(request, policy, dirfd, &path, false)?;
    policy.check_removal(&target)?;
    request.is_valid()?;
    value(unsafe { libc::unlinkat(target.parent.as_raw_fd(), target.name.as_ptr(), flags) } as i64)
}

fn rename(
    request: &Request,
    policy: &Policy,
    olddir: i32,
    old_address: u64,
    newdir: i32,
    new_address: u64,
    flags: u32,
) -> io::Result<Outcome> {
    let old = request.read_cstring(old_address)?;
    let new = request.read_cstring(new_address)?;
    let source = resolve(request, policy, olddir, &old, false)?;
    let destination = resolve(request, policy, newdir, &new, false)?;
    policy.check_removal(&source)?;
    policy.check_removal(&destination)?;
    request.is_valid()?;
    value(unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source.parent.as_raw_fd(),
            source.name.as_ptr(),
            destination.parent.as_raw_fd(),
            destination.name.as_ptr(),
            flags,
        )
    } as i64)
}

fn truncate(
    request: &Request,
    policy: &Policy,
    address: u64,
    length: libc::off_t,
) -> io::Result<Outcome> {
    let path = request.read_cstring(address)?;
    let target = resolve(request, policy, libc::AT_FDCWD, &path, true)?;
    let pinned = fd_path(existing(&target)?);
    request.is_valid()?;
    value(unsafe { libc::truncate(pinned.as_ptr(), length) } as i64)
}

fn metadata_fd(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    flags: i32,
) -> io::Result<OwnedFd> {
    if flags & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) != 0 {
        return Err(errno(libc::EINVAL));
    }
    let path = request.read_cstring(address)?;
    if path.is_empty() && flags & libc::AT_EMPTY_PATH != 0 {
        let fd = capture_fd(request.tid, dirfd)?;
        request.is_valid()?;
        policy.check_fd(&fd)?;
        return Ok(fd);
    }
    let target = resolve(
        request,
        policy,
        dirfd,
        &path,
        flags & libc::AT_SYMLINK_NOFOLLOW == 0,
    )?;
    existing(&target)?.try_clone()
}

fn chmod(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    mode: libc::mode_t,
    flags: i32,
) -> io::Result<Outcome> {
    let fd = metadata_fd(request, policy, dirfd, address, flags)?;
    chmod_pinned(request, &fd, mode)
}

fn fd_chmod(
    request: &Request,
    policy: &Policy,
    number: i32,
    mode: libc::mode_t,
) -> io::Result<Outcome> {
    let fd = duplicate_fd(request, number)?;
    policy.check_fd(&fd)?;
    request.is_valid()?;
    value(unsafe { libc::fchmod(fd.as_raw_fd(), mode) } as i64)
}

fn chmod_pinned(request: &Request, fd: &OwnedFd, mode: libc::mode_t) -> io::Result<Outcome> {
    if file_type(fd)? == libc::S_IFLNK {
        return Err(errno(libc::EOPNOTSUPP));
    }
    let path = fd_path(fd);
    request.is_valid()?;
    value(unsafe { libc::chmod(path.as_ptr(), mode) } as i64)
}

fn chown(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    uid: libc::uid_t,
    gid: libc::gid_t,
    flags: i32,
) -> io::Result<Outcome> {
    let fd = metadata_fd(request, policy, dirfd, address, flags)?;
    chown_pinned(request, &fd, uid, gid)
}

fn fd_chown(
    request: &Request,
    policy: &Policy,
    number: i32,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<Outcome> {
    let fd = duplicate_fd(request, number)?;
    policy.check_fd(&fd)?;
    request.is_valid()?;
    value(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) } as i64)
}

fn chown_pinned(
    request: &Request,
    fd: &OwnedFd,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<Outcome> {
    request.is_valid()?;
    value(unsafe {
        libc::fchownat(
            fd.as_raw_fd(),
            c"".as_ptr(),
            uid,
            gid,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    } as i64)
}

fn utimens(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    times_address: u64,
    flags: i32,
) -> io::Result<Outcome> {
    let times: Option<[libc::timespec; 2]> = if times_address == 0 {
        None
    } else {
        Some(copied(request, times_address)?)
    };
    if address == 0 {
        if flags != 0 {
            return Err(errno(libc::EINVAL));
        }
        return fd_times(request, policy, dirfd, times.as_ref());
    }
    let fd = metadata_fd(request, policy, dirfd, address, flags)?;
    times_pinned(request, &fd, times.as_ref())
}

#[cfg(target_arch = "x86_64")]
fn legacy_times(
    request: &Request,
    policy: &Policy,
    dirfd: i32,
    address: u64,
    times_address: u64,
    seconds: bool,
) -> io::Result<Outcome> {
    let times = if times_address == 0 {
        None
    } else if seconds {
        let old: libc::utimbuf = copied(request, times_address)?;
        Some([
            libc::timespec {
                tv_sec: old.actime,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: old.modtime,
                tv_nsec: 0,
            },
        ])
    } else {
        let old: [libc::timeval; 2] = copied(request, times_address)?;
        if old
            .iter()
            .any(|value| !(0..1_000_000).contains(&value.tv_usec))
        {
            return Err(errno(libc::EINVAL));
        }
        Some(old.map(|value| libc::timespec {
            tv_sec: value.tv_sec,
            tv_nsec: value.tv_usec * 1000,
        }))
    };
    if address == 0 {
        return fd_times(request, policy, dirfd, times.as_ref());
    }
    let fd = metadata_fd(request, policy, dirfd, address, 0)?;
    times_pinned(request, &fd, times.as_ref())
}

fn fd_times(
    request: &Request,
    policy: &Policy,
    number: i32,
    times: Option<&[libc::timespec; 2]>,
) -> io::Result<Outcome> {
    let fd = duplicate_fd(request, number)?;
    policy.check_fd(&fd)?;
    let times = times.map_or(std::ptr::null(), |times| times.as_ptr());
    request.is_valid()?;
    value(unsafe { libc::futimens(fd.as_raw_fd(), times) } as i64)
}

fn times_pinned(
    request: &Request,
    fd: &OwnedFd,
    times: Option<&[libc::timespec; 2]>,
) -> io::Result<Outcome> {
    let times = times.map_or(std::ptr::null(), |times| times.as_ptr());
    request.is_valid()?;
    if file_type(fd)? == libc::S_IFLNK {
        // Linux 6.6 added empty-path utimensat. Older kernels fail closed for
        // the uncommon operation on a pinned symlink rather than following it.
        value(unsafe {
            libc::utimensat(
                fd.as_raw_fd(),
                c"".as_ptr(),
                times,
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        } as i64)
    } else {
        let path = fd_path(fd);
        value(unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times, 0) } as i64)
    }
}

fn xattr(request: &Request, policy: &Policy) -> io::Result<Outcome> {
    let a = request.args;
    let call = i64::from(request.syscall);
    let fd_form = matches!(call, libc::SYS_fsetxattr | libc::SYS_fremovexattr);
    let remove = matches!(
        call,
        libc::SYS_removexattr | libc::SYS_lremovexattr | libc::SYS_fremovexattr
    );
    let follow = !matches!(call, libc::SYS_lsetxattr | libc::SYS_lremovexattr);
    let path = if fd_form {
        None
    } else {
        Some(request.read_cstring(a[0])?)
    };
    let name = request.read_cstring(a[1])?;
    let data = if remove {
        Vec::new()
    } else {
        if a[3] > XATTR_SIZE_MAX as u64 {
            return Err(errno(libc::E2BIG));
        }
        request.read_bytes(a[2], a[3] as usize)?
    };
    if fd_form {
        let fd = duplicate_fd(request, a[0] as i32)?;
        policy.check_fd(&fd)?;
        request.is_valid()?;
        let result = if remove {
            unsafe { libc::fremovexattr(fd.as_raw_fd(), name.as_ptr()) }
        } else {
            unsafe {
                libc::fsetxattr(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    data.as_ptr().cast(),
                    data.len(),
                    a[4] as i32,
                )
            }
        };
        return value(result as i64);
    }
    let path = resolve(
        request,
        policy,
        libc::AT_FDCWD,
        &path.unwrap_or_else(|| panic!("pathname xattr")),
        follow,
    )?;
    let fd = existing(&path)?;
    // The older xattr API has no empty-path form, and lsetxattr on a proc fd
    // link would address that proc link. Do not follow a pinned symlink.
    if file_type(fd)? == libc::S_IFLNK {
        return Err(errno(libc::EOPNOTSUPP));
    }
    let path = fd_path(fd);
    request.is_valid()?;
    let result = if remove {
        unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) }
    } else {
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
                a[4] as i32,
            )
        }
    };
    value(result as i64)
}

fn duplicate_fd(request: &Request, number: RawFd) -> io::Result<OwnedFd> {
    // clone/unshare/close_range filters guarantee that threads in a group
    // share their descriptor table. pidfd_open on a nonleader is unavailable
    // on supported kernels, so obtain its leader explicitly.
    let status = std::fs::read_to_string(format!("/proc/{}/status", request.tid))?;
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:\t"))
        .and_then(|pid| pid.trim().parse::<libc::pid_t>().ok())
        .ok_or_else(|| errno(libc::EIO))?;
    let pidfd = owned(unsafe { libc::syscall(libc::SYS_pidfd_open, tgid, 0) } as i32)?;
    request.is_valid()?;
    let descriptor =
        owned(
            unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), number, 0) } as i32,
        )?;
    request.is_valid()?;
    Ok(descriptor)
}

fn bind(request: &Request, policy: &Policy) -> io::Result<Outcome> {
    let length = request.args[2] as usize;
    if length < size_of::<libc::sa_family_t>() || length > size_of::<libc::sockaddr_storage>() {
        return Err(errno(libc::EINVAL));
    }
    let bytes = request.read_bytes(request.args[1], length)?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    if family == libc::AF_UNIX {
        if length > size_of::<libc::sockaddr_un>() {
            return Err(errno(libc::EINVAL));
        }
        let name = &bytes[size_of::<libc::sa_family_t>()..];
        if name.first().is_some_and(|first| *first != 0) {
            let end = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len());
            let path = CString::new(&name[..end]).map_err(|_| errno(libc::EINVAL))?;
            let cwd = capture_cwd(request.tid)?;
            request.is_valid()?;
            // This request owns its fs_struct before changing cwd or umask.
            // The directory-mutation guard prevents sandbox rename/symlink
            // races between this lookup and bind's own native pathname walk.
            creation_umask(request)?;
            if unsafe { libc::fchdir(cwd.as_raw_fd()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let target = policy.resolve_from(&cwd, &path, false)?;
            policy.check(&target)?;
        }
    }
    let socket = duplicate_fd(request, request.args[0] as i32)?;
    request.is_valid()?;
    value(unsafe {
        libc::bind(
            socket.as_raw_fd(),
            bytes.as_ptr().cast(),
            length as libc::socklen_t,
        )
    } as i64)
}

fn ioctl(operation: u32) -> io::Result<Outcome> {
    // These requests change descriptor/terminal state or read information;
    // none interprets a pathname or changes filesystem contents/metadata.
    // Unknown requests include filesystem-specific mutation ioctls and fail
    // closed even when the caller originally opened the file read-only.
    let safe = [
        libc::FIOCLEX as u32,
        libc::FIONCLEX as u32,
        libc::FIONBIO as u32,
        libc::FIONREAD as u32,
        libc::TCGETS as u32,
        libc::TCSETS as u32,
        libc::TCSETSW as u32,
        libc::TCSETSF as u32,
        libc::TCSBRK as u32,
        libc::TCXONC as u32,
        libc::TCFLSH as u32,
        libc::TIOCGPGRP as u32,
        libc::TIOCSPGRP as u32,
        libc::TIOCGWINSZ as u32,
        libc::TIOCSWINSZ as u32,
        libc::TIOCGSID as u32,
        libc::TIOCSCTTY as u32,
        libc::TIOCNOTTY as u32,
        libc::TIOCGPTN as u32,
        libc::TIOCSPTLCK as u32,
    ];
    if safe.contains(&operation) {
        Ok(Outcome::Continue)
    } else {
        Err(errno(libc::EOPNOTSUPP))
    }
}
