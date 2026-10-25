//! Pin mutation destinations before checking missing-path protection.
//!
//! The broker and target share a fixed filesystem root and mount namespace.
//! Kernel lookups retain ordinary symlink and directory-descriptor semantics.
//! Mutations through procfs, sysfs, or magic links are deliberately unsupported:
//! resolving `/proc/self` in the broker must never expose its private descriptors.
//! Protected entries must remain absent for this policy's lifetime. If the host
//! creates one, the next mediated mutation retires the sandbox and requires a
//! restart; this policy does not reinterpret a new directory, symlink, or hardlink.

use std::ffi::CStr;
use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const MAX_SYMLINKS: usize = 40;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

struct ProtectedPath {
    parent: OwnedFd,
    identity: Identity,
    name: CString,
}

pub(super) struct Policy {
    paths: Vec<ProtectedPath>,
}

#[derive(Debug)]
pub(super) struct PolicyChanged;

impl std::fmt::Display for PolicyChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an initially missing protected path appeared; restart the sandbox")
    }
}

impl std::error::Error for PolicyChanged {}

pub(super) struct ResolvedPath {
    pub(super) parent: OwnedFd,
    /// A single basename, retaining a requested trailing slash.
    pub(super) name: CString,
    pub(super) existing: Option<OwnedFd>,
    pub(super) trailing_slash: bool,
    leaf: CString,
}

impl Policy {
    pub(super) fn new(paths: &[PathBuf]) -> io::Result<Self> {
        let mut protected = Vec::with_capacity(paths.len());
        for path in paths {
            if !path.is_absolute() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let parent_path = path
                .parent()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
            let parent = open_directory(
                libc::AT_FDCWD,
                &cstring(parent_path.as_os_str().as_bytes())?,
            )?;
            check_filesystem(&parent)?;
            // Opening ptmx creates a numbered devpts node inside the kernel;
            // there is no destination pathname syscall for the broker to deny.
            // Reject only protected parents, retaining normal tty fd behavior.
            if filesystem_type(&parent)? == libc::DEVPTS_SUPER_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "missing read-only paths on devpts are unsupported",
                ));
            }
            protected.push(ProtectedPath {
                identity: identity(&parent)?,
                parent,
                name: cstring(name.as_bytes())?,
            });
        }
        let policy = Self { paths: protected };
        policy.ensure_absent()?;
        Ok(policy)
    }

    pub(super) fn resolve(
        &self,
        tid: u32,
        dirfd: i32,
        path: &CStr,
        follow_final: bool,
    ) -> io::Result<ResolvedPath> {
        let start = if path.to_bytes().starts_with(b"/") {
            capture_proc_path(tid, "root")?
        } else if dirfd == libc::AT_FDCWD {
            capture_cwd(tid)?
        } else {
            capture_fd(tid, dirfd)?
        };
        resolve_from(&start, path, follow_final, 0)
    }

    /// Resolve against the same captured cwd used by a native pathname syscall.
    pub(super) fn resolve_from(
        &self,
        start: &OwnedFd,
        path: &CStr,
        follow_final: bool,
    ) -> io::Result<ResolvedPath> {
        resolve_from(start, path, follow_final, 0)
    }

    pub(super) fn check(&self, path: &ResolvedPath) -> io::Result<()> {
        self.ensure_absent()?;
        check_filesystem(&path.parent)?;
        let parent_identity = identity(&path.parent)?;
        for protected in &self.paths {
            if parent_identity == protected.identity && path.leaf == protected.name {
                return denied();
            }
        }
        Ok(())
    }

    pub(super) fn check_fd(&self, descriptor: &OwnedFd) -> io::Result<()> {
        self.ensure_absent()?;
        // An unlinked temporary file or memfd has no name to create under a
        // protected parent. Existing read-only mounts retain native enforcement.
        check_filesystem(descriptor)
    }

    fn ensure_absent(&self) -> io::Result<()> {
        for protected in &self.paths {
            match open_path(protected.parent.as_raw_fd(), &protected.name, false) {
                Ok(_) => return Err(io::Error::other(PolicyChanged)),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Removing or moving an ancestor must not detach a protected name from
    /// the pinned directory that defines it for this sandbox's lifetime.
    pub(super) fn check_removal(&self, path: &ResolvedPath) -> io::Result<()> {
        self.check(path)?;
        let Some(existing) = &path.existing else {
            return Ok(());
        };
        let candidate_identity = identity(existing)?;
        for protected in &self.paths {
            let mut ancestor = protected.parent.try_clone()?;
            loop {
                let ancestor_identity = identity(&ancestor)?;
                if ancestor_identity == candidate_identity {
                    return denied();
                }
                let parent = open_directory(ancestor.as_raw_fd(), c"..")?;
                // A bind alias may repeat an inode at a different mount. Only
                // an unchanged inode *and mount* means `..` reached the root.
                if identity(&parent)? == ancestor_identity
                    && mount_id(&parent)? == mount_id(&ancestor)?
                {
                    break;
                }
                ancestor = parent;
            }
        }
        Ok(())
    }
}

/// Capture the target's path reference, not a shared open file description.
/// The caller validates the notification after opening target procfs entries.
pub(super) fn capture_fd(tid: u32, fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    capture_proc_path(tid, &format!("fd/{fd}"))
}

pub(super) fn capture_cwd(tid: u32) -> io::Result<OwnedFd> {
    capture_proc_path(tid, "cwd")
}

fn capture_proc_path(tid: u32, entry: &str) -> io::Result<OwnedFd> {
    let proc_path = cstring(format!("/proc/{tid}").as_bytes())?;
    let proc_directory = open_directory(libc::AT_FDCWD, &proc_path)?;
    let entry = cstring(entry.as_bytes())?;
    // This intentional magic-link lookup captures the target's root, cwd, or
    // descriptor. Untrusted pathname resolution never uses this operation.
    let fd = unsafe {
        libc::openat(
            proc_directory.as_raw_fd(),
            entry.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    owned_fd(fd)
}

fn resolve_from(
    start: &OwnedFd,
    path: &CStr,
    follow_final: bool,
    links: usize,
) -> io::Result<ResolvedPath> {
    if links > MAX_SYMLINKS {
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }
    let bytes = path.to_bytes();
    if bytes.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let trailing_slash = bytes.ends_with(b"/");
    let end = bytes.iter().rposition(|byte| *byte != b'/');
    let (parent_name, leaf) = match end {
        None => (c"/".to_owned(), c".".to_owned()),
        Some(end) => match bytes[..=end].iter().rposition(|byte| *byte == b'/') {
            Some(0) => (c"/".to_owned(), cstring(&bytes[1..=end])?),
            Some(slash) => (cstring(&bytes[..slash])?, cstring(&bytes[slash + 1..=end])?),
            None => (c".".to_owned(), cstring(&bytes[..=end])?),
        },
    };
    let parent = open_directory(start.as_raw_fd(), &parent_name)?;
    check_filesystem(&parent)?;
    let existing = match open_path(parent.as_raw_fd(), &leaf, false) {
        Ok(descriptor) => Some(descriptor),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
        Err(error) => return Err(error),
    };
    if follow_final
        && let Some(descriptor) = &existing
        && metadata(descriptor)?.st_mode & libc::S_IFMT == libc::S_IFLNK
    {
        match open_path(parent.as_raw_fd(), &leaf, true) {
            Ok(target) => return resolved_existing(target, trailing_slash),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                // The kernel has checked the symlink traversal, including
                // protected_symlinks. Its immutable contents identify the
                // missing destination; the eventual mutation uses that pinned
                // destination's parent and O_NOFOLLOW, never the original link.
                let target = read_link(descriptor)?;
                let mut result = resolve_from(&parent, &target, true, links + 1)?;
                if trailing_slash && !result.trailing_slash {
                    result.name = slash_name(&result.leaf, true)?;
                    result.trailing_slash = true;
                }
                return Ok(result);
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(descriptor) = &existing {
        check_filesystem(descriptor)?;
    }
    Ok(ResolvedPath {
        parent,
        name: slash_name(&leaf, trailing_slash)?,
        existing,
        trailing_slash,
        leaf,
    })
}

fn resolved_existing(existing: OwnedFd, trailing_slash: bool) -> io::Result<ResolvedPath> {
    check_filesystem(&existing)?;
    let path = descriptor_path(&existing)?;
    let parent_path = path.parent().unwrap_or(Path::new("/"));
    let leaf = cstring(path.file_name().map_or(b".".as_slice(), OsStrExt::as_bytes))?;
    let parent = open_directory(
        libc::AT_FDCWD,
        &cstring(parent_path.as_os_str().as_bytes())?,
    )?;
    check_filesystem(&parent)?;
    let current = open_path(parent.as_raw_fd(), &leaf, false)?;
    if identity(&current)? != identity(&existing)? {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(ResolvedPath {
        parent,
        name: slash_name(&leaf, trailing_slash)?,
        existing: Some(existing),
        trailing_slash,
        leaf,
    })
}

fn slash_name(leaf: &CStr, trailing_slash: bool) -> io::Result<CString> {
    let mut bytes = leaf.to_bytes().to_vec();
    if trailing_slash {
        bytes.push(b'/');
    }
    cstring(&bytes)
}

fn descriptor_path(descriptor: &OwnedFd) -> io::Result<PathBuf> {
    descriptor_location(descriptor)?.ok_or_else(|| io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

fn descriptor_location(descriptor: &OwnedFd) -> io::Result<Option<PathBuf>> {
    let path = fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))?;
    if !path.is_absolute() || path.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Ok(None);
    }
    Ok(Some(path))
}

fn read_link(descriptor: &OwnedFd) -> io::Result<CString> {
    let mut bytes = vec![0_u8; libc::PATH_MAX as usize];
    let length = unsafe {
        libc::readlinkat(
            descriptor.as_raw_fd(),
            c"".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize == bytes.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    bytes.truncate(length as usize);
    cstring(&bytes)
}

fn open_directory(dirfd: i32, path: &CStr) -> io::Result<OwnedFd> {
    openat2(
        dirfd,
        path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
}

fn open_path(dirfd: i32, path: &CStr, follow: bool) -> io::Result<OwnedFd> {
    openat2(
        dirfd,
        path,
        libc::O_PATH | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW },
    )
}

fn openat2(dirfd: i32, path: &CStr, flags: i32) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    owned_fd(fd as i32)
}

fn owned_fd(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful open syscall returned a newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn metadata(descriptor: &OwnedFd) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat initialized the complete structure on success.
    Ok(unsafe { metadata.assume_init() })
}

fn identity(descriptor: &OwnedFd) -> io::Result<Identity> {
    let metadata = metadata(descriptor)?;
    Ok(Identity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn mount_id(descriptor: &OwnedFd) -> io::Result<u64> {
    let mut metadata = std::mem::MaybeUninit::<libc::statx>::uninit();
    if unsafe {
        libc::statx(
            descriptor.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            metadata.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statx initialized the complete structure on success.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    Ok(metadata.stx_mnt_id)
}

fn check_filesystem(descriptor: &OwnedFd) -> io::Result<()> {
    let kind = filesystem_type(descriptor)?;
    if kind == libc::PROC_SUPER_MAGIC || kind == libc::SYSFS_MAGIC {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    Ok(())
}

fn filesystem_type(descriptor: &OwnedFd) -> io::Result<libc::c_long> {
    let mut metadata = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs initialized the complete structure on success.
    Ok(unsafe { metadata.assume_init() }.f_type)
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn denied() -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::EACCES))
}
