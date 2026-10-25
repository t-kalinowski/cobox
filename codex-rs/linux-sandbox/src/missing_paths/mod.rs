//! Enforce absent read-only entries without creating host filesystem objects.
//!
//! The namespace init owns a seccomp notification listener. The workload inherits
//! its filter, while broker threads retain the native mount restrictions. A broker
//! copies arguments and executes mutations against pinned directory descriptors;
//! inspecting a pathname and continuing its original syscall is never sufficient.
mod paths;
mod syscalls;

use paths::Policy;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

static PATHS: OnceLock<Vec<PathBuf>> = OnceLock::new();
const USER_NOTIF: u32 = 0x7fc0_0000;
const ALLOW: u32 = 0x7fff_0000;
const ERRNO: u32 = 0x0005_0000;
const RECV: libc::c_ulong = 0xc050_2100;
const SEND: libc::c_ulong = 0xc018_2101;
const ID_VALID: libc::c_ulong = 0x4008_2102;
const ADDFD: libc::c_ulong = 0x4018_2103;

pub(crate) fn set_policy_paths(paths: Vec<PathBuf>) {
    assert!(
        PATHS.set(paths).is_ok(),
        "missing-path policy installed twice"
    );
}

/// Precomputed child-side installation, owned until the target has been spawned.
/// The listener itself belongs to the namespace init and dies with that process.
pub struct Installation {
    socket: OwnedFd,
    filter: Vec<libc::sock_filter>,
}

/// Prepare enforcement before fork. An empty policy needs no broker or filter.
pub fn prepare() -> io::Result<Option<Installation>> {
    let Some(paths) = PATHS.get().filter(|paths| !paths.is_empty()) else {
        return Ok(None);
    };
    if std::fs::read_link("/proc/self")? != unsafe { libc::getpid() }.to_string() {
        return Err(io::Error::other(
            "missing-path enforcement requires namespace-local procfs",
        ));
    }
    #[repr(C)]
    #[derive(Default)]
    struct NotificationSizes {
        notification: u16,
        response: u16,
        data: u16,
    }
    let mut sizes = NotificationSizes::default();
    if unsafe { libc::syscall(libc::SYS_seccomp, 3, 0, &mut sizes) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::from(sizes.notification) != std::mem::size_of::<Notification>()
        || usize::from(sizes.response) != std::mem::size_of::<Response>()
        || sizes.data != 64
    {
        return Err(io::Error::other("unsupported seccomp notification layout"));
    }
    let policy = Arc::new(Policy::new(paths)?);
    // The workload must not inspect or import the init's broker authority.
    // Exec restores the ordinary target's dumpability, allowing its parent to
    // copy notification arguments without exposing the parent's own memory.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sockets = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sockets.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let receiver = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
    let socket = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
    let filter = filter();
    std::thread::Builder::new()
        .name("missing-path-broker".into())
        .spawn(move || {
            // Creation modes use each caller's umask. Do not change the namespace
            // init's or target's filesystem state when setting the broker's umask.
            let result = (|| {
                if unsafe { libc::unshare(libc::CLONE_FS) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                unsafe {
                    libc::umask(0);
                }
                let listener = receive_descriptor(receiver.as_raw_fd())?;
                drop(receiver);
                serve(Arc::new(listener), policy)
            })();
            if let Err(error) = result {
                eprintln!("missing-path broker: {error}");
                // Namespace-init death retires the complete workload. A failed broker
                // must never leave a workload running with an unserviced policy.
                std::process::exit(1);
            }
        })?;
    Ok(Some(Installation { socket, filter }))
}

impl Installation {
    /// Install in the forked target immediately before exec. This uses only
    /// preallocated memory and async-signal-safe system calls.
    pub fn install(&self) -> io::Result<()> {
        let program = libc::sock_fprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr().cast_mut(),
        };
        let listener = unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &program) };
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = send_descriptor(self.socket.as_raw_fd(), listener as RawFd);
        unsafe {
            libc::close(listener as RawFd);
        }
        result
    }
}

#[repr(C)]
#[derive(Default)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    syscall: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct Response {
    id: u64,
    value: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct AddFd {
    id: u64,
    flags: u32,
    source: u32,
    target: u32,
    target_flags: u32,
}

pub(super) struct Request {
    id: u64,
    tid: u32,
    syscall: i32,
    args: [u64; 6],
    listener: RawFd,
}

impl Request {
    fn is_valid(&self) -> io::Result<()> {
        if unsafe { libc::ioctl(self.listener, ID_VALID, &self.id) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_bytes(&self, address: u64, len: usize) -> io::Result<Vec<u8>> {
        self.is_valid()?;
        let memory = File::open(format!("/proc/{}/mem", self.tid))?;
        self.is_valid()?;
        let mut bytes = vec![0; len];
        memory.read_exact_at(&mut bytes, address)?;
        self.is_valid()?;
        Ok(bytes)
    }

    fn read_cstring(&self, address: u64) -> io::Result<CString> {
        self.is_valid()?;
        let memory = File::open(format!("/proc/{}/mem", self.tid))?;
        self.is_valid()?;
        let mut bytes = Vec::new();
        while bytes.len() < libc::PATH_MAX as usize {
            let offset = address
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EFAULT))?;
            // Never read across a page boundary: the terminating NUL may be the
            // last readable byte before an unmapped page.
            let count = (4096 - offset as usize % 4096).min(libc::PATH_MAX as usize - bytes.len());
            let mut buffer = vec![0; count];
            let read = memory.read_at(&mut buffer, offset)?;
            if read == 0 {
                return Err(io::Error::from_raw_os_error(libc::EFAULT));
            }
            if let Some(end) = buffer[..read].iter().position(|byte| *byte == 0) {
                bytes.extend_from_slice(&buffer[..end]);
                self.is_valid()?;
                return CString::new(bytes).map_err(io::Error::other);
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
    }
}

pub(super) enum Outcome {
    Value(i64),
    Opened(OwnedFd, bool),
    Continue,
}

fn serve(listener: Arc<OwnedFd>, policy: Arc<Policy>) -> io::Result<()> {
    loop {
        let mut notification = Notification::default();
        if unsafe { libc::ioctl(listener.as_raw_fd(), RECV, &mut notification) } < 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::EINTR | libc::ENOENT)) {
                continue;
            }
            return Err(error);
        }
        let listener = Arc::clone(&listener);
        let policy = Arc::clone(&policy);
        // A FIFO open may wait for a second intercepted open. Servicing requests
        // concurrently preserves this native blocking behavior.
        std::thread::Builder::new()
            .name("missing-path-request".into())
            .spawn(move || {
                let request = Request {
                    id: notification.id,
                    tid: notification.pid,
                    syscall: notification.syscall,
                    args: notification.args,
                    listener: listener.as_raw_fd(),
                };
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    syscalls::dispatch(&request, &policy)
                }))
                .unwrap_or_else(|_| std::process::exit(1));
                if let Err(error) = &outcome
                    && let Some(cause) = error.get_ref()
                    && cause.is::<paths::PolicyChanged>()
                {
                    eprintln!("missing-path broker: {error}");
                    std::process::exit(1);
                }
                let mut response = Response {
                    id: request.id,
                    ..Response::default()
                };
                match outcome {
                    Ok(Outcome::Value(value)) => response.value = value,
                    Ok(Outcome::Continue) => response.flags = 1,
                    Ok(Outcome::Opened(descriptor, cloexec)) => {
                        let add = AddFd {
                            id: request.id,
                            flags: 2, // SECCOMP_ADDFD_FLAG_SEND: inject and complete atomically.
                            source: descriptor.as_raw_fd() as u32,
                            target: 0,
                            target_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
                        };
                        if unsafe { libc::ioctl(listener.as_raw_fd(), ADDFD, &add) } >= 0 {
                            return;
                        }
                        response.error = -io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(libc::EIO);
                    }
                    Err(error) => response.error = -error.raw_os_error().unwrap_or(libc::EIO),
                }
                loop {
                    if unsafe { libc::ioctl(listener.as_raw_fd(), SEND, &response) } >= 0 {
                        break;
                    }
                    let error = io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        // An interrupted/dead caller invalidates its notification;
                        // no other process can receive this response.
                        Some(libc::ENOENT) => break,
                        _ => {
                            eprintln!("missing-path broker response: {error}");
                            std::process::exit(1);
                        }
                    }
                }
            })?;
    }
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn filter() -> Vec<libc::sock_filter> {
    let arch = if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else {
        0xc000_00b7
    };
    let mut result = vec![
        instruction(0x20, 0, 0, 4), // seccomp_data.arch
        instruction(0x15, 1, 0, arch),
        instruction(0x06, 0, 0, 0x8000_0000), // KILL_PROCESS: no alternate ABI bypass.
        instruction(0x20, 0, 0, 0),           // seccomp_data.nr
    ];
    if cfg!(target_arch = "x86_64") {
        result.extend([
            instruction(0x45, 0, 1, 0x4000_0000),
            instruction(0x06, 0, 0, ERRNO | libc::ENOSYS as u32),
        ]);
    }
    // A new kernel mutation API must be reviewed before it can run under this
    // filesystem policy. The two supported ABIs share this modern range.
    result.extend([
        instruction(0x35, 0, 1, 473),
        instruction(0x06, 0, 0, ERRNO | libc::ENOSYS as u32),
    ]);
    let denied = [
        libc::SYS_seccomp,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_open_by_handle_at,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_process_vm_readv,
        libc::SYS_pidfd_getfd,
        // A target-only Landlock domain cannot constrain the broker's syscalls.
        // Refuse installation rather than report an unenforced self-restriction.
        libc::SYS_landlock_restrict_self,
        // BPF_OBJ_PIN can create filesystem entries without a pathname syscall.
        libc::SYS_bpf,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // New Linux mutation APIs must not bypass dispatch on newer kernels.
        463,
        466,
        467,
        469,
        472,
    ];
    for syscall in denied {
        result.extend([
            instruction(0x15, 0, 1, syscall as u32),
            instruction(0x06, 0, 0, ERRNO | libc::EPERM as u32),
        ]);
    }
    result.extend([
        instruction(0x15, 0, 1, libc::SYS_clone3 as u32),
        instruction(0x06, 0, 0, ERRNO | libc::ENOSYS as u32),
    ]);
    // Mutable process namespace and descriptor-table state cannot diverge from
    // the broker's authority. Ordinary fork and pthread creation stay available.
    let namespace_flags = (libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET) as u32;
    result.extend([
        instruction(0x15, 0, 7, libc::SYS_clone as u32),
        instruction(0x20, 0, 0, 16),
        instruction(0x45, 0, 1, namespace_flags),
        instruction(0x06, 0, 0, ERRNO | libc::EPERM as u32),
        instruction(0x45, 0, 2, libc::CLONE_THREAD as u32),
        instruction(0x45, 1, 0, libc::CLONE_FILES as u32),
        instruction(0x06, 0, 0, ERRNO | libc::EPERM as u32),
        instruction(0x06, 0, 0, ALLOW),
    ]);
    {
        let (syscall, argument, mask) = (libc::SYS_close_range, 2, 2);
        result.extend([
            instruction(0x15, 0, 4, syscall as u32),
            instruction(0x20, 0, 0, 16 + argument * 8),
            instruction(0x45, 0, 1, mask),
            instruction(0x06, 0, 0, ERRNO | libc::EPERM as u32),
            instruction(0x06, 0, 0, ALLOW),
        ]);
    }
    // Installing a newer USER_NOTIF filter could replace this listener.
    result.extend([
        instruction(0x15, 0, 4, libc::SYS_prctl as u32),
        instruction(0x20, 0, 0, 16),
        instruction(0x15, 0, 1, libc::PR_SET_SECCOMP as u32),
        instruction(0x06, 0, 0, ERRNO | libc::EPERM as u32),
        instruction(0x06, 0, 0, ALLOW),
    ]);
    for syscall in syscalls::intercepted_syscalls() {
        result.extend([
            instruction(0x15, 0, 1, syscall as u32),
            instruction(0x06, 0, 0, USER_NOTIF),
        ]);
    }
    result.push(instruction(0x06, 0, 0, ALLOW));
    result
}

fn send_descriptor(socket: RawFd, descriptor: RawFd) -> io::Result<()> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
        if libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn receive_descriptor(socket: RawFd) -> io::Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    unsafe {
        if libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) != 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing seccomp listener",
            ));
        }
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || message.msg_flags & libc::MSG_CTRUNC != 0
        {
            return Err(io::Error::other("invalid seccomp listener transfer"));
        }
        Ok(OwnedFd::from_raw_fd(std::ptr::read(
            libc::CMSG_DATA(header).cast::<RawFd>(),
        )))
    }
}
