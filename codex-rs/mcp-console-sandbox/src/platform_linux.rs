use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

// Linux 6.5 added this ancillary type; the pinned libc exposes SO_PASSPIDFD
// but does not yet expose its matching message constant.
const SCM_PIDFD: libc::c_int = 0x04;

fn signal(fd: &OwnedFd, signal: i32) -> io::Result<()> {
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

pub struct Parent {
    pid: i32,
}
impl Parent {
    pub fn capture(pid: i32) -> io::Result<Self> {
        if unsafe { libc::getppid() } != pid {
            return Err(io::Error::other("parent_pid is not the current parent"));
        }
        // The caller is our direct parent. Its death changes getppid and wakes
        // the existing SIGCHLD wait set; no PID lookup or pidfd is needed.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGCHLD, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let value = Self { pid };
        if !value.alive()? {
            return Err(io::Error::other("parent exited during startup"));
        }
        Ok(value)
    }
    pub fn alive(&self) -> io::Result<bool> {
        Ok(unsafe { libc::getppid() } == self.pid)
    }
}

pub struct Tracker {
    root: Option<i32>,
}
impl Tracker {
    pub fn new() -> io::Result<Self> {
        Ok(Self { root: None })
    }
    pub fn track_root(&mut self, pid: i32) -> io::Result<()> {
        self.root = Some(pid);
        Ok(())
    }
    pub fn observe(&mut self) -> io::Result<()> {
        Ok(())
    }
    pub fn retire_pass(&mut self) -> io::Result<bool> {
        // For native execution the monitor reaps init after namespace retirement.
        // External enforcement observes only our direct child; the outer sandbox
        // owns detached descendants. Keep the child waitable until this step.
        self.root.map_or(Ok(true), |pid| {
            super::root_status(pid).map(|status| status.is_some())
        })
    }
}

pub struct Target {
    channel: UnixStream,
    // Optional identity-safe emergency termination also reaches a stopped init.
    // Ordinary forwarding and retirement use the private native channel.
    pidfd: Option<OwnedFd>,
}
pub fn configure_channel(stream: &UnixStream) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSPIDFD,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOPROTOOPT | libc::EPERM | libc::EACCES)
        ) {
            return Err(error);
        }
        // Older kernels or host policy can disable this optional handle. The
        // private channel still retires init; never look up a queued numeric PID.
    }
    Ok(())
}
pub fn receive_ready(stream: &mut UnixStream, _: i32) -> io::Result<Option<Target>> {
    let mut byte = 0u8;
    let mut control = [0usize; 16];
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // musl uses socklen_t here; glibc uses size_t. The fixed buffer fits both.
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    let count = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error);
    }
    let mut credentials = None;
    let mut pidfd = None;
    let mut invalid = false;
    let mut descriptor_error = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        // Adopt every delivered descriptor before rejecting the message, so
        // truncation, invalid credentials, or a later error cannot leak it.
        let length = unsafe { (*header).cmsg_len as usize };
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        let data = unsafe { libc::CMSG_DATA(header) };
        if level == libc::SOL_SOCKET && matches!(kind, SCM_PIDFD | libc::SCM_RIGHTS) {
            let payload = length - unsafe { libc::CMSG_LEN(0) as usize };
            for offset in (0..payload / std::mem::size_of::<i32>())
                .map(|index| index * std::mem::size_of::<i32>())
            {
                let descriptor = unsafe { data.add(offset).cast::<i32>().read_unaligned() };
                if descriptor < 0 {
                    // SCM_PIDFD carries a negative errno if allocation fails.
                    descriptor_error = Some(io::Error::from_raw_os_error(-descriptor));
                } else {
                    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                    if kind == SCM_PIDFD && payload == std::mem::size_of::<i32>() && pidfd.is_none()
                    {
                        pidfd = Some(descriptor);
                    } else {
                        invalid = true;
                    }
                }
            }
            invalid |= kind != SCM_PIDFD || payload != std::mem::size_of::<i32>();
        } else if level == libc::SOL_SOCKET
            && kind == libc::SCM_CREDENTIALS
            && length
                == unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize }
            && credentials.is_none()
        {
            credentials = Some(unsafe { data.cast::<libc::ucred>().read_unaligned() });
        } else {
            invalid = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if count == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    if count != 1 || byte != 1 || message.msg_flags & libc::MSG_CTRUNC != 0 || invalid {
        return Err(io::Error::other("invalid native readiness"));
    }
    if let Some(error) = descriptor_error {
        return Err(error);
    }
    let Some(credentials) = credentials else {
        return Err(io::Error::other("native readiness lacks credentials"));
    };
    if credentials.uid != unsafe { libc::geteuid() } || credentials.pid <= 1 {
        return Err(io::Error::other("invalid native readiness identity"));
    }
    Ok(Some(Target {
        channel: stream.try_clone()?,
        pidfd,
    }))
}
pub fn forward(target: &Target, number: i32) -> io::Result<()> {
    if number == libc::SIGKILL {
        if let Some(fd) = &target.pidfd {
            match signal(fd, number) {
                Ok(()) => return Ok(()),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOSYS | libc::EPERM | libc::EACCES)
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        return target.channel.shutdown(std::net::Shutdown::Write);
    }
    let byte = number as u8;
    if unsafe { libc::write(target.channel.as_raw_fd(), (&byte as *const u8).cast(), 1) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::BrokenPipe {
            return Err(error);
        }
    }
    Ok(())
}

// Bubblewrap owns the target's separate session. Original terminal descriptors
// remain attached; host foreground ownership stays with the calling job.
pub struct Terminal;
impl Terminal {
    pub fn capture() -> io::Result<Self> {
        Ok(Self)
    }
    pub fn transfer(&self, _: i32) -> io::Result<()> {
        Ok(())
    }
    pub fn restore(&self) -> io::Result<()> {
        Ok(())
    }
}
