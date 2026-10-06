//! Console namespace-init control. Only the host runner owns the other endpoint.
use crate::signals::FORWARDED;
use crate::signals::Signals;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;

pub(crate) fn wait(channel: OwnedFd, command: libc::pid_t, signals: &Signals) -> io::Result<i32> {
    let signals = signals.notification()?;
    loop {
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped == command {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            });
        }
        if reaped > 0 {
            continue;
        }
        if reaped < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let mut descriptors = [
            libc::pollfd {
                fd: channel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptors[0].revents != 0 {
            let mut signal = 0u8;
            match unsafe { libc::read(channel.as_raw_fd(), (&mut signal as *mut u8).cast(), 1) } {
                // Exiting PID 1 makes the kernel retire the entire namespace.
                // Its native parent remains alive to wait for that completion.
                0 => return Ok(0),
                1 if FORWARDED.contains(&i32::from(signal)) => {
                    if unsafe { libc::kill(command, i32::from(signal)) } < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                _ => return Err(io::Error::other("invalid native control message")),
            }
        }
        if descriptors[1].revents != 0 {
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::read(
                    signals.as_raw_fd(),
                    (&mut info as *mut libc::signalfd_siginfo).cast(),
                    std::mem::size_of_val(&info),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let signal = info.ssi_signo as i32;
            // Group delivery includes its leader. Address the PID only if
            // the target has not created a group with its own ID.
            if FORWARDED.contains(&signal)
                && unsafe { libc::kill(-command, signal) } < 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                unsafe { libc::kill(command, signal) };
            }
        }
    }
}
