//! Console's post-enforcement namespace init. Native policy setup stays upstream.
use crate::native::accept;
use crate::signals::Signals;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn run(arguments: Vec<String>, descriptor: OwnedFd) -> ! {
    let code = match spawn_and_wait(arguments, descriptor) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("native namespace init: {error}");
            1
        }
    };
    std::process::exit(code);
}

fn spawn_and_wait(arguments: Vec<String>, descriptor: OwnedFd) -> io::Result<i32> {
    // Keep forwarding signals and SIGCHLD blocked through setup and spawning.
    // Only the target restores the caller's original state in pre_exec.
    let signals = Signals::install()?;
    // Re-arm after bubblewrap's credential/exec boundary, before readiness.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (setup, channel) = match accept(descriptor) {
        Ok(value) => value,
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe
                )
            }) =>
        {
            std::process::exit(0)
        }
        Err(error) => return Err(std::io::Error::other(error)),
    };
    if unsafe { libc::fcntl(channel.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut command = Command::new(&arguments[0]);
    command.args(&arguments[1..]);
    // Install the target environment only after enforcement and helper setup.
    // Only managed proxy values rewritten in the namespace cross this boundary.
    command.env_clear().envs(&setup.environment);
    if !setup.environment.contains_key("PWD") {
        command.env("PWD", std::env::current_dir()?);
    }
    for name in setup.proxy_environment {
        let value = std::env::var_os(&name)
            .ok_or_else(|| std::io::Error::other("missing native proxy environment"))?;
        command.env(name, value);
    }
    for name in setup.excluded_environment {
        command.env_remove(name);
    }
    unsafe {
        command.pre_exec(move || setup.signals.restore());
    }
    // The control loop reaps this child and all other namespace children.
    #[expect(clippy::zombie_processes)]
    let child = command.spawn()?;
    drop(command);
    // Waiting helpers must not hide target-side stdin closure from the caller.
    if unsafe { libc::close(libc::STDIN_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    crate::target_control::wait(channel.into(), child.id() as libc::pid_t, &signals)
}
