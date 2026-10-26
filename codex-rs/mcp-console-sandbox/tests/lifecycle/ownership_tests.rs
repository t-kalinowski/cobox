use super::*;
use pretty_assertions::assert_eq;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::time::Duration;
use std::time::Instant;

// The test process stays outside the killed group. Pin each observed lifetime
// before killing its owner, and clean up even when an assertion unwinds.
pub(super) struct Process {
    pid: i32,
    exit: OwnedFd,
}
impl Process {
    pub(super) fn watch(pid: i32) -> Self {
        #[cfg(target_os = "linux")]
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        #[cfg(target_os = "macos")]
        let fd = unsafe { libc::kqueue() };
        assert!(fd >= 0, "watch {pid}: {}", std::io::Error::last_os_error());
        let exit = unsafe { OwnedFd::from_raw_fd(fd) };
        #[cfg(target_os = "macos")]
        {
            let event = libc::kevent {
                ident: pid as usize,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            assert_eq!(
                unsafe { libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) },
                0
            );
        }
        Self { pid, exit }
    }

    fn kill(&self) {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.exit.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        #[cfg(target_os = "macos")]
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let mut fd = libc::pollfd {
            fd: self.exit.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut fd, 1, 0) } == 0 {
            self.kill();
        }
    }
}

pub(super) fn await_exit(processes: &[Process]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    for process in processes {
        let mut fd = libc::pollfd {
            fd: process.exit.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as i32;
        assert_eq!(
            unsafe { libc::poll(&mut fd, 1, remaining) },
            1,
            "process {} survived",
            process.pid
        );
        assert_ne!(fd.revents & libc::POLLIN, 0);
    }
}

#[cfg(target_os = "linux")]
pub(super) fn watch_tree(root: i32) -> Vec<Process> {
    let mut processes = vec![Process::watch(root)];
    let mut index = 0;
    while index < processes.len() {
        for task in std::fs::read_dir(format!("/proc/{}/task", processes[index].pid)).unwrap() {
            let children = std::fs::read_to_string(task.unwrap().path().join("children")).unwrap();
            for pid in children
                .split_whitespace()
                .map(|pid| pid.parse::<i32>().unwrap())
            {
                if !processes.iter().any(|process| process.pid == pid) {
                    processes.push(Process::watch(pid));
                }
            }
        }
        index += 1;
    }
    processes
}

#[derive(Clone, Copy, Debug)]
enum Loss {
    Caller,
    Group,
    #[cfg(target_os = "linux")]
    Runner,
}

#[test]
fn caller_sigkill_retires_workload_and_storage() {
    owned_loss(Loss::Caller);
}

#[test]
fn caller_group_sigkill_with_terminal_stderr_retires_workload_and_storage() {
    owned_loss(Loss::Group);
}

#[cfg(target_os = "linux")]
#[test]
fn runner_sigkill_terminates_native_chain_and_detached_workload() {
    owned_loss(Loss::Runner);
}

fn owned_loss(loss: Loss) {
    #[cfg(target_os = "linux")]
    let paths = [String::new(), std::env::var("PATH").unwrap()];
    #[cfg(target_os = "macos")]
    let paths = [String::new()];
    for path in paths {
        for proxy in [Value::Null, proxy_config()] {
            eprintln!("loss={loss:?}, path={path}, proxy={}", !proxy.is_null());
            let directory = tempfile::tempdir().unwrap();
            let native = runner(directory.path());
            let mut request = fixture("lifecycle", &["detached"]);
            request["cwd"] = json!(directory.path());
            request["proxy"] = proxy;
            request["filesystem"]["entries"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "path": {"type": "path", "path": directory.path()}, "access": "write"
                }));
            request["lifecycle"] =
                json!({"private_tmp": {"parent": directory.path(), "environment": ["TMPDIR"]}});
            let mut command = Command::new(cargo_bin("mcp-console-sandbox-fixture").unwrap());
            command
                .arg("owner")
                .arg(native.get_program())
                // Helper selection uses the launch environment, before target setup.
                .env("PATH", &path)
                .env("SANDBOX_TEST_REQUEST", request.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let terminal = if matches!(loss, Loss::Group) {
                let (mut master, mut slave) = (-1, -1);
                assert_eq!(
                    unsafe {
                        libc::openpty(
                            &mut master,
                            &mut slave,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    },
                    0
                );
                let master = unsafe { File::from_raw_fd(master) };
                command.stderr(Stdio::from(unsafe { File::from_raw_fd(slave) }));
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() < 0 || libc::ioctl(2, libc::TIOCSCTTY as _, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                Some(master)
            } else {
                command.process_group(0);
                None
            };
            let mut owner = command.spawn().unwrap();
            drop(command);
            let owner_watch = Process::watch(owner.id() as i32);
            let mut stdout = BufReader::new(owner.stdout.take().unwrap());
            let mut line = String::new();
            stdout.read_line(&mut line).unwrap();
            let supervisor = line.trim().parse::<i32>().unwrap();
            let runner_watch = Process::watch(supervisor);
            line.clear();
            stdout.read_line(&mut line).unwrap();
            let ready: Value = serde_json::from_str(&line).unwrap();
            #[cfg(target_os = "linux")]
            let processes = watch_tree(supervisor);
            #[cfg(target_os = "macos")]
            let processes = ["pid", "descendant"]
                .map(|key| Process::watch(ready[key].as_i64().unwrap() as i32));
            #[cfg(target_os = "linux")]
            {
                // Confirm that the namespace-local detached PID names a live
                // host process in this exact observed tree, outside its parent's session.
                let descendant = ready["descendant"].as_i64().unwrap();
                let detached = processes
                    .iter()
                    .find(|process| {
                        std::fs::read_to_string(format!("/proc/{}/status", process.pid))
                            .unwrap()
                            .lines()
                            .any(|line| {
                                line.starts_with("NSpid:")
                                    && line
                                        .split_whitespace()
                                        .last()
                                        .unwrap()
                                        .parse::<i64>()
                                        .unwrap()
                                        == descendant
                            })
                    })
                    .unwrap();
                assert_eq!(unsafe { libc::getsid(detached.pid) }, detached.pid);
                assert!(
                    processes.len() >= 5,
                    "native chain and workload: {}",
                    processes.len()
                );
            }
            assert_ne!(unsafe { libc::getpgrp() }, owner.id() as i32);
            if let Some(terminal) = &terminal {
                assert_eq!(
                    unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) },
                    owner.id() as i32
                );
            }
            // Capture before death; checking this after SIGKILL could mistake a
            // recycled PID or the runner's retirement for successful isolation.
            let group = unsafe { libc::getpgid(supervisor) };
            match loss {
                Loss::Caller => owner_watch.kill(),
                Loss::Group => assert_eq!(
                    unsafe { libc::kill(-(owner.id() as i32), libc::SIGKILL) },
                    0
                ),
                #[cfg(target_os = "linux")]
                Loss::Runner => runner_watch.kill(),
            }
            await_exit(&processes);
            await_exit(std::slice::from_ref(&runner_watch));
            owner.wait().unwrap();
            assert_eq!(group, supervisor, "{loss:?}: runner shared caller group");
            let temporary = Path::new(ready["temporary"].as_str().unwrap());
            #[cfg(target_os = "linux")]
            if matches!(loss, Loss::Runner) {
                assert!(temporary.exists());
                continue;
            }
            assert!(
                !temporary.exists(),
                "{loss:?}: storage retained; runner stderr: {:?}",
                owner
                    .stderr
                    .take()
                    .map(std::io::read_to_string)
                    .transpose()
                    .unwrap()
            );
            line.clear();
            stdout.read_to_string(&mut line).unwrap();
            assert!(line.is_empty(), "{line}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn runner_death_before_and_after_native_death_signal_setup() {
    for stage in ["before", "armed", "ready", "partial", "blocked"] {
        eprintln!("stage={stage}");
        let directory = tempfile::tempdir().unwrap();
        let library = startup::interposer(directory.path());
        let marker = directory.path().join("target-ran");
        let (mut events, event_writer) = std::io::pipe().unwrap();
        let (release, mut release_writer) = std::io::pipe().unwrap();
        let mut command = runner(directory.path());
        startup::preload(&mut command, &library);
        command
            .env(
                "SANDBOX_TEST_EVENT_FD",
                event_writer.as_raw_fd().to_string(),
            )
            .env("SANDBOX_TEST_RELEASE_FD", release.as_raw_fd().to_string());
        match stage {
            "before" | "armed" => {
                command.env("SANDBOX_TEST_CHILD_STAGE", stage);
            }
            _ => {
                command.env("SANDBOX_TEST_SETUP_STAGE", stage);
            }
        }
        startup::inherit(
            &mut command,
            &[event_writer.as_raw_fd(), release.as_raw_fd()],
        );
        let mut request = fixture("write", &[marker.to_str().unwrap()]);
        request["filesystem"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "path": {"type": "path", "path": directory.path()}, "access": "write"
            }));
        request["proxy"] = proxy_config();
        request["lifecycle"] =
            json!({"private_tmp": {"parent": directory.path(), "environment": ["TMPDIR"]}});
        let (mut child, mut bootstrap) = spawn(command.stdin(Stdio::piped()));
        drop((command, event_writer, release));
        let runner_watch = Process::watch(child.id() as i32);
        bootstrap.write_all(&frame(&request)).unwrap();
        let mut bytes = [0; 4];
        events.read_exact(&mut bytes).unwrap();
        let processes = watch_tree(child.id() as i32);
        assert!(
            processes
                .iter()
                .any(|process| process.pid == i32::from_ne_bytes(bytes))
        );
        runner_watch.kill();
        child.wait().unwrap();
        if stage == "before" {
            // Death before arming cannot deliver PDEATHSIG. Release the child
            // only after its creating parent has been reaped; the recheck must cancel exec.
            release_writer.write_all(b"x").unwrap();
        }
        await_exit(&processes);
        let output = child.wait_with_output().unwrap();
        assert!(output.stdout.is_empty(), "{stage}: {output:?}");
        assert!(!marker.exists(), "{stage}: target ran after owner death");
    }
}

#[cfg(target_os = "linux")]
pub(super) fn managed_proxy_bridges_retire_before_return() {
    // STOP models delayed bridge scheduling. A host peer keeps the group from
    // becoming orphaned, whose HUP/CONT would otherwise release that gate.
    for target_status in [Some(0), Some(42), None] {
        let directory = tempfile::tempdir().unwrap();
        let mut command = runner(directory.path());
        let operation = if target_status == Some(42) {
            "normal-tree"
        } else {
            "detached"
        };
        let mut value = fixture("lifecycle", &[operation]);
        value["proxy"] = proxy_config();
        value["lifecycle"] = json!({
            "private_tmp": {"parent": directory.path(), "environment": ["TMPDIR"]},
            "sigterm": "retire"
        });
        let (mut child, mut bootstrap) = spawn(command.stdin(Stdio::piped()));
        drop(command);
        let root = Process::watch(child.id() as i32);
        bootstrap.write_all(&frame(&value)).unwrap();
        drop(bootstrap);
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut temporary = String::new();
        output.read_line(&mut temporary).unwrap();
        let ready: Value = serde_json::from_str(&temporary).unwrap();
        let temporary = Path::new(ready["temporary"].as_str().unwrap());
        assert!(temporary.is_dir());
        let processes = watch_tree(child.id() as i32);
        let mut peer = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let host_status = std::fs::read_to_string("/proc/self/status").unwrap();
            let host_namespace_depth = host_status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .unwrap()
                .split_whitespace()
                .count();
            let identities: Vec<_> = processes
                .iter()
                .map(|process| {
                    let status =
                        std::fs::read_to_string(format!("/proc/{}/status", process.pid)).unwrap();
                    let parent: i32 = status
                        .lines()
                        .find_map(|line| line.strip_prefix("PPid:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    let namespace_depth = status
                        .lines()
                        .find_map(|line| line.strip_prefix("NSpid:"))
                        .unwrap()
                        .split_whitespace()
                        .count();
                    (process, parent, namespace_depth)
                })
                .collect();
            // Target readiness establishes both managed routes. Their host-side
            // leaf processes remain outside the target PID namespace; the native
            // supervisor and bubblewrap monitor each retain a child.
            let bridges: Vec<_> = identities
                .iter()
                .filter(|(process, _, depth)| {
                    process.pid != root.pid
                        && *depth == host_namespace_depth
                        && !identities
                            .iter()
                            .any(|(_, parent, _)| *parent == process.pid)
                })
                .map(|(process, _, _)| *process)
                .collect();
            assert_eq!(bridges.len(), 2, "HTTP and SOCKS host bridges");
            let group = unsafe { libc::getpgid(bridges[0].pid) };
            assert!(group > 0 && group != unsafe { libc::getpgrp() });
            assert!(
                bridges
                    .iter()
                    .all(|process| unsafe { libc::getpgid(process.pid) } == group)
            );
            let host_peer = Command::new("/bin/sh")
                .args(["-c", r"printf 'peer ready\n'; IFS= read -r line"])
                .process_group(group)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let peer_identity = Process::watch(host_peer.id() as i32);
            peer = Some((host_peer, peer_identity));
            let (host_peer, peer_identity) = peer.as_mut().unwrap();
            let mut peer_ready = String::new();
            BufReader::new(host_peer.stdout.take().unwrap())
                .read_line(&mut peer_ready)
                .unwrap();
            assert_eq!(peer_ready, "peer ready\n");
            assert_eq!(unsafe { libc::getsid(peer_identity.pid) }, unsafe {
                libc::getsid(/*pid*/ 0)
            });
            for process in &bridges {
                assert_eq!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            process.exit.as_raw_fd(),
                            libc::SIGSTOP,
                            std::ptr::null::<libc::siginfo_t>(),
                            /*flags*/ 0,
                        )
                    },
                    0
                );
            }
            let deadline = Instant::now() + Duration::from_secs(/*secs*/ 5);
            for process in &bridges {
                loop {
                    let status =
                        std::fs::read_to_string(format!("/proc/{}/status", process.pid)).unwrap();
                    if status.lines().any(|line| line.starts_with("State:\tT")) {
                        eprintln!(
                            "status={target_status:?}: stopped host bridge {}",
                            process.pid
                        );
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "bridge {} did not stop",
                        process.pid
                    );
                    std::thread::yield_now();
                }
            }
            if target_status.is_some() {
                child.stdin.take().unwrap().write_all(b"exit\n").unwrap();
            } else {
                assert_eq!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            root.exit.as_raw_fd(),
                            libc::SIGTERM,
                            std::ptr::null::<libc::siginfo_t>(),
                            /*flags*/ 0,
                        )
                    },
                    0
                );
            }
            let mut exited = libc::pollfd {
                fd: root.exit.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe {
                    libc::poll(&mut exited, /*nfds*/ 1, /*timeout*/ 15_000)
                },
                1,
                "runner did not exit"
            );
            // Capture every readiness result before reading any output or doing
            // cleanup. An eventual exit cannot satisfy this retirement barrier.
            let bridge_exits: Vec<_> = bridges
                .iter()
                .map(|process| {
                    let mut exit = libc::pollfd {
                        fd: process.exit.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    (
                        process.pid,
                        unsafe {
                            libc::poll(&mut exit, /*nfds*/ 1, /*timeout*/ 0)
                        },
                        exit.revents,
                    )
                })
                .collect();
            let mut peer_exit = libc::pollfd {
                fd: peer_identity.exit.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe {
                    libc::poll(&mut peer_exit, /*nfds*/ 1, /*timeout*/ 0)
                },
                0,
                "runner retired an unrelated process-group peer"
            );
            let status = child.wait().unwrap();
            let mut tail = String::new();
            output.read_to_string(&mut tail).unwrap();
            let error = std::io::read_to_string(child.stderr.take().unwrap()).unwrap();
            assert_eq!(status.code(), Some(target_status.unwrap_or(0)), "{error}");
            assert_eq!(tail, "");
            assert_eq!(error, "");
            assert!(!temporary.exists());
            assert!(
                bridge_exits
                    .iter()
                    .all(|(_, count, events)| *count == 1 && events & libc::POLLIN != 0),
                "runner returned before host bridge retirement: {bridge_exits:?}"
            );
        }));
        // Retain kernel identities through cleanup, including reparented stopped
        // bridges. Clean them before propagating a failed public assertion.
        for process in &processes {
            process.kill();
        }
        if let Some((mut host_peer, identity)) = peer {
            identity.kill();
            host_peer.wait().unwrap();
        }
        await_exit(&processes);
        child.wait().unwrap();
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    }
}
