use super::*;
use pretty_assertions::assert_eq;

#[test]
fn explicit_backend_selection_does_not_fall_back_when_namespaces_are_denied() {
    for backend in [None, Some("bubblewrap")] {
        let directory = tempfile::tempdir().unwrap();
        let mut command = runner(directory.path());
        unsafe {
            command.pre_exec(|| {
                let statement = |code, k| libc::sock_filter {
                    code,
                    jt: 0,
                    jf: 0,
                    k,
                };
                let jump = |code, k, jt, jf| libc::sock_filter { code, k, jt, jf };
                let mut filters = [
                    statement(0x20, 0),
                    jump(0x15, libc::SYS_unshare as u32, 4, 0),
                    jump(0x15, libc::SYS_clone3 as u32, 3, 0),
                    jump(0x15, libc::SYS_clone as u32, 0, 3),
                    statement(0x20, 16),
                    jump(
                        0x45,
                        (libc::CLONE_NEWUSER
                            | libc::CLONE_NEWNS
                            | libc::CLONE_NEWPID
                            | libc::CLONE_NEWNET) as u32,
                        0,
                        1,
                    ),
                    statement(0x06, 0x00050000 | libc::EPERM as u32),
                    statement(0x06, 0x7fff0000),
                ];
                let program = libc::sock_fprog {
                    len: filters.len() as u16,
                    filter: filters.as_mut_ptr(),
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                    || libc::prctl(libc::PR_SET_SECCOMP, 2, &program) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut request = request(&["/bin/echo", "target"]);
        if let Some(backend) = backend {
            request["linux_backend"] = json!(backend);
        }
        let output = run_command(command, frame(&request), &[]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("namespace"),
            "{output:?}"
        );
    }
}

#[derive(Clone, Copy)]
enum Unavailable {
    ReadinessPidfd(i32),
    PidfdSignal,
    NumericPidfd,
    OlderKernel,
}

fn constrained_runner(directory: &Path, unavailable: Unavailable) -> Command {
    let mut command = runner(directory);
    constrain(&mut command, unavailable);
    command
}

fn constrain(command: &mut Command, unavailable: Unavailable) {
    // Restrict the actual process and all of its native helpers, not a mocked
    // capability probe. Namespace lifetime must still retire detached children.
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let equal = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    let mut filters = match unavailable {
        Unavailable::ReadinessPidfd(error) => vec![
            statement(0x20, 0),
            equal(libc::SYS_setsockopt as u32, 0, 5),
            statement(0x20, 24),
            equal(libc::SOL_SOCKET as u32, 0, 3),
            statement(0x20, 32),
            equal(libc::SO_PASSPIDFD as u32, 0, 1),
            statement(0x06, 0x00050000 | error as u32),
        ],
        Unavailable::PidfdSignal | Unavailable::NumericPidfd => {
            let (number, error) = match unavailable {
                Unavailable::PidfdSignal => (libc::SYS_pidfd_send_signal, libc::ENOSYS),
                _ => (libc::SYS_pidfd_open, libc::EIO),
            };
            vec![
                statement(0x20, 0),
                equal(number as u32, 0, 1),
                statement(0x06, 0x00050000 | error as u32),
            ]
        }
        Unavailable::OlderKernel => {
            let mut filters = vec![statement(0x20, 0)];
            for number in [
                libc::SYS_landlock_create_ruleset,
                libc::SYS_landlock_add_rule,
                libc::SYS_landlock_restrict_self,
                libc::SYS_pidfd_open,
                libc::SYS_pidfd_send_signal,
                libc::SYS_clone3,
                libc::SYS_close_range,
                libc::SYS_faccessat2,
            ] {
                filters.extend([
                    equal(number as u32, 0, 1),
                    statement(0x06, 0x00050000 | libc::ENOSYS as u32),
                ]);
            }
            filters
        }
    };
    filters.extend([
        statement(0x20, 0),
        equal(libc::SYS_prctl as u32, 0, 3),
        statement(0x20, 16),
        equal(libc::PR_SET_CHILD_SUBREAPER as u32, 0, 1),
        statement(0x06, 0x00050000 | libc::ENOSYS as u32),
        statement(0x06, 0x7fff0000),
    ]);
    unsafe {
        command.pre_exec(move || {
            let program = libc::sock_fprog {
                len: filters.len() as u16,
                filter: filters.as_mut_ptr(),
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::prctl(libc::PR_SET_SECCOMP, 2, &program) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[test]
fn older_kernel_preserves_enforcement_and_namespace_lifetime() {
    // Exercise the public executable contracts with these facilities absent
    // together, including in helpers and the workload. This checks the existing
    // bubblewrap path without requiring Landlock or recent process syscalls.
    for test in [
        "filesystem_policy_denies_and_grants_writes",
        "network_permission_controls_direct_connections",
        "lifecycle::private_storage_is_removed_after_success_and_nonzero_exit",
        "prerequisite::constrained_host_retires_detached_children_and_forwards_interrupts",
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", test, "--nocapture"]);
        constrain(&mut command, Unavailable::OlderKernel);
        constrain(&mut command, Unavailable::ReadinessPidfd(libc::ENOPROTOOPT));
        let output = command.output().unwrap();
        assert!(output.status.success(), "{test}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{test}: {output:?}"
        );
    }
}

#[test]
fn namespace_lifetime_does_not_require_pidfds_or_a_host_subreaper() {
    let directory = tempfile::tempdir().unwrap();
    let command = constrained_runner(
        directory.path(),
        Unavailable::ReadinessPidfd(libc::ENOPROTOOPT),
    );
    let mut request = fixture("lifecycle", &["nonzero"]);
    request["lifecycle"] =
        json!({"parent_pid": std::process::id(), "private_tmp": {"environment": ["TMPDIR"]}});
    let output = run_command(command, frame(&request), &[]);
    assert_eq!(output.status.code(), Some(42), "{output:?}");
    assert_eq!(output.stderr, b"");
    let temporary = std::str::from_utf8(&output.stdout).unwrap().trim();
    assert!(!Path::new(temporary).exists());
}

#[test]
fn readiness_never_opens_a_handle_from_a_numeric_pid() {
    let directory = tempfile::tempdir().unwrap();
    let command = constrained_runner(directory.path(), Unavailable::NumericPidfd);
    let output = run_command(command, frame(&request(&["/bin/echo", "launched"])), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"launched\n");
    assert_eq!(output.stderr, b"");
}

#[test]
fn policy_denied_readiness_handles_preserve_public_contracts() {
    for error in [libc::EPERM, libc::EACCES] {
        let directory = tempfile::tempdir().unwrap();
        let command = constrained_runner(directory.path(), Unavailable::ReadinessPidfd(error));
        let output = run_command(command, frame(&request(&["/bin/echo", "launched"])), &[]);
        assert_eq!(output.status.code(), Some(0), "{error}: {output:?}");
        assert_eq!(output.stdout, b"launched\n");
        assert_eq!(output.stderr, b"");

        // Apply the host policy to the executable test process as well. The
        // pidfd-only contracts must recognize the same supported host as the
        // public runner above, without attempting their injected-handle cases.
        for test in [
            "prerequisite::invalid_readiness_closes_received_handles_before_retirement",
            "prerequisite::retirement_uses_the_readiness_handle_instead_of_a_numeric_pid",
        ] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", test, "--nocapture"]);
            constrain(&mut command, Unavailable::ReadinessPidfd(error));
            let output = command.output().unwrap();
            assert!(output.status.success(), "{error}: {test}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{error}: {test}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("kernel-attached pidfds are unavailable"),
                "{error}: {test}: {output:?}"
            );
        }
    }
}

fn readiness_pidfds_available() -> bool {
    use std::os::unix::net::UnixStream;

    // The replacement-identity check needs kernel-attached handles. Older
    // kernels and host policies can disable the option; the constrained-host
    // contracts exercise the runner's channel-only retirement in those cases.
    let (probe, _) = UnixStream::pair().unwrap();
    let enabled: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            probe.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSPIDFD,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ENOPROTOOPT | libc::EPERM | libc::EACCES)
            ),
            "probe kernel-attached pidfds: {error}"
        );
        eprintln!("kernel-attached pidfds are unavailable: {error}");
        return false;
    }
    true
}

#[test]
fn invalid_readiness_closes_received_handles_before_retirement() {
    if !readiness_pidfds_available() {
        return;
    }
    for (failure, expected) in [
        ("truncated", "invalid native readiness"),
        ("identity", "invalid native readiness identity"),
        ("allocation", "Too many open files"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let library = startup::interposer(directory.path());
        let mut command = runner(directory.path());
        startup::preload(&mut command, &library);
        command.env("SANDBOX_TEST_INVALID_READINESS", failure);
        let mut request = request(&["/bin/echo", "must not run"]);
        request["lifecycle"] = json!({"cleanup_timeout_ms": 100});
        let output = run_command(command, frame(&request), &[]);
        assert_eq!(output.status.code(), Some(1), "{failure}: {output:?}");
        assert_eq!(output.stdout, b"");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{failure}: {output:?}"
        );
    }
}

#[test]
fn retirement_uses_the_readiness_handle_instead_of_a_numeric_pid() {
    if !readiness_pidfds_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let library = startup::interposer(directory.path());
    let mut replacement = Command::new("/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut command = runner(directory.path());
    startup::preload(&mut command, &library);
    let (mut events, event_writer) = std::io::pipe().unwrap();
    let (release, mut release_writer) = std::io::pipe().unwrap();
    command
        .env("SANDBOX_TEST_SETUP_STAGE", "blocked")
        .env("SANDBOX_TEST_READINESS_PID", replacement.id().to_string())
        .env(
            "SANDBOX_TEST_EVENT_FD",
            event_writer.as_raw_fd().to_string(),
        )
        .env("SANDBOX_TEST_RELEASE_FD", release.as_raw_fd().to_string());
    startup::inherit(
        &mut command,
        &[event_writer.as_raw_fd(), release.as_raw_fd()],
    );
    let mut request = request(&["/bin/echo", "must not run"]);
    request["lifecycle"] = json!({"sigterm": "retire", "cleanup_timeout_ms": 100, "private_tmp": {"parent": directory.path(), "environment": ["TMPDIR"]}});
    let (child, mut bootstrap) = spawn(&mut command);
    drop(command);
    drop(event_writer);
    drop(release);
    bootstrap.write_all(&frame(&request)).unwrap();
    // Init is stopped and the runner is gated in its first setup write. This
    // orders cancellation before the next setup/retirement iteration.
    events.read_exact(&mut [0; 4]).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    release_writer.write_all(b"x").unwrap();
    let output = child.wait_with_output().unwrap();
    let replacement_status = replacement.try_wait().unwrap();
    if replacement_status.is_none() {
        replacement.kill().unwrap();
        replacement.wait().unwrap();
    }
    assert!(
        replacement_status.is_none(),
        "retirement killed the unrelated replacement process: {output:?}"
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"");
    assert_eq!(output.stderr, b"");
    assert!(!std::fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("sandbox-")
    }));
}

#[test]
fn constrained_host_retires_detached_children_and_forwards_interrupts() {
    use std::io::BufRead;
    use std::io::BufReader;
    for (operation, unavailable) in [
        (
            "normal-tree",
            Unavailable::ReadinessPidfd(libc::ENOPROTOOPT),
        ),
        (
            "interrupted",
            Unavailable::ReadinessPidfd(libc::ENOPROTOOPT),
        ),
        ("detached", Unavailable::ReadinessPidfd(libc::ENOPROTOOPT)),
        ("detached", Unavailable::PidfdSignal),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut command = constrained_runner(directory.path(), unavailable);
        let (mut child, mut bootstrap) = spawn(command.stdin(Stdio::piped()));
        drop(command);
        let mut request = fixture("lifecycle", &[operation]);
        request["lifecycle"] = json!({"parent_pid": std::process::id(), "sigterm": "retire", "private_tmp": {"environment": ["TMPDIR"]}});
        bootstrap.write_all(&frame(&request)).unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let ready: Value = serde_json::from_str(&line).unwrap();
        if operation == "normal-tree" {
            child.stdin.take().unwrap().write_all(b"exit").unwrap();
        } else {
            let signal = if operation == "interrupted" {
                libc::SIGINT
            } else {
                libc::SIGTERM
            };
            assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        }
        let stdin = child.stdin.take();
        let output = child.wait_with_output().unwrap();
        drop(stdin);
        assert_eq!(
            output.status.code(),
            Some(if operation == "detached" { 0 } else { 42 }),
            "{output:?}"
        );
        assert_eq!(output.stderr, b"");
        assert!(!Path::new(ready["temporary"].as_str().unwrap()).exists());
    }
}

#[test]
fn a_stopped_init_without_pidfds_reports_incomplete_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let library = startup::interposer(directory.path());
    let mut command = constrained_runner(
        directory.path(),
        Unavailable::ReadinessPidfd(libc::ENOPROTOOPT),
    );
    startup::preload(&mut command, &library);
    let (mut events, event_writer) = std::io::pipe().unwrap();
    let (release, mut release_writer) = std::io::pipe().unwrap();
    command
        .env("SANDBOX_TEST_SETUP_STAGE", "blocked")
        .env(
            "SANDBOX_TEST_EVENT_FD",
            event_writer.as_raw_fd().to_string(),
        )
        .env("SANDBOX_TEST_RELEASE_FD", release.as_raw_fd().to_string());
    startup::inherit(
        &mut command,
        &[event_writer.as_raw_fd(), release.as_raw_fd()],
    );
    let mut request = request(&["/bin/echo", "must not run"]);
    request["lifecycle"] = json!({"sigterm": "retire", "cleanup_timeout_ms": 100, "private_tmp": {"parent": directory.path(), "environment": ["TMPDIR"]}});
    let (child, mut bootstrap) = spawn(&mut command);
    drop(command);
    drop(event_writer);
    drop(release);
    bootstrap.write_all(&frame(&request)).unwrap();
    events.read_exact(&mut [0; 4]).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    release_writer.write_all(b"x").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(output.stdout, b"");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timed out retiring sandbox descendants"),
        "{output:?}"
    );
    assert!(
        stderr.contains("private storage retained after incomplete retirement"),
        "{output:?}"
    );
    assert!(std::fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("sandbox-")
    }));
}

#[test]
fn missing_native_wait_status_never_reports_cleanup_success() {
    let directory = tempfile::tempdir().unwrap();
    let library = startup::interposer(directory.path());
    let mut command = runner(directory.path());
    startup::preload(&mut command, &library);
    command.env("SANDBOX_TEST_FAIL_WAIT", "1");
    let mut request = request(&["/bin/echo", "must not run"]);
    request["lifecycle"] = json!({"cleanup_timeout_ms": 100, "private_tmp": {"parent": directory.path(), "environment": ["TMPDIR"]}});
    let output = run_command(command, frame(&request), &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(output.stdout, b"");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("descendant retirement failed: Input/output error"),
        "{output:?}"
    );
    assert!(
        stderr.contains("private storage retained after incomplete retirement"),
        "{output:?}"
    );
}
