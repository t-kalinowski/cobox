use super::*;
use pretty_assertions::assert_eq;

fn native_command(directory: &Path, arguments: &[&str]) -> Command {
    let mut command = runner(directory);
    command
        .current_dir(directory)
        .arg("--sandbox-policy-cwd")
        .arg(directory)
        .arg("--permission-profile")
        .arg(
            serde_json::to_string(&codex_protocol::models::PermissionProfile::read_only()).unwrap(),
        )
        .arg("--")
        .args(arguments);
    command
}

#[test]
fn ordinary_entry_preserves_upstream_sigpipe_disposition() {
    let directory = tempfile::tempdir().unwrap();
    // Rust's helper startup ignores SIGPIPE. Upstream fork/exec preserves that
    // disposition; Command::spawn resets it before the target loader runs.
    let output = native_command(
        directory.path(),
        &["/bin/sh", "-c", "kill -PIPE $$; exit 23"],
    )
    .output()
    .unwrap();
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(23), vec![], vec![])
    );
}

#[test]
fn ordinary_entry_releases_all_helper_stdin_readers() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = cargo_bin("mcp-console-sandbox-fixture").unwrap();
    let (gate, mut release) = std::io::pipe().unwrap();
    let mut command = native_command(
        directory.path(),
        &[fixture.to_str().unwrap(), "close-stdin"],
    );
    command.stdin(Stdio::piped()).stderr(Stdio::from(gate));
    let mut child = command.spawn().unwrap();
    drop(command);
    let mut stdin = child.stdin.take().unwrap();
    assert_eq!(
        unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    // Fill the pipe before waiting: writable means every helper released its
    // reader, even though init and the target remain alive behind the gate.
    loop {
        match stdin.write(&[0; 4096]) {
            Ok(written) => assert!(written > 0),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                break;
            }
        }
    }
    let mut ready = [0; 6];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    let mut event = libc::pollfd {
        fd: stdin.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let writable = unsafe { libc::poll(&mut event, 1, 5000) };
    let write = stdin.write_all(b"closed-input-probe");
    release.write_all(b"x").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(ready, *b"closed");
    assert_eq!(writable, 1);
    assert_eq!(write.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
}

#[test]
fn standalone_init_forwards_direct_signals() {
    let output = run(frame(&fixture("signal-init", &[])), &[]);
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(42), vec![], vec![])
    );
}

#[test]
fn default_null_and_explicit_bubblewrap_keep_supervision() {
    for backend in [None, Some(Value::Null), Some(json!("bubblewrap"))] {
        let mut request = fixture("lifecycle", &["nonzero"]);
        if let Some(backend) = backend {
            request["linux_backend"] = backend;
        }
        request["lifecycle"] = json!({"private_tmp": {"environment": ["TMPDIR"]}});
        let output = run(frame(&request), &[]);
        assert_eq!(output.status.code(), Some(42), "{output:?}");
        assert_eq!(output.stderr, b"");
        let temporary = std::str::from_utf8(&output.stdout).unwrap().trim();
        assert!(!Path::new(temporary).exists());
    }
}
