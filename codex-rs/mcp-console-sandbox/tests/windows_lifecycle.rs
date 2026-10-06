#![cfg(windows)]

use anyhow::Context;
use anyhow::Result;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::io::BufRead;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::PROCESS_SYNCHRONIZE;
use windows_sys::Win32::System::Threading::PROCESS_TERMINATE;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

fn configuration(root: &Path) -> Value {
    json!({
        "version": 2, "extends": ":read-only", "network": "enabled",
        "windows_sandbox_level": "unelevated",
        "windows_state_dir": root.join("state"),
        "lifecycle": {"private_tmp": {"parent": root, "environment": ["TMPDIR"]}},
    })
}

fn runner(root: &Path, operation: &str) -> Result<Command> {
    let mut command = Command::new(cargo_bin("mcp-console-sandbox")?);
    command
        .current_dir(root)
        .env("CONSOLE_POLICY", configuration(root).to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(cargo_bin("mcp-console-sandbox-fixture")?)
        .arg(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}

struct Process(OwnedHandle);

impl Process {
    fn open(pid: u32) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                /*binherithandle*/ 0,
                pid,
            )
        };
        anyhow::ensure!(
            !handle.is_null(),
            "open fixture {pid}: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
    }

    fn wait(&self) {
        assert_eq!(
            unsafe {
                WaitForSingleObject(self.0.as_raw_handle(), /*dwmilliseconds*/ 10_000)
            },
            WAIT_OBJECT_0,
            "fixture process survived retirement"
        );
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            TerminateProcess(self.0.as_raw_handle(), /*uexitcode*/ 1);
            WaitForSingleObject(self.0.as_raw_handle(), /*dwmilliseconds*/ 5_000);
        }
    }
}

fn ready(child: &mut Child) -> Result<Value> {
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.as_mut().context("fixture stdout")?)
        .read_line(&mut line)?;
    serde_json::from_str(&line).context("fixture readiness")
}

#[test]
fn binary_stdin_is_preserved_through_eof() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut child = runner(root.path(), "copy-stdin")?.spawn()?;
    let process = Process::open(child.id())?;
    let input: Vec<u8> = (0..256)
        .cycle()
        .take(512 * 1024)
        .map(|byte| byte as u8)
        .collect();
    let expected = input.clone();
    let mut stdin = child.stdin.take().context("runner stdin")?;
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output()?;
    writer.join().expect("input writer")?;
    process.wait();
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), expected, vec![])
    );
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn read_only_policy_denies_target_writes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let forbidden = root.path().join("forbidden");
    let output = runner(root.path(), "probe-write")?
        .arg(&forbidden)
        .output()?;
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), b"write denied\n".to_vec(), vec![])
    );
    assert!(!forbidden.exists());
    Ok(())
}

#[test]
fn target_uses_a_private_desktop() -> Result<()> {
    let root = tempfile::tempdir()?;
    let output = runner(root.path(), "desktop")?.output()?;
    assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
    let desktop = String::from_utf8(output.stdout)?;
    assert!(desktop.starts_with("ConsoleSandboxDesktop-"), "{desktop:?}");
    Ok(())
}

#[test]
fn root_exit_retires_descendants_before_removing_storage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut child = runner(root.path(), "tree")?.spawn()?;
    let process = Process::open(child.id())?;
    let receipt = ready(&mut child)?;
    let descendant =
        Process::open(receipt["descendant"].as_u64().context("descendant pid")? as u32)?;
    let temporary = Path::new(receipt["temporary"].as_str().context("private storage")?);
    assert!(temporary.join("held-by-descendant").exists());
    child
        .stdin
        .as_mut()
        .context("runner stdin")?
        .write_all(b"x")?;
    process.wait();
    descendant.wait();
    let output = child.wait_with_output()?;
    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(42), vec![], vec![])
    );
    assert!(!temporary.exists());
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn direct_caller_death_retires_workload_and_storage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut owner = Command::new(cargo_bin("mcp-console-sandbox-fixture")?)
        .arg("owner")
        .arg(cargo_bin("mcp-console-sandbox")?)
        .current_dir(root.path())
        .env("CONSOLE_POLICY", configuration(root.path()).to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let owner_process = Process::open(owner.id())?;
    let receipt = ready(&mut owner)?;
    let processes = ["runner", "root", "descendant"]
        .map(|name| Process::open(receipt[name].as_u64().expect("fixture pid") as u32));
    let [runner, target, descendant] = processes;
    let (runner, target, descendant) = (runner?, target?, descendant?);
    owner.kill()?;
    owner_process.wait();
    runner.wait();
    target.wait();
    descendant.wait();
    let output = owner.wait_with_output()?;
    assert_eq!(output.stderr, Vec::<u8>::new());
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn runner_loss_retires_descendants_and_retains_storage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut child = runner(root.path(), "tree-hold")?.spawn()?;
    let process = Process::open(child.id())?;
    let receipt = ready(&mut child)?;
    let target = Process::open(receipt["root"].as_u64().context("root pid")? as u32)?;
    let descendant =
        Process::open(receipt["descendant"].as_u64().context("descendant pid")? as u32)?;
    child.kill()?;
    process.wait();
    target.wait();
    descendant.wait();
    child.wait()?;
    assert!(Path::new(receipt["temporary"].as_str().context("private storage")?).is_dir());
    Ok(())
}

#[test]
#[ignore = "requires explicit elevated Console setup and access to the Public directory"]
fn elevated_offline_account_denies_loopback_tcp() -> Result<()> {
    let root = tempfile::tempdir_in(std::env::var_os("PUBLIC").context("PUBLIC")?)?;
    // The separate account needs ordinary host read access to its executable.
    let fixture = root.path().join("fixture.exe");
    std::fs::copy(cargo_bin("mcp-console-sandbox-fixture")?, &fixture)?;
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let listener = std::net::TcpListener::bind(address)?;
        for (network, expected) in [("enabled", "connected\n"), ("restricted", "blocked\n")] {
            let config = json!({
                "version":2, "extends":":read-only", "network":network,
                "windows_sandbox_level":"elevated",
                "windows_state_dir": std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR")
                    .map(PathBuf::from),
            });
            let output = Command::new(cargo_bin("mcp-console-sandbox")?)
                .current_dir(root.path())
                .env("CONSOLE_POLICY", config.to_string())
                .args(["--config-env", "CONSOLE_POLICY", "--"])
                .arg(&fixture)
                .arg("connect")
                .arg(listener.local_addr()?.to_string())
                .output()?;
            assert_eq!(
                (output.status.code(), output.stdout, output.stderr),
                (Some(0), expected.as_bytes().to_vec(), vec![]),
                "{network}"
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires explicit elevated Console setup and access to the Public directory"]
fn elevated_offline_account_denies_loopback_udp() -> Result<()> {
    let root = tempfile::tempdir_in(std::env::var_os("PUBLIC").context("PUBLIC")?)?;
    let fixture = root.path().join("fixture.exe");
    std::fs::copy(cargo_bin("mcp-console-sandbox-fixture")?, &fixture)?;
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let listener = std::net::UdpSocket::bind(address)?;
        listener.set_read_timeout(Some(std::time::Duration::from_millis(/*millis*/ 200)))?;
        for network in ["enabled", "restricted"] {
            let config = json!({
                "version":2, "extends":":read-only", "network":network,
                "windows_sandbox_level":"elevated",
                "windows_state_dir": std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR")
                    .map(PathBuf::from),
            });
            let output = Command::new(cargo_bin("mcp-console-sandbox")?)
                .current_dir(root.path())
                .env("CONSOLE_POLICY", config.to_string())
                .args(["--config-env", "CONSOLE_POLICY", "--"])
                .arg(&fixture)
                .arg("datagram")
                .arg(listener.local_addr()?.to_string())
                .output()?;
            assert_eq!((output.status.code(), output.stderr), (Some(0), vec![]));
            // UDP sends can succeed locally even when the firewall drops the packet.
            // The host's receipt, with an online positive control, is the boundary.
            assert!(matches!(output.stdout.as_slice(), b"sent\n" | b"blocked\n"));
            let mut buffer = [0; 8];
            let received = match listener.recv(&mut buffer) {
                Ok(length) => Some(buffer[..length].to_vec()),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            assert_eq!(
                received,
                (network == "enabled").then(|| b"probe".to_vec()),
                "{network} {address}"
            );
        }
    }
    Ok(())
}
