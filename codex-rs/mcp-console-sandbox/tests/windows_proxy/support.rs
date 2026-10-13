use super::*;
use pretty_assertions::assert_eq;

pub(super) struct Session {
    pub(super) child: std::process::Child,
    pub(super) output: std::sync::mpsc::Receiver<std::io::Result<String>>,
    pub(super) ready: Value,
    pub(super) error: tempfile::NamedTempFile,
    pub(super) _directory: tempfile::TempDir,
}

impl Session {
    pub(super) fn start(policy: Value) -> Result<Self> {
        Self::start_with(policy, json!({}), &[])
    }

    pub(super) fn start_with(
        policy: Value,
        overrides: Value,
        host_environment: &[(&str, String)],
    ) -> Result<Self> {
        let directory = tempfile::tempdir_in(std::env::var_os("PUBLIC").context("PUBLIC")?)?;
        let fixture = directory.path().join("fixture.exe");
        std::fs::copy(cargo_bin("mcp-console-sandbox-fixture")?, &fixture)?;
        let state = std::path::PathBuf::from(
            std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR").context(
                "set MCP_CONSOLE_SANDBOX_TEST_STATE_DIR to explicitly provisioned state",
            )?,
        );
        let mut config = json!({"extends": ":read-only", "network": "enabled", "proxy": policy,
            "windows_backend":"elevated",
            "lifecycle": {"private_tmp":{"parent":directory.path(), "environment":["TMPDIR"]}},
            "windows_state_dir": state, "environment": {"hTtP_pRoXy":"http://127.0.0.1:1", "No_ProXy":"*",
            "CoDeX_WinDows_SANDBOX_PROXY_PORTS":"1,2", "CoDeX_NETWORK_ALLOW_LOCAL_BINDING":"1",
            "CoDeX_SaNdBoX_LaUnCh_Count":"999", "CODEX_SANDBOX_LAUNCH_0":"untrusted"}});
        if policy.is_null() {
            config["network"] = json!("restricted");
        }
        config
            .as_object_mut()
            .context("configuration object")?
            .extend(
                overrides
                    .as_object()
                    .context("configuration overrides")?
                    .clone(),
            );
        let error = tempfile::NamedTempFile::new()?;
        let mut child = Command::new(cargo_bin("mcp-console-sandbox")?)
            .current_dir(directory.path())
            .env("CONSOLE_POLICY", config.to_string())
            .env("USERPROFILE", directory.path())
            .env("HOME", directory.path())
            .envs(host_environment.iter().map(|(key, value)| (*key, value)))
            .args(["--config-env", "CONSOLE_POLICY", "--"])
            .arg(&fixture)
            .arg("proxy-session")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(error.reopen()?)
            .spawn()?;
        let stdout = child.stdout.take().context("stdout")?;
        let (send, output) = std::sync::mpsc::sync_channel(/*bound*/ 1);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let line = match output.recv_timeout(Duration::from_secs(/*secs*/ 20)) {
            Ok(line) => line?,
            Err(receive_error) => {
                child.stdin.take();
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!(
                    "companion did not launch ({receive_error}): {}",
                    std::fs::read_to_string(error.path()).unwrap_or_default()
                );
            }
        };
        let ready = serde_json::from_str(&line)?;
        Ok(Self {
            child,
            output,
            ready,
            error,
            _directory: directory,
        })
    }

    pub(super) fn probe(&mut self, request: Value) -> Result<Value> {
        writeln!(self.child.stdin.as_mut().context("stdin")?, "{request}")?;
        let line = self
            .output
            .recv_timeout(Duration::from_secs(/*secs*/ 20))
            .context("fixture reply deadline")??;
        Ok(serde_json::from_str(&line)?)
    }

    pub(super) fn http_endpoint(&self) -> Result<&str> {
        self.ready["environment"]
            .as_object()
            .context("environment")?
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("HTTP_PROXY"))
            .and_then(|(_, value)| value.as_str())
            .context("endpoint")
    }

    pub(super) fn lease_path(&self) -> Result<std::path::PathBuf> {
        let endpoint: std::net::SocketAddr = self
            .http_endpoint()?
            .strip_prefix("http://")
            .context("HTTP URL")?
            .parse()?;
        anyhow::ensure!(
            (43180..43188).contains(&endpoint.port()),
            "unexpected managed port"
        );
        let slot = (endpoint.port() - 43180) / 2;
        let state = std::path::PathBuf::from(
            std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR").context("state")?,
        );
        Ok(state
            .join(".sandbox-secrets")
            .join(format!("proxy-slot-{slot}.lease")))
    }

    pub(super) fn finish(self) -> Result<()> {
        self.finish_with_code(/*code*/ 0)
    }

    pub(super) fn finish_with_code(mut self, code: i32) -> Result<()> {
        let temporary = self.ready["environment"]["TMPDIR"]
            .as_str()
            .map(std::path::PathBuf::from);
        self.child.stdin.take();
        assert_eq!(wait_for_exit(&mut self.child)?.code(), Some(code));
        let error = std::fs::read_to_string(self.error.path())?;
        assert_eq!(error, "");
        if let Some(temporary) = temporary {
            assert!(!temporary.exists(), "private storage survived retirement");
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.child.stdin.take();
        let _ = wait_for_exit(&mut self.child);
        if std::thread::panicking() {
            eprintln!(
                "companion stderr: {}",
                std::fs::read_to_string(self.error.path()).unwrap_or_default()
            );
        }
    }
}

pub(super) fn wait_for_exit(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    use std::os::windows::io::AsRawHandle;
    let waited = unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(
            child.as_raw_handle(),
            /*dwmilliseconds*/ 20_000,
        )
    };
    if waited != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("companion retirement deadline expired; retain its quarantine");
    }
    Ok(child.wait()?)
}

pub(super) fn origin() -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(/*secs*/ 3)));
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    break;
                }
                request.push(byte[0]);
            }
            if request.starts_with(b"CONNECT ") {
                let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                request.clear();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    request.push(byte[0]);
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    Ok(address)
}

pub(super) fn observe_processes(pids: &[&Value]) -> Result<Vec<std::os::windows::io::OwnedHandle>> {
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::System::Threading::*;
    pids.iter()
        .map(|pid| {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE,
                    /*binherithandle*/ 0,
                    pid.as_u64().context("process id")? as u32,
                )
            };
            anyhow::ensure!(
                !handle.is_null(),
                "observe workload: {}",
                std::io::Error::last_os_error()
            );
            Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
        })
        .collect()
}

pub(super) fn assert_processes_retired(processes: &[std::os::windows::io::OwnedHandle]) {
    use std::os::windows::io::AsRawHandle;
    for process in processes {
        assert_eq!(
            unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    process.as_raw_handle(),
                    /*dwmilliseconds*/ 10_000,
                )
            },
            windows_sys::Win32::Foundation::WAIT_OBJECT_0
        );
    }
}
