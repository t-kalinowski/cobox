//! The same public transport and native probes, without provisioned accounts.
use super::*;
use pretty_assertions::assert_eq;

fn start(policy: Value) -> Result<Session> {
    Session::start_with(policy, json!({"windows_sandbox_level":"mxc"}), &[])
}

fn policy() -> Value {
    let mut policy = proxy();
    policy["allowLocalBinding"] = json!(true);
    policy
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_protects_requested_and_installed_state_despite_workload_grants() -> Result<()> {
    let requested = tempfile::tempdir()?;
    let default =
        std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA")?)
            .join("mcp-console");
    let mut roots = vec![requested.path().to_path_buf()];
    if default.is_dir() {
        roots.push(default);
    }
    if let Some(registered) = codex_windows_sandbox::ConsoleProxySlot::registered_state_directory()?
    {
        roots.push(registered);
    }
    let canaries = roots
        .iter()
        .map(tempfile::NamedTempFile::new_in)
        .collect::<std::io::Result<Vec<_>>>()?;
    for filesystem in [
        json!({"kind":"restricted","entries":[]}),
        json!({"kind":"unrestricted"}),
        json!({"kind":"external-sandbox"}),
    ] {
        let mut session = Session::start_with(
            Value::Null,
            json!({
                "windows_sandbox_level":"mxc", "windows_state_dir":requested.path(),
                "filesystem":filesystem
            }),
            &[],
        )?;
        for canary in &canaries {
            assert!(
                std::fs::File::open(canary.path()).is_ok(),
                "host read positive control"
            );
            assert!(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(canary.path())
                    .is_ok(),
                "host write positive control"
            );
            assert_eq!(
                session.probe(json!({"op":"file-access","path":canary.path()}))?,
                json!({"readable":false,"writable":false})
            );
        }
        session.finish()?;
    }
    Ok(())
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_resolves_tmpdir_grants_from_case_insensitive_target_environment() -> Result<()> {
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let target_files = [
        tempfile::NamedTempFile::new_in(first.path())?,
        tempfile::NamedTempFile::new_in(second.path())?,
    ];
    let host_file = tempfile::NamedTempFile::new()?;
    let mut session = Session::start_with(
        Value::Null,
        json!({
            "windows_sandbox_level":"mxc", "environment":{"tEmP":first.path(),"TmP":second.path()},
            "filesystem":{"kind":"restricted","entries":[
                {"path":{"type":"special","value":{"kind":"tmpdir"}},"access":"write"}
            ]}
        }),
        &[],
    )?;
    for file in &target_files {
        assert_eq!(
            session.probe(json!({"op":"file-access","path":file.path()}))?,
            json!({"readable":true,"writable":true})
        );
    }
    assert_eq!(
        session.probe(json!({"op":"file-access","path":host_file.path()}))?,
        json!({"readable":true,"writable":false})
    );
    session.finish()
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_policies_and_cross_process_proxy_ownership() -> Result<()> {
    let address = origin()?;
    let mut allowed = start(policy())?;
    let endpoint = allowed.http_endpoint()?.to_owned();
    let env = allowed.ready["environment"]
        .as_object()
        .context("environment")?;
    assert_eq!(
        env.keys()
            .filter(|key| key.eq_ignore_ascii_case("HTTP_PROXY"))
            .count(),
        1
    );
    assert!(env.keys().all(|key| {
        !key.to_ascii_uppercase()
            .starts_with("CODEX_SANDBOX_LAUNCH_")
            && key != "CONSOLE_POLICY"
    }));
    assert_ne!(endpoint, "http://127.0.0.1:1");
    let mut denied_policy = policy();
    denied_policy["domains"] = json!({"*":"allow", "127.0.0.1":"deny"});
    let mut denied = start(denied_policy)?;
    assert_ne!(denied.http_endpoint()?, endpoint);
    let mut offline = start(Value::Null)?;
    for op in ["http", "connect", "socks"] {
        for address in [address.to_string(), format!("localhost:{}", address.port())] {
            let response = allowed.probe(json!({"op":op,"address":address}))?;
            assert!(
                response["headers"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("HTTP/1.1 200")),
                "{op}: {response}"
            );
        }
        let response = denied.probe(json!({"op":op,"address":address.to_string()}))?;
        match op {
            "http" | "connect" => {
                let headers = response["headers"]
                    .as_str()
                    .context("proxy denial response")?;
                assert!(
                    headers.starts_with("HTTP/1.1 403") && headers.contains("blocked-by-denylist"),
                    "{op}: {response}"
                );
            }
            "socks" => assert!(
                response["socks"].as_u64().is_some_and(|reply| reply != 0),
                "SOCKS rejection reply: {response}"
            ),
            _ => unreachable!(),
        }
    }
    let socks = allowed.ready["environment"]
        .as_object()
        .context("environment")?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("ALL_PROXY"))
        .context("SOCKS endpoint")?
        .1
        .as_str()
        .context("SOCKS URL")?
        .to_owned();
    for attacker in [&mut denied, &mut offline] {
        for (op, endpoint) in [("http", &endpoint), ("socks", &socks)] {
            let response = attacker
                .probe(json!({"op":op,"endpoint":endpoint,"address":address.to_string()}))?;
            assert!(
                response.get("error").is_some(),
                "borrowed proxy: {response}"
            );
        }
    }
    // Even the unsandboxed owner process has no authority to use this workload's proxy.
    let mut outsider = TcpStream::connect(endpoint.strip_prefix("http://").context("HTTP URL")?)?;
    outsider.set_read_timeout(Some(Duration::from_secs(/*secs*/ 2)))?;
    let _ = write!(
        outsider,
        "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\n\r\n"
    );
    let mut bytes = [0; 64];
    assert!(!matches!(outsider.read(&mut bytes), Ok(n) if n > 0));
    offline.finish()?;
    denied.finish()?;
    allowed.finish()?;
    assert!(TcpStream::connect(endpoint.strip_prefix("http://").unwrap()).is_err());
    Ok(())
}

#[test]
#[ignore = "requires native MXC, explicit setup, and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn mxc_and_elevated_sessions_cannot_borrow_each_others_policy() -> Result<()> {
    let address = origin()?;
    let mut mxc = start(policy())?;
    let mut elevated = Session::start(proxy())?;
    let mxc_endpoint = mxc.http_endpoint()?.to_owned();
    let elevated_endpoint = elevated.http_endpoint()?.to_owned();
    for (session, endpoint) in [(&mut mxc, elevated_endpoint), (&mut elevated, mxc_endpoint)] {
        assert!(
            session
                .probe(json!({"op":"http","endpoint":endpoint,"address":address.to_string()}))?
                .get("error")
                .is_some()
        );
    }
    elevated.finish()?;
    mxc.finish()
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_limited_mode() -> Result<()> {
    network::limited_mode("mxc")
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_trusted_upstream() -> Result<()> {
    network::trusted_upstream("mxc")
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_authenticated_https_connect() -> Result<()> {
    network::authenticated_tls("mxc")
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_direct_network_and_local_binding_controls() -> Result<()> {
    let mut online = Session::start_with(
        Value::Null,
        json!({"windows_sandbox_level":"mxc", "network":"enabled"}),
        &[],
    )?;
    let mut local = start(policy())?;
    let mut offline = start(Value::Null)?;
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let tcp = TcpListener::bind(address)?;
        let udp = std::net::UdpSocket::bind(address)?;
        udp.set_read_timeout(Some(Duration::from_millis(/*millis*/ 300)))?;
        let mut inbound_controls = None;
        for (name, session, permitted) in [
            ("online", &mut online, true),
            ("local", &mut local, true),
            ("offline", &mut offline, false),
        ] {
            assert_eq!(
                session.probe(json!({"op":"tcp","address":tcp.local_addr()?.to_string()}))?,
                json!({"connected":permitted})
            );
            // MXC restricts traffic, not port allocation, even without a proxy.
            assert_eq!(
                session.probe(json!({"op":"bind","address":address}))?,
                json!({"bound":true})
            );
            let listener = session.probe(json!({"op":"tcp-listen","address":address}))?;
            assert!(
                listener["address"].is_string(),
                "MXC TCP bind/listen {name} {address}: {listener}"
            );
            if let Some(target) = listener["address"].as_str() {
                let connected = TcpStream::connect_timeout(
                    &target.parse()?,
                    Duration::from_millis(/*millis*/ 500),
                )
                .is_ok();
                let received = session.probe(json!({"op":"tcp-receive"}))?;
                let received = received["received"].as_bool().context("TCP receipt")?;
                assert_eq!(received, connected);
                if name == "online" {
                    if !received {
                        eprintln!("UNAVAILABLE MXC inbound TCP positive control: {address}");
                    }
                    inbound_controls = Some((received, false));
                } else {
                    assert_eq!(
                        received,
                        permitted && inbound_controls.context("inbound control")?.0
                    );
                }
            }
            let _ = session.probe(json!({"op":"udp","address":udp.local_addr()?.to_string()}))?;
            assert_eq!(
                udp.recv_from(&mut [0; 32]).is_ok(),
                permitted,
                "UDP {address}"
            );
            let incoming = session.probe(json!({"op":"udp-listen","address":address}))?;
            let target = incoming["address"]
                .as_str()
                .with_context(|| format!("MXC UDP bind/listen {name} {address}: {incoming}"))?;
            udp.send_to(b"probe", target)?;
            let received = session.probe(json!({"op":"udp-receive"}))?;
            let received = received["received"].as_bool().context("UDP receipt")?;
            if name == "online" {
                if !received {
                    eprintln!("UNAVAILABLE MXC inbound UDP positive control: {address}");
                }
                inbound_controls.as_mut().context("TCP control")?.1 = received;
            } else {
                assert_eq!(
                    received,
                    permitted && inbound_controls.context("inbound control")?.1
                );
            }
        }
    }
    for address in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
        if TcpStream::connect_timeout(&address.parse()?, Duration::from_secs(/*secs*/ 2)).is_err() {
            eprintln!("UNAVAILABLE external TCP positive control: {address}");
            continue;
        }
        assert_eq!(
            online.probe(json!({"op":"tcp","address":address}))?,
            json!({"connected":true})
        );
        for session in [&mut local, &mut offline] {
            assert_eq!(
                session.probe(json!({"op":"tcp","address":address}))?,
                json!({"connected":false})
            );
        }
    }
    eprintln!(
        "UNESTABLISHED external UDP egress: requires an independently observed non-loopback receiver"
    );
    offline.finish()?;
    local.finish()?;
    online.finish()
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_cleanup_failure_withholds_success_after_job_retirement() -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
    let mut session = start(policy())?;
    let child = session.probe(json!({"op":"descendant"}))?;
    let processes = observe_processes(&[&session.ready["pid"], &child["pid"]])?;
    let temporary = std::path::PathBuf::from(
        session.ready["environment"]["TMPDIR"]
            .as_str()
            .context("private storage")?,
    );
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(temporary.join("held-by-descendant"))?;
    session.child.stdin.take();
    assert_eq!(wait_for_exit(&mut session.child)?.code(), Some(1));
    assert!(
        std::fs::read_to_string(session.error.path())?
            .contains("remove retired Windows private storage")
    );
    assert_processes_retired(&processes);
    assert!(temporary.exists());
    drop(held);
    Ok(())
}

#[test]
#[ignore = "requires a usable native MXC runtime"]
fn mxc_native_job_retirement_and_proxy_cleanup() -> Result<()> {
    for termination in ["normal", "owner", "companion"] {
        let mut owner = Command::new("cmd.exe")
            .args(["/d", "/c", "pause"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()?;
        let mut session = Session::start_with(
            policy(),
            json!({"windows_sandbox_level":"mxc",
            "lifecycle":{"parent_pid":owner.id(),"private_tmp":{"environment":["TMPDIR"]}}}),
            &[],
        )?;
        let child = session.probe(json!({"op":"descendant"}))?;
        let processes = observe_processes(&[&session.ready["pid"], &child["pid"]])?;
        let endpoint = session.http_endpoint()?.to_owned();
        match termination {
            "normal" => session.finish()?,
            "owner" => {
                owner.kill()?;
                owner.wait()?;
                let status = wait_for_exit(&mut session.child)?;
                assert_ne!(status.code(), Some(125));
                assert_eq!(std::fs::read_to_string(session.error.path())?, "");
            }
            "companion" => {
                session.child.kill()?;
                assert!(!wait_for_exit(&mut session.child)?.success());
            }
            _ => unreachable!(),
        }
        assert_processes_retired(&processes);
        assert!(TcpStream::connect(endpoint.strip_prefix("http://").unwrap()).is_err());
        let _ = owner.kill();
        owner.wait()?;
    }
    start(policy())?.finish()
}
