use super::*;
use pretty_assertions::assert_eq;

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_cannot_borrow_pool_secrets_through_a_write_grant() -> Result<()> {
    let state = std::path::PathBuf::from(
        std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR").context("state")?,
    );
    let mut secrets = vec![state.join(".sandbox-secrets")];
    for slot in 0..4 {
        secrets.push(
            state
                .join("proxy-slots")
                .join(slot.to_string())
                .join(".sandbox-secrets"),
        );
    }
    let canaries = secrets
        .iter()
        .map(tempfile::NamedTempFile::new_in)
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut session = Session::start_with(
        proxy(),
        json!({"filesystem":{"kind":"restricted","entries":[
            {"path":{"type":"path","path":state},"access":"write"}
        ]}}),
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
            session.probe(json!({"op":"file-access", "path":canary.path()}))?,
            json!({"readable":false,"writable":false})
        );
    }
    session.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_transports_policies_and_isolated_companions() -> Result<()> {
    let address = origin()?;
    let mut allowed = Session::start(proxy())?;
    let env = allowed.ready["environment"]
        .as_object()
        .context("environment")?;
    let http = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("HTTP_PROXY"))
        .context("HTTP_PROXY")?
        .1
        .as_str()
        .unwrap()
        .to_owned();
    assert!(http.starts_with("http://127.0.0.1:4318"), "{http}");
    assert_eq!(
        env.iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("HTTP_PROXY"))
            .count(),
        1
    );
    assert_eq!(
        env.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("NO_PROXY"))
            .unwrap()
            .1,
        ""
    );
    for op in ["http", "connect", "socks"] {
        for address in [address.to_string(), format!("localhost:{}", address.port())] {
            let result = allowed.probe(json!({"op":op, "address":address}))?;
            assert!(
                result["headers"]
                    .as_str()
                    .is_some_and(|headers| headers.starts_with("HTTP/1.1 200")),
                "{op}: {result}"
            );
        }
    }
    let mut deny = proxy();
    deny["domains"] = json!({"*":"allow", "127.0.0.1":"deny"});
    deny["allowLocalBinding"] = json!(true);
    let mut denied = Session::start(deny)?;
    let response = denied.probe(json!({"op":"http", "address":address.to_string()}))?;
    assert!(
        response["headers"]
            .as_str()
            .context("HTTP response headers")?
            .contains("blocked-by-denylist"),
        "{response}"
    );
    for op in ["connect", "socks"] {
        let response = denied.probe(json!({"op":op, "address":address.to_string()}))?;
        assert!(
            !response["headers"]
                .as_str()
                .is_some_and(|headers| headers.starts_with("HTTP/1.1 200")),
            "{op}: {response}"
        );
    }
    let response =
        denied.probe(json!({"op":"http", "address":address.to_string(), "endpoint":http}))?;
    assert!(
        response.get("error").is_some(),
        "cross-session proxy accepted: {response}"
    );
    let route_sids = allowed.probe(json!({"op":"route-sids"}))?;
    for sid in route_sids
        .as_array()
        .context("route SIDs")?
        .iter()
        .filter_map(Value::as_str)
    {
        let forgery = json!({"op":"forge-route", "sid":sid, "endpoint":http.strip_prefix("http://").unwrap(), "address":address.to_string()});
        assert_eq!(denied.probe(forgery.clone())?, json!({"code":0}));
        // A host-account child can create the exact route SID without the session's account.
        let mut attacker = Command::new(cargo_bin("mcp-console-sandbox-fixture")?)
            .arg("proxy-session")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let mut output =
            std::io::BufReader::new(attacker.stdout.take().context("attacker stdout")?);
        let mut line = String::new();
        output.read_line(&mut line)?;
        line.clear();
        writeln!(
            attacker.stdin.as_mut().context("attacker stdin")?,
            "{forgery}"
        )?;
        output.read_line(&mut line)?;
        attacker.stdin.take();
        assert!(attacker.wait()?.success());
        assert_eq!(serde_json::from_str::<Value>(&line)?, json!({"code":0}));
    }
    assert_eq!(
        denied.probe(json!({"op":"tcp", "address":address.to_string()}))?,
        json!({"connected":true})
    );
    assert_eq!(
        allowed.probe(json!({"op":"tcp", "address":address.to_string()}))?,
        json!({"connected":false})
    );
    let mut offline = Session::start(Value::Null)?;
    assert_eq!(
        offline.probe(json!({"op":"tcp", "address":address.to_string()}))?,
        json!({"connected":false})
    );
    assert!(
        offline
            .probe(json!({"op":"http", "address":address.to_string(), "endpoint":http}))?
            .get("error")
            .is_some()
    );
    for port in 43180..43188 {
        assert_eq!(
            denied.probe(json!({"op":"bind", "address":format!("127.0.0.1:{port}")}))?,
            json!({"bound":false})
        );
    }
    offline.finish()?;
    denied.finish()?;
    allowed.finish()?;
    assert!(
        TcpStream::connect(http.strip_prefix("http://").unwrap()).is_err(),
        "retired proxy remained open"
    );
    Ok(())
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_limited_mode_rejects_writes_and_tunnels() -> Result<()> {
    limited_mode("elevated")
}

pub(super) fn limited_mode(backend: &str) -> Result<()> {
    let address = origin()?;
    let mut policy = proxy();
    policy["mode"] = json!("limited");
    policy["allowLocalBinding"] = json!(backend == "mxc");
    let mut session = Session::start_with(policy, json!({"windows_sandbox_level":backend}), &[])?;
    let allowed = session.probe(json!({"op":"http", "address":address.to_string()}))?;
    assert!(
        allowed["headers"]
            .as_str()
            .context("HTTP response headers")?
            .starts_with("HTTP/1.1 200"),
        "{allowed}"
    );
    for (op, method) in [("http", "POST"), ("connect", "GET"), ("socks", "GET")] {
        let response =
            session.probe(json!({"op":op, "method":method, "address":address.to_string()}))?;
        assert!(
            !response["headers"]
                .as_str()
                .is_some_and(|headers| headers.starts_with("HTTP/1.1 200")),
            "{response}"
        );
    }
    session.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_direct_ipv4_ipv6_tcp_udp_and_local_access() -> Result<()> {
    let mut online = Session::start_with(Value::Null, json!({"network":"enabled"}), &[])?;
    let mut strict = Session::start(proxy())?;
    let mut local_policy = proxy();
    local_policy["allowLocalBinding"] = json!(true);
    let mut local = Session::start(local_policy)?;
    let mut offline = Session::start(Value::Null)?;
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let tcp = TcpListener::bind(address)?;
        let udp = std::net::UdpSocket::bind(address)?;
        udp.set_read_timeout(Some(Duration::from_millis(/*millis*/ 200)))?;
        for (session, permitted) in [
            (&mut online, true),
            (&mut strict, false),
            (&mut local, true),
            (&mut offline, false),
        ] {
            assert_eq!(
                session.probe(json!({"op":"bind", "address":address}))?,
                json!({"bound":permitted}),
                "local TCP binding {address}"
            );
            assert_eq!(
                session.probe(json!({"op":"tcp", "address":tcp.local_addr()?.to_string()}))?,
                json!({"connected":permitted})
            );
            let _ = session.probe(json!({"op":"udp", "address":udp.local_addr()?.to_string()}))?;
            let mut bytes = [0; 32];
            assert_eq!(
                udp.recv_from(&mut bytes).is_ok(),
                permitted,
                "UDP {address}"
            );
            let incoming = session.probe(json!({"op":"udp-listen", "address":address}))?;
            if let Some(target) = incoming["address"].as_str() {
                udp.send_to(b"probe", target)?;
                assert_eq!(
                    session.probe(json!({"op":"udp-receive"}))?,
                    json!({"received":permitted}),
                    "inbound UDP {address}"
                );
            } else {
                assert!(!permitted, "positive UDP bind control failed: {incoming}");
            }
        }
    }
    for address in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
        if TcpStream::connect_timeout(&address.parse()?, Duration::from_secs(/*secs*/ 2)).is_err() {
            eprintln!("UNAVAILABLE external TCP positive control: {address}");
            continue;
        }
        assert_eq!(
            online.probe(json!({"op":"tcp", "address":address}))?,
            json!({"connected":true})
        );
        for session in [&mut strict, &mut local, &mut offline] {
            assert_eq!(
                session.probe(json!({"op":"tcp", "address":address}))?,
                json!({"connected":false})
            );
        }
    }
    if let Ok(address) = std::env::var("MCP_CONSOLE_SANDBOX_TEST_ECHO_ADDR") {
        // A separate host/VM must echo UDP and accept TCP on this non-loopback address.
        // Missing echoes establish only a blocked round trip: the receive filter could
        // drop replies to escaped datagrams. Egress requires observation at that peer.
        eprintln!("UNESTABLISHED external UDP egress: echo results do not observe peer receipt");
        for (session, permitted) in [
            (&mut online, true),
            (&mut strict, false),
            (&mut local, false),
            (&mut offline, false),
        ] {
            assert_eq!(
                session.probe(json!({"op":"tcp", "address":address}))?,
                json!({"connected":permitted})
            );
            assert_eq!(
                session.probe(json!({"op":"udp-echo", "address":address}))?,
                json!({"received":permitted})
            );
        }
    } else {
        eprintln!(
            "UNAVAILABLE external UDP positive control: set MCP_CONSOLE_SANDBOX_TEST_ECHO_ADDR"
        );
    }
    offline.finish()?;
    local.finish()?;
    strict.finish()?;
    online.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_uses_trusted_upstream_and_preserves_domain_denials() -> Result<()> {
    trusted_upstream("elevated")
}

pub(super) fn trusted_upstream(backend: &str) -> Result<()> {
    let upstream = origin()?;
    let mut policy = proxy();
    policy["allowUpstreamProxy"] = json!(true);
    policy["allowLocalBinding"] = json!(true);
    policy["domains"] = json!({"allowed.invalid":"allow", "denied.invalid":"deny"});
    let mut session = Session::start_with(
        policy,
        json!({"windows_sandbox_level":backend}),
        &[
            ("HTTP_PROXY", format!("http://{upstream}")),
            ("HTTPS_PROXY", format!("http://{upstream}")),
        ],
    )?;
    for op in ["http", "connect"] {
        let response = session.probe(json!({"op":op, "address":"allowed.invalid:80"}))?;
        assert!(
            response["headers"]
                .as_str()
                .context("HTTP response headers")?
                .starts_with("HTTP/1.1 200"),
            "{response}"
        );
        let response = session.probe(json!({"op":op, "address":"denied.invalid:80"}))?;
        assert!(
            response["headers"]
                .as_str()
                .context("HTTP response headers")?
                .contains("blocked-by-denylist"),
            "{response}"
        );
    }
    session.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_port_conflict_and_pool_exhaustion_fail_closed() -> Result<()> {
    for enabled in [false, true] {
        let mut policy = proxy();
        policy["enableSocks5"] = json!(enabled);
        for port in [43180, 43181] {
            let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
            let error = Session::start(policy.clone())
                .err()
                .context("port conflict must reject startup")?;
            assert!(error.to_string().contains("no port fallback"), "{error:#}");
            drop(occupied);
        }
    }
    let first = Session::start(proxy())?;
    let second = Session::start(proxy())?;
    let error = Session::start(proxy())
        .err()
        .context("pool exhaustion must reject startup")?;
    assert!(
        error.to_string().contains("busy or quarantined"),
        "{error:#}"
    );
    second.finish()?;
    first.finish()
}

#[test]
#[ignore = "requires explicit setup and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_concurrent_admission_and_disabled_socks() -> Result<()> {
    let address = origin()?;
    let mut policy = proxy();
    policy["enableSocks5"] = json!(false);
    let barrier = std::sync::Barrier::new(2);
    let (mut first, second) = std::thread::scope(|scope| -> Result<_> {
        let start = || {
            barrier.wait();
            Session::start(policy.clone())
        };
        let first = scope.spawn(start);
        let second = scope.spawn(start);
        Ok((first.join().unwrap()?, second.join().unwrap()?))
    })?;
    assert_ne!(first.lease_path()?, second.lease_path()?);
    let endpoint: std::net::SocketAddr = first
        .http_endpoint()?
        .strip_prefix("http://")
        .context("HTTP endpoint")?
        .parse()?;
    let result = first.probe(json!({"op":"http", "address":address.to_string()}))?;
    assert!(
        result["headers"]
            .as_str()
            .context("HTTP response headers")?
            .starts_with("HTTP/1.1 200"),
        "{result}"
    );
    // The disabled service's firewall exception still has an owner. It cannot
    // be hijacked by a host listener and does not accept SOCKS requests.
    assert!(TcpListener::bind((endpoint.ip(), endpoint.port() + 1)).is_err());
    let result = first.probe(json!({"op":"socks", "address":address.to_string(),
        "endpoint":format!("socks5://{}:{}", endpoint.ip(), endpoint.port() + 1)}))?;
    assert!(
        result.get("error").is_some(),
        "disabled SOCKS accepted: {result}"
    );
    second.finish()?;
    first.finish()
}

#[test]
#[ignore = "requires explicit setup, curl.exe, and MCP_CONSOLE_SANDBOX_TEST_STATE_DIR"]
fn elevated_proxy_https_connect_transfers_authenticated_tls() -> Result<()> {
    authenticated_tls("elevated")
}

pub(super) fn authenticated_tls(backend: &str) -> Result<()> {
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![generated.cert.der().clone()], key.into())?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<()> {
        let (tcp, _) = listener.accept()?;
        tcp.set_read_timeout(Some(Duration::from_secs(/*secs*/ 5)))?;
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(std::sync::Arc::new(config))?,
            tcp,
        );
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tls.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")?;
        tls.flush()?;
        Ok(())
    });
    let mut policy = proxy();
    policy["allowLocalBinding"] = json!(backend == "mxc");
    let mut session = Session::start_with(policy, json!({"windows_sandbox_level":backend}), &[])?;
    let certificate = session._directory.path().join("origin.pem");
    std::fs::write(&certificate, generated.cert.pem())?;
    assert_eq!(
        session.probe(
            json!({"op":"https", "address":address.to_string(), "certificate":certificate})
        )?,
        json!({"code":0,"body":"OK","error":""})
    );
    server
        .join()
        .map_err(|_| anyhow::anyhow!("TLS origin thread panicked"))??;
    session.finish()
}
