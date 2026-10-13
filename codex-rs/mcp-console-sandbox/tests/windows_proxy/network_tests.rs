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
    for op in ["http", "connect"] {
        let response = denied.probe(json!({"op":op, "address":address.to_string()}))?;
        let headers = response["headers"]
            .as_str()
            .context("denied HTTP response headers")?;
        assert!(
            headers.starts_with("HTTP/1.1 403") && headers.contains("blocked-by-denylist"),
            "{op}: {response}"
        );
    }
    let response = denied.probe(json!({"op":"socks", "address":address.to_string()}))?;
    assert_eq!(response, json!({"socks":2}), "SOCKS policy denial reply");
    let response =
        denied.probe(json!({"op":"http", "address":address.to_string(), "endpoint":http}))?;
    assert!(
        response.get("error").is_some(),
        "cross-session proxy accepted: {response}"
    );
    let route_sids = allowed.probe(json!({"op":"route-sids"}))?;
    let route_sids = route_sids.as_array().context("route SIDs")?;
    anyhow::ensure!(!route_sids.is_empty(), "no restricting SIDs to exercise");
    for sid in route_sids {
        let sid = sid.as_str().context("restricting SID")?;
        let forgery = json!({"op":"forge-route", "sid":sid, "endpoint":http.strip_prefix("http://").unwrap(), "address":address.to_string()});
        let result = denied.probe(forgery.clone())?;
        if result.get("code").is_some() {
            assert_eq!(result, json!({"code":0}));
        } else {
            assert_eq!(
                result,
                json!({"identity_created":false, "reason":"restricting-sid-intersection"})
            );
            eprintln!(
                "UNAVAILABLE account route admission for {sid}: Windows prevented construction of the foreign restricting SID; host forgery below still exercises account admission"
            );
        }
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
        for (endpoint, code) in [(address.to_string(), 91), (http.clone(), 0)] {
            let mut request = forgery.clone();
            request["endpoint"] = endpoint.into();
            writeln!(
                attacker.stdin.as_mut().context("attacker stdin")?,
                "{request}"
            )?;
            line.clear();
            output.read_line(&mut line)?;
            assert_eq!(serde_json::from_str::<Value>(&line)?, json!({"code":code}));
        }
        attacker.stdin.take();
        assert!(attacker.wait()?.success());
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
    for (op, method, reason) in [
        ("http", "POST", "blocked-by-method-policy"),
        ("connect", "GET", "blocked-by-mitm-required"),
    ] {
        let response =
            session.probe(json!({"op":op, "method":method, "address":address.to_string()}))?;
        let headers = response["headers"]
            .as_str()
            .context("limited-mode HTTP response headers")?;
        assert!(
            headers.starts_with("HTTP/1.1 403") && headers.contains(reason),
            "{response}"
        );
    }
    let response = session.probe(json!({"op":"socks", "address":address.to_string()}))?;
    assert_eq!(
        response,
        json!({"socks":2}),
        "limited-mode SOCKS policy denial"
    );
    session.finish()
}
