#![cfg(windows)]

use anyhow::Context;
use anyhow::Result;
use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

fn probe(request: Value) -> Result<Value> {
    probe_with_command(
        Command::new(cargo_bin("mcp-console-sandbox-fixture")?).arg("proxy-session"),
        request,
    )
}

fn probe_with_command(command: &mut Command, request: Value) -> Result<Value> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start fixture")?;
    writeln!(child.stdin.take().context("fixture stdin")?, "{request}")?;
    let output = child.wait_with_output()?;
    anyhow::ensure!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout)?;
    Ok(serde_json::from_str(
        stdout.lines().nth(1).context("probe result")?,
    )?)
}

fn read_headers(stream: &mut TcpStream) -> Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(/*secs*/ 2)))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    Ok(String::from_utf8(request)?)
}

fn accept(listener: TcpListener) -> Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(/*secs*/ 3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(/*millis*/ 10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[test]
fn socks_probe_encodes_bracketed_ipv6_as_an_ip_address() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("socks5://{}", listener.local_addr()?);
    let server = std::thread::spawn(move || -> Result<()> {
        let mut stream = accept(listener)?;
        stream.set_read_timeout(Some(Duration::from_secs(/*secs*/ 2)))?;
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting)?;
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0])?;
        let mut request = [0; 4];
        stream.read_exact(&mut request)?;
        assert_eq!(request, [5, 1, 0, 4]);
        let mut destination = [0; 18];
        stream.read_exact(&mut destination)?;
        let mut expected = std::net::Ipv6Addr::LOCALHOST.octets().to_vec();
        expected.extend(8080_u16.to_be_bytes());
        assert_eq!(destination.as_slice(), expected.as_slice());
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])?;
        assert!(read_headers(&mut stream)?.starts_with("GET / HTTP/1.1\r\n"));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")?;
        Ok(())
    });
    let response = probe(json!({"op":"socks", "endpoint":endpoint, "address":"[::1]:8080"}))?;
    server
        .join()
        .map_err(|_| anyhow::anyhow!("SOCKS probe server panicked"))??;
    assert_eq!(
        response,
        json!({"headers":"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "body":"OK"})
    );
    Ok(())
}

#[test]
fn socks_probe_requires_a_complete_valid_connect_reply() -> Result<()> {
    let mut ipv6_denial = vec![5, 2, 0, 4];
    ipv6_denial.extend([0; 18]);
    for (reply, expected) in [
        (vec![5, 2, 0, 1, 0, 0, 0, 0, 0, 0], Some(2)),
        (ipv6_denial, Some(2)),
        (vec![5, 8, 0, 3, 1, b'a', 0, 0], Some(8)),
        (vec![5, 2], None),
        (vec![4, 2, 0, 1, 0, 0, 0, 0, 0, 0], None),
        (vec![5, 9, 0, 1, 0, 0, 0, 0, 0, 0], None),
        (vec![5, 2, 1, 1, 0, 0, 0, 0, 0, 0], None),
        (vec![5, 2, 0, 2], None),
        (vec![5, 2, 0, 1, 0, 0, 0, 0, 0], None),
        (vec![5, 2, 0, 4, 0], None),
        (vec![5, 2, 0, 3], None),
        (vec![5, 2, 0, 3, 0, 0, 0], None),
        (vec![5, 2, 0, 3, 2, b'a'], None),
        (vec![5, 2, 0, 3, 1, b'a', 0], None),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("socks5://{}", listener.local_addr()?);
        let server_reply = reply.clone();
        let server = std::thread::spawn(move || -> Result<()> {
            let mut stream = accept(listener)?;
            stream.set_read_timeout(Some(Duration::from_secs(/*secs*/ 2)))?;
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting)?;
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0])?;
            let mut request = [0; 10];
            stream.read_exact(&mut request)?;
            assert_eq!(request, [5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
            stream.write_all(&server_reply)?;
            Ok(())
        });
        let response = probe(json!({"op":"socks", "endpoint":endpoint, "address":"127.0.0.1:80"}))?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("SOCKS reply server panicked"))??;
        match expected {
            Some(code) => assert_eq!(response, json!({"socks":code})),
            None => assert!(
                response["socks"].is_null()
                    && response["error"]
                        .as_str()
                        .is_some_and(|error| error.contains("SOCKS")),
                "malformed reply {reply:?} was not rejected: {response}"
            ),
        }
    }
    Ok(())
}

#[test]
fn http_probe_requires_complete_headers_and_obeys_head() -> Result<()> {
    let ordinary = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
    let prefix = "HTTP/1.1 200 OK\r\nX-Padding: ";
    let padded = format!("{prefix}{}", "x".repeat(16380 - prefix.len()));
    let complete = format!("{padded}\r\n\r\n");
    let incomplete = format!("{padded}xxxx");
    for (method, headers, expected_body) in [
        ("HEAD", ordinary, Some("")),
        ("GET", ordinary, Some("body")),
        ("HEAD", complete.as_str(), Some("")),
        ("HEAD", incomplete.as_str(), None),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server_headers = headers.to_owned();
        let server = std::thread::spawn(move || -> Result<()> {
            let mut stream = accept(listener)?;
            assert!(
                read_headers(&mut stream)?
                    .starts_with(&format!("{method} http://example.test:80/ HTTP/1.1\r\n"))
            );
            stream.write_all(server_headers.as_bytes())?;
            stream.write_all(expected_body.unwrap_or("").as_bytes())?;
            Ok(())
        });
        let response = probe(
            json!({"op":"http", "endpoint":endpoint, "address":"example.test:80", "method":method}),
        )?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("HTTP probe server panicked"))??;
        match expected_body {
            Some(body) => assert_eq!(response, json!({"headers":headers, "body":body})),
            None => assert_eq!(
                response,
                json!({"error":"destination HTTP response: HTTP response headers exceed 16384 bytes"})
            ),
        }
    }
    Ok(())
}

#[test]
fn route_probe_distinguishes_allowed_and_denied_for_bare_and_url_endpoints() -> Result<()> {
    for (url, status, code) in [(false, 200, 91), (true, 200, 91), (false, 403, 0)] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let endpoint = if url {
            format!("http://{address}/")
        } else {
            address.to_string()
        };
        let server = std::thread::spawn(move || -> Result<()> {
            let mut stream = accept(listener)?;
            assert!(
                read_headers(&mut stream)?.starts_with("GET http://example.test:80/ HTTP/1.1\r\n")
            );
            write!(
                stream,
                "HTTP/1.1 {status} response\r\nContent-Length: 0\r\n\r\n"
            )?;
            Ok(())
        });
        let output = Command::new(cargo_bin("mcp-console-sandbox-fixture")?)
            .args(["probe-route", &endpoint, "example.test:80"])
            .output()?;
        let served = server
            .join()
            .map_err(|_| anyhow::anyhow!("route probe server panicked"))?;
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        served?;
    }
    Ok(())
}

#[test]
fn route_probe_does_not_count_invalid_inputs_as_denial() -> Result<()> {
    for (endpoint, destination) in [
        ("invalid", "example.test:80"),
        ("http://not-a-socket", "example.test:80"),
        ("http://127.0.0.1:bad", "example.test:80"),
        ("127.0.0.1:9", "invalid-destination"),
    ] {
        let output = Command::new(cargo_bin("mcp-console-sandbox-fixture")?)
            .args(["probe-route", endpoint, destination])
            .output()?;
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            !output.stderr.is_empty(),
            "missing invalid endpoint diagnostic"
        );
    }
    Ok(())
}

#[test]
fn route_probe_does_not_count_a_stopped_listener_as_denial() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    drop(listener);
    let output = Command::new(cargo_bin("mcp-console-sandbox-fixture")?)
        .args(["probe-route", &endpoint, "example.test:80"])
        .output()?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8(output.stderr)?.contains("connect route endpoint"));
    Ok(())
}

#[test]
fn route_probe_distinguishes_admission_close_from_broken_http() -> Result<()> {
    for (response, code) in [
        (Some(""), 0),
        (Some("HTTP/1.1 403"), 1),
        (Some("HTTP/1.1 403 Forbidden\r\n"), 1),
        (
            Some("HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nx"),
            1,
        ),
        (
            Some("HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\ndeny"),
            0,
        ),
        (Some("HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"), 1),
        (Some("invalid response\r\n\r\n"), 1),
        (None, 1),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?.to_string();
        let server = std::thread::spawn(move || -> Result<()> {
            let mut stream = accept(listener)?;
            read_headers(&mut stream)?;
            match response {
                Some(response) => stream.write_all(response.as_bytes())?,
                None => std::thread::sleep(Duration::from_secs(/*secs*/ 3)),
            }
            Ok(())
        });
        let output = Command::new(cargo_bin("mcp-console-sandbox-fixture")?)
            .args(["probe-route", &endpoint, "example.test:80"])
            .output()?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("route server panicked"))??;
        assert_eq!(output.status.code(), Some(code), "{response:?}: {output:?}");
    }
    Ok(())
}

#[test]
fn host_forgery_reaches_the_route_with_the_requested_sid() -> Result<()> {
    let directory = tempfile::tempdir_in(std::env::var_os("PUBLIC").context("PUBLIC")?)?;
    let nested = directory.path().join("a".repeat(120)).join("b".repeat(120));
    std::fs::create_dir_all(&nested).context("create long fixture directory")?;
    let fixture = nested.join("fixture.exe");
    std::fs::copy(cargo_bin("mcp-console-sandbox-fixture")?, &fixture)
        .context("stage long fixture")?;
    assert!(fixture.as_os_str().len() > 260);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<()> {
        let mut stream = accept(listener)?;
        read_headers(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        Ok(())
    });
    let result = probe_with_command(
        Command::new(fixture.canonicalize()?).arg("proxy-session"),
        json!({"op":"forge-route", "sid":"S-1-5-21-1-2-3-43180",
            "endpoint":endpoint, "address":"example.test:80"}),
    )?;
    let served = server
        .join()
        .map_err(|_| anyhow::anyhow!("forgery server panicked"))?;
    assert_eq!(result, json!({"code":91}));
    served?;
    Ok(())
}

#[test]
fn restricted_token_reports_unavailable_forged_identity_separately() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let policy = json!({"extends":":read-only", "network":"enabled",
        "windows_sandbox_level":"unelevated", "windows_state_dir":directory.path().join("state")});
    let mut command = Command::new(cargo_bin("mcp-console-sandbox")?);
    command
        .env("CONSOLE_POLICY", policy.to_string())
        .args(["--config-env", "CONSOLE_POLICY", "--"])
        .arg(cargo_bin("mcp-console-sandbox-fixture")?)
        .arg("proxy-session");
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<()> {
        let mut stream = accept(listener)?;
        read_headers(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        Ok(())
    });
    let control = probe_with_command(
        &mut command,
        json!({"op":"forge-route", "sid":"S-1-1-0", "endpoint":endpoint, "address":"example.test:80"}),
    )?;
    let served = server
        .join()
        .map_err(|_| anyhow::anyhow!("restricted route server panicked"))?;
    assert_eq!(control, json!({"code":91}));
    served?;
    let result = probe_with_command(
        &mut command,
        json!({"op":"forge-route", "sid":"S-1-5-21-1-2-3-43180",
            "endpoint":"127.0.0.1:9", "address":"example.test:80"}),
    )?;
    assert_eq!(
        result,
        json!({"identity_created":false, "reason":"restricting-sid-intersection"})
    );
    Ok(())
}
