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
        .spawn()?;
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
fn head_probe_ignores_content_length_but_get_reads_the_body() -> Result<()> {
    for (method, expected_body) in [("HEAD", ""), ("GET", "body")] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server = std::thread::spawn(move || -> Result<()> {
            let mut stream = accept(listener)?;
            assert!(
                read_headers(&mut stream)?
                    .starts_with(&format!("{method} http://example.test:80/ HTTP/1.1\r\n"))
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")?;
            stream.write_all(expected_body.as_bytes())?;
            Ok(())
        });
        let response = probe(
            json!({"op":"http", "endpoint":endpoint, "address":"example.test:80", "method":method}),
        )?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("HTTP probe server panicked"))??;
        assert_eq!(
            response,
            json!({"headers":"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", "body":expected_body})
        );
    }
    Ok(())
}
