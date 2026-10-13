//! Interactive native probes. Requests arrive only after the sandbox has launched the fixture.
use anyhow::Context;
use anyhow::Result;
use serde_json::Value;
use serde_json::json;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::time::Duration;

pub(super) fn run() -> Result<()> {
    let mut receiver = None;
    let mut tcp_receiver = None;
    println!(
        "{}",
        json!({"pid": std::process::id(), "environment": std::env::vars().collect::<std::collections::BTreeMap<_,_>>() })
    );
    std::io::stdout().flush()?;
    for line in std::io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line?)?;
        let result = (|| -> Result<Value> {
            if request["op"] == "tcp-listen" {
                let listener = TcpListener::bind(request["address"].as_str().context("listen address")?)?;
                let address = listener.local_addr()?;
                let (send, receive) = std::sync::mpsc::channel();
                std::thread::spawn(move || { let _ = send.send(listener.accept().is_ok()); });
                tcp_receiver = Some(receive);
                return Ok(json!({"address":address.to_string()}));
            }
            if request["op"] == "tcp-receive" {
                return Ok(json!({"received":tcp_receiver.as_ref().context("TCP listener")?
                    .recv_timeout(Duration::from_millis(/*millis*/ 300)).unwrap_or(/*default*/ false)}));
            }
            if request["op"] == "udp-listen" {
                let socket = UdpSocket::bind(request["address"].as_str().context("listen address")?)?;
                socket.set_read_timeout(Some(Duration::from_millis(/*millis*/ 300)))?;
                let address = socket.local_addr()?;
                receiver = Some(socket);
                return Ok(json!({"address":address.to_string()}));
            }
            if request["op"] == "udp-receive" {
                let mut bytes = [0;5];
                return Ok(json!({"received":receiver.as_ref().context("UDP listener")?.recv_from(&mut bytes).is_ok() && &bytes == b"probe"}));
            }
            probe(&request)
        })().unwrap_or_else(|error| json!({"error":format!("{error:#}")}));
        println!("{result}");
        std::io::stdout().flush()?;
    }
    Ok(())
}

fn headers(stream: &mut TcpStream) -> Result<String> {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") && result.len() < 16384 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        result.push(byte[0]);
    }
    Ok(String::from_utf8(result)?)
}

fn probe(request: &Value) -> Result<Value> {
    let operation = request["op"].as_str().context("probe operation")?;
    if operation == "file-access" {
        let path = request["path"].as_str().context("probe path")?;
        return Ok(json!({"readable": std::fs::File::open(path).is_ok(),
            "writable": std::fs::OpenOptions::new().write(true).open(path).is_ok()}));
    }
    if operation == "exit" {
        std::process::exit(request["code"].as_i64().context("exit code")? as i32);
    }
    if operation == "parent-pid" {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::io::FromRawHandle;
        use std::os::windows::io::OwnedHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, /*th32processid*/ 0)
        };
        anyhow::ensure!(snapshot != INVALID_HANDLE_VALUE, "process snapshot");
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
        while found && entry.th32ProcessID != std::process::id() {
            found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
        }
        anyhow::ensure!(found, "find fixture process");
        return Ok(json!(entry.th32ParentProcessID));
    }
    if operation == "descendant" {
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .arg("hold")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let mut pid = String::new();
        std::io::BufReader::new(child.stdout.take().context("descendant stdout")?)
            .read_line(&mut pid)?;
        return Ok(json!({"pid":pid.trim().parse::<u32>()?}));
    }
    let address = request["address"].as_str().context("probe address")?;
    if operation == "https" {
        let output = std::process::Command::new("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--noproxy",
                "",
                "--proxy",
            ])
            .arg(std::env::var("HTTP_PROXY")?)
            .arg("--cacert")
            .arg(request["certificate"].as_str().context("certificate")?)
            .arg(format!("https://{address}/"))
            .output()?;
        return Ok(
            json!({"code":output.status.code(), "body":String::from_utf8(output.stdout)?, "error":String::from_utf8(output.stderr)?}),
        );
    }
    let timeout = Duration::from_secs(/*secs*/ 2);
    if operation == "tcp" {
        return Ok(
            json!({"connected": TcpStream::connect_timeout(&address.parse()?, timeout).is_ok()}),
        );
    }
    if operation == "bind" {
        return Ok(json!({"bound": TcpListener::bind(address).is_ok()}));
    }
    if operation == "udp" || operation == "udp-echo" {
        let address: SocketAddr = address.parse()?;
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        let sent = socket.send_to(b"probe", address).is_ok();
        if operation == "udp" {
            return Ok(json!({"sent":sent}));
        }
        socket.set_read_timeout(Some(timeout))?;
        let mut reply = [0; 5];
        return Ok(
            json!({"received": sent && socket.recv_from(&mut reply).is_ok() && &reply == b"probe"}),
        );
    }
    let environment = if operation == "socks" {
        "ALL_PROXY"
    } else {
        "HTTP_PROXY"
    };
    let endpoint = match request["endpoint"].as_str() {
        Some(endpoint) => endpoint.to_owned(),
        None => std::env::var(environment)?,
    };
    let endpoint = endpoint
        .split_once("://")
        .context("proxy URL")?
        .1
        .trim_end_matches('/');
    let mut stream = TcpStream::connect_timeout(&endpoint.parse()?, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    if operation == "socks" {
        stream.write_all(&[5, 1, 0])?;
        let mut reply = [0; 2];
        stream
            .read_exact(&mut reply)
            .context("SOCKS authentication response")?;
        anyhow::ensure!(reply == [5, 0], "SOCKS authentication rejected");
        let (host, port) = address.rsplit_once(':').context("SOCKS destination")?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let mut message = vec![5, 1, 0];
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                message.push(1);
                message.extend(ip.octets());
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                message.push(4);
                message.extend(ip.octets());
            }
            Err(_) => {
                message.extend([3, u8::try_from(host.len())?]);
                message.extend(host.as_bytes());
            }
        }
        message.extend(port.parse::<u16>()?.to_be_bytes());
        stream.write_all(&message)?;
        let mut response = [0; 4];
        stream
            .read_exact(&mut response)
            .context("SOCKS connect response")?;
        if response[1] != 0 {
            return Ok(json!({"socks": response[1]}));
        }
        let length = match response[3] {
            1 => 6,
            4 => 18,
            3 => {
                let mut size = [0];
                stream.read_exact(&mut size)?;
                usize::from(size[0]) + 2
            }
            _ => anyhow::bail!("invalid SOCKS bound address: {response:?}"),
        };
        let mut rest = vec![0; length];
        stream
            .read_exact(&mut rest)
            .context("SOCKS bound address")?;
    } else if operation == "connect" {
        write!(
            stream,
            "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n"
        )?;
        let response = headers(&mut stream)?;
        if !response.starts_with("HTTP/1.1 200") {
            return Ok(json!({"headers":response}));
        }
    }
    let method = request["method"].as_str().unwrap_or("GET");
    let target = if operation == "http" {
        format!("http://{address}/")
    } else {
        "/".to_owned()
    };
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {address}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    let response = headers(&mut stream).context("destination HTTP response")?;
    if method == "HEAD" {
        return Ok(json!({"headers":response, "body":""}));
    }
    let mut body = vec![
        0;
        response
            .lines()
            .find_map(|line| line
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|value| value.trim().parse::<usize>().ok()))
            .unwrap_or(0)
            .min(16384)
    ];
    stream.read_exact(&mut body)?;
    Ok(json!({"headers":response, "body":String::from_utf8_lossy(&body)}))
}
