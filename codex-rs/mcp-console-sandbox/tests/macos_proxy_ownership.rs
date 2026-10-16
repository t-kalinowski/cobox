#![cfg(target_os = "macos")]

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_network_proxy::ManagedNetworkSandboxContext;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_sandboxing::seatbelt::CreateSeatbeltCommandArgsParams;
use codex_sandboxing::seatbelt::create_seatbelt_command_args;
use codex_utils_cargo_bin::cargo_bin;
use serde::Serialize;
use serde_json::json;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Child;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;

const FORK_RULE: &str = "\n(deny process-info-pidinfo (require-not (target same-sandbox)))\n";

struct GatedClient {
    child: Child,
    output: BufReader<ChildStdout>,
}

#[derive(Debug, Serialize)]
struct Outcome {
    code: i32,
    response: String,
    stderr: String,
}

impl Outcome {
    fn matches(&self, expected: &str) -> bool {
        self.code == 0 && self.response.starts_with(expected)
    }
}

impl GatedClient {
    fn start(command: &mut Command) -> Result<(Self, String)> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut output = BufReader::new(child.stdout.take().context("client stdout")?);
        let mut ready = String::new();
        if output.read_line(&mut ready)? == 0 {
            let output = child.wait_with_output()?;
            anyhow::bail!("client failed before readiness: {output:?}");
        }
        ensure!(ready.starts_with("READY "), "unexpected readiness: {ready}");
        Ok((Self { child, output }, ready))
    }

    fn connect(&mut self) -> Result<(i32, String)> {
        self.child
            .stdin
            .as_mut()
            .context("client stdin")?
            .write_all(b"connect\n")?;
        let mut response = String::new();
        loop {
            let mut line = String::new();
            ensure!(
                self.output.read_line(&mut line)? != 0,
                "client closed before result"
            );
            if let Some(code) = line.strip_prefix("RESULT ") {
                return Ok((code.trim().parse()?, response));
            }
            response.push_str(&line);
        }
    }

    fn finish(mut self, result: (i32, String)) -> Result<Outcome> {
        self.child
            .stdin
            .take()
            .context("client stdin")?
            .write_all(b"retire\n")?;
        let status = self.child.wait()?;
        ensure!(
            status.code() == Some(result.0),
            "client result changed: {status}"
        );
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .context("client stderr")?
            .read_to_string(&mut stderr)?;
        Ok(Outcome {
            code: result.0,
            response: result.1,
            stderr,
        })
    }
}

impl Drop for GatedClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(listener: TcpListener, cancel: UnixStream) -> Result<()> {
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        ensure!(
            unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } > 0,
            "origin poll"
        );
        if descriptors[1].revents != 0 {
            return Ok(());
        }
        let (mut stream, _) = listener.accept()?;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed",
        )?;
    }
}

#[test]
fn compare_native_and_upstream_proxy_policy_application() -> Result<()> {
    let trials: usize = std::env::var("SANDBOX_PROXY_TRIALS")?.parse()?;
    let api_trials: usize = std::env::var("SANDBOX_API_TRIALS")?.parse()?;
    ensure!(
        trials > 0 && api_trials > 0,
        "diagnostic trials must be positive"
    );
    let api_launcher = std::env::var("SANDBOX_POLICY_LAUNCHER")?;
    let log = std::env::var("SANDBOX_DIAGNOSTIC_DIR")?;
    let log = Path::new(&log);
    std::fs::create_dir_all(log)?;
    let root = tempfile::tempdir()?;
    let cwd = root.path().canonicalize()?;
    let fixture = cargo_bin("mcp-console-sandbox-fixture")?
        .to_string_lossy()
        .into_owned();
    let filesystem = FileSystemSandboxPolicy::unrestricted();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}/", listener.local_addr()?);
    let (mut cancel, cancellation) = UnixStream::pair()?;
    let origin = std::thread::spawn(move || serve(listener, cancellation));
    let result = (|| -> Result<()> {
        let mut failed = Vec::new();
        for trial in 0..trials {
            for kind in ["unrestricted", "external-sandbox"] {
                for network in ["restricted", "enabled"] {
                    for phase in ["allow", "deny"] {
                        let tag = format!("{trial}-{kind}-{network}-{phase}");
                        let target =
                            vec![fixture.clone(), "proxy-get-gated".to_owned(), url.clone()];
                        let config = json!({
                            "filesystem": {"kind": kind}, "network": network,
                            "inherit_environment": false,
                            "proxy": {
                                "enabled": true, "enableSocks5": true, "enableSocks5Udp": false,
                                "allowUpstreamProxy": false, "dangerouslyAllowAllUnixSockets": false,
                                "mode": "full", "domains": {"127.0.0.1": phase},
                                "unixSockets": null, "allowLocalBinding": false
                            }
                        });
                        let (mut native, ready) = GatedClient::start(
                            Command::new(cargo_bin("mcp-console-sandbox")?)
                                .current_dir(&cwd)
                                .env("CONSOLE_POLICY", config.to_string())
                                .args(["--config-env", "CONSOLE_POLICY", "--"])
                                .args(&target),
                        )?;
                        let endpoints: Vec<_> = ready.split_whitespace().skip(1).collect();
                        ensure!(endpoints.len() == 2, "proxy endpoints: {ready}");
                        std::fs::write(
                            log.join(format!("{tag}-request.json")),
                            serde_json::to_vec_pretty(&json!({
                                "command": target, "configuration": config,
                                "cwd": cwd, "endpoints": endpoints,
                            }))?,
                        )?;
                        let mut ports = endpoints
                            .iter()
                            .map(|endpoint| -> Result<u16> {
                                let (_, address) =
                                    endpoint.split_once("://").context("proxy scheme")?;
                                Ok(address.parse::<SocketAddr>()?.port())
                            })
                            .collect::<Result<Vec<_>>>()?;
                        ports.sort_unstable();
                        ports.dedup();
                        let context = ManagedNetworkSandboxContext {
                            loopback_ports: ports,
                            ..Default::default()
                        };
                        let args = create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
                            command: target,
                            file_system_sandbox_policy: &filesystem,
                            network_sandbox_policy: if network == "enabled" {
                                NetworkSandboxPolicy::Enabled
                            } else {
                                NetworkSandboxPolicy::Restricted
                            },
                            sandbox_policy_cwd: &cwd,
                            enforce_managed_network: true,
                            managed_network: Some(&context),
                            environment_id: None,
                            network: None,
                            extra_allow_unix_sockets: &[],
                        })
                        .map_err(anyhow::Error::msg)?;
                        std::fs::write(log.join(format!("{tag}.sbpl")), &args[1])?;
                        ensure!(
                            args[0] == "-p" && args[2] == "--" && args[3] == fixture,
                            "diagnostic profiles must have no parameters"
                        );
                        let native_profile = log.join(format!("{tag}-native.sbpl"));
                        std::fs::write(&native_profile, format!("{}{FORK_RULE}", args[1]))?;
                        let upstream_command = |args: &[String]| {
                            let mut command = Command::new("/usr/bin/sandbox-exec");
                            command
                                .args(args)
                                .current_dir(&cwd)
                                .env_clear()
                                .env("HTTP_PROXY", endpoints[0])
                                .env("ALL_PROXY", endpoints[1]);
                            command
                        };
                        let (mut upstream, _) = GatedClient::start(&mut upstream_command(&args))?;
                        let (native_result, upstream_result) = if trial % 2 == 0 {
                            let upstream = upstream.connect()?;
                            (native.connect()?, upstream)
                        } else {
                            let native = native.connect()?;
                            (native, upstream.connect()?)
                        };
                        let expected = if phase == "allow" {
                            "HTTP/1.1 200"
                        } else {
                            "HTTP/1.1 403"
                        };
                        let mut api_init = Vec::new();
                        let mut api_compiled = Vec::new();
                        for api_trial in 0..api_trials {
                            // Both modes read the same profile and exec the same
                            // target from the same launcher. Alternate their order.
                            let modes = if api_trial % 2 == 0 {
                                ["init", "compiled"]
                            } else {
                                ["compiled", "init"]
                            };
                            for mode in modes {
                                let mut command = Command::new(&api_launcher);
                                command
                                    .arg(mode)
                                    .arg(&native_profile)
                                    .args(&args[3..])
                                    .current_dir(&cwd)
                                    .env_clear()
                                    .env("HTTP_PROXY", endpoints[0])
                                    .env("ALL_PROXY", endpoints[1]);
                                let (mut client, _) = GatedClient::start(&mut command)?;
                                let result = client.connect()?;
                                let outcome = client.finish(result)?;
                                if mode == "init" {
                                    api_init.push(outcome);
                                } else {
                                    api_compiled.push(outcome);
                                }
                            }
                        }
                        let native_matches =
                            native_result.0 == 0 && native_result.1.starts_with(expected);
                        let upstream_matches =
                            upstream_result.0 == 0 && upstream_result.1.starts_with(expected);
                        let differs = native_matches != upstream_matches;
                        let matching_rule = if differs {
                            let mut matching_args = args.clone();
                            matching_args[1].push_str(FORK_RULE);
                            let (mut client, _) =
                                GatedClient::start(&mut upstream_command(&matching_args))?;
                            let result = client.connect()?;
                            Some(client.finish(result)?)
                        } else {
                            None
                        };
                        let upstream = upstream.finish(upstream_result)?;
                        let native = native.finish(native_result)?;
                        let success = native.matches(expected)
                            && upstream.matches(expected)
                            && api_init.iter().all(|outcome| outcome.matches(expected))
                            && api_compiled.iter().all(|outcome| outcome.matches(expected));
                        let outcome = json!({"trial": trial, "filesystem": kind, "network": network, "phase": phase, "expected": expected, "origin": url, "endpoints": endpoints, "native": native, "upstream": upstream, "upstream_with_fork_rule": matching_rule, "api_profile": native_profile, "api_init": api_init, "api_compiled": api_compiled});
                        println!("{outcome}");
                        std::fs::write(
                            log.join(format!("{tag}.json")),
                            serde_json::to_vec_pretty(&outcome)?,
                        )?;
                        if !success {
                            failed.push(tag);
                        }
                    }
                }
            }
        }
        ensure!(
            failed.is_empty(),
            "proxy policy application failed: {failed:?}"
        );
        Ok(())
    })();
    cancel.write_all(b"stop")?;
    origin.join().expect("origin thread")?;
    result
}
