use anyhow::Context;
use anyhow::Result;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

pub(super) fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let operation = args.next().context("fixture operation")?;
    match operation.to_str().context("UTF-8 fixture operation")? {
        "arguments" => {
            println!(
                "{}",
                serde_json::to_string(&std::env::args().skip(2).collect::<Vec<_>>())?
            );
        }
        "copy-stdin" => {
            std::io::copy(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())?;
        }
        "desktop" => {
            // Query the target's actual desktop without launching a shell.
            #[link(name = "user32")]
            unsafe extern "system" {
                fn GetThreadDesktop(thread_id: u32) -> *mut std::ffi::c_void;
                fn GetUserObjectInformationW(
                    object: *mut std::ffi::c_void,
                    index: i32,
                    info: *mut std::ffi::c_void,
                    length: u32,
                    needed: *mut u32,
                ) -> i32;
            }
            let mut name = [0_u16; 256];
            let mut needed = 0;
            let success = unsafe {
                GetUserObjectInformationW(
                    GetThreadDesktop(windows_sys::Win32::System::Threading::GetCurrentThreadId()),
                    /*index*/ 2,
                    name.as_mut_ptr().cast(),
                    std::mem::size_of_val(&name) as u32,
                    &mut needed,
                )
            };
            anyhow::ensure!(success != 0, "{}", std::io::Error::last_os_error());
            println!("{}", String::from_utf16(&name[..needed as usize / 2 - 1])?);
        }
        "connect" => {
            let address = args.next().context("socket address")?;
            let address = address.to_str().context("UTF-8 socket address")?.parse()?;
            let connected = std::net::TcpStream::connect_timeout(
                &address,
                std::time::Duration::from_secs(/*secs*/ 2),
            )
            .is_ok();
            println!("{}", if connected { "connected" } else { "blocked" });
        }
        "datagram" => {
            let address = args.next().context("socket address")?;
            let address: std::net::SocketAddr =
                address.to_str().context("UTF-8 socket address")?.parse()?;
            let local = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = std::net::UdpSocket::bind(local)?;
            let sent = socket
                .connect(address)
                .and_then(|()| socket.send(b"probe"))
                .is_ok();
            println!("{}", if sent { "sent" } else { "blocked" });
        }
        "probe-write" => {
            let path = args.next().context("probe path")?;
            let error = std::fs::write(path, b"escaped")
                .err()
                .context("write must be denied")?;
            anyhow::ensure!(
                error.kind() == std::io::ErrorKind::PermissionDenied,
                "{error}"
            );
            println!("write denied");
        }
        "hold" => {
            let _file = std::fs::File::create(
                std::path::PathBuf::from(std::env::var_os("TMPDIR").context("TMPDIR")?)
                    .join("held-by-descendant"),
            )?;
            println!("{}", std::process::id());
            std::io::stdout().flush()?;
            loop {
                std::thread::park();
            }
        }
        "tree" | "tree-hold" => {
            let mut descendant = Command::new(std::env::current_exe()?)
                .arg("hold")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()?;
            let mut pid = String::new();
            std::io::BufReader::new(descendant.stdout.take().context("descendant stdout")?)
                .read_line(&mut pid)?;
            println!(
                "{}",
                serde_json::json!({
                    "root": std::process::id(),
                    "descendant": pid.trim().parse::<u32>()?,
                    "temporary": std::env::var("TMPDIR")?,
                })
            );
            std::io::stdout().flush()?;
            if operation == "tree" {
                std::io::stdin().read_exact(&mut [0])?;
                std::process::exit(42);
            }
            loop {
                std::thread::park();
            }
        }
        "owner" => {
            let mut runner = Command::new(args.next().context("runner executable")?)
                .args(["--config-env", "CONSOLE_POLICY", "--"])
                .arg(std::env::current_exe()?)
                .arg("tree-hold")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()?;
            let mut ready = String::new();
            std::io::BufReader::new(runner.stdout.take().context("runner stdout")?)
                .read_line(&mut ready)?;
            let mut ready: serde_json::Value = serde_json::from_str(&ready)?;
            ready["runner"] = runner.id().into();
            println!("{ready}");
            std::io::stdout().flush()?;
            std::io::stdin().read_exact(&mut [0])?;
        }
        _ => anyhow::bail!("unknown Windows fixture operation: {operation:?}"),
    }
    Ok(())
}
