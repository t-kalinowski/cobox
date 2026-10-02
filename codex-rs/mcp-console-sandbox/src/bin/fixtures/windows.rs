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
        "copy-stdin" => {
            std::io::copy(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())?;
        }
        "probe-write" => {
            let path = args.next().context("probe path")?;
            let error = std::fs::write(path, b"escaped").expect_err("write must be denied");
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
