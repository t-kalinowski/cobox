use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;

pub fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let read = args.next().context("denied read path")?;
    let write = args.next().context("denied write path")?;
    let allowed = args.next().context("allowed write path")?;
    println!("started");
    ensure!(
        std::fs::read(&read).is_err(),
        "mandatory read deny was reopened"
    );
    ensure!(
        std::fs::write(&write, "escape").is_err(),
        "mandatory write deny was reopened"
    );
    std::fs::write(&allowed, "allowed")?;
    println!("clamped");
    Ok(())
}
