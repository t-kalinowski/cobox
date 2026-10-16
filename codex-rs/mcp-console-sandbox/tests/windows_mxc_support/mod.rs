pub fn available() -> anyhow::Result<bool> {
    if !codex_sandboxing::windows_mxc_available() {
        eprintln!("SKIP native MXC contract: native runtime is unavailable on this host");
        return Ok(false);
    }
    Ok(true)
}
