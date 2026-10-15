pub fn available() -> anyhow::Result<bool> {
    if !codex_sandboxing::windows_mxc_available() {
        eprintln!("public MXC unavailable: native runtime is unavailable");
        return Ok(false);
    }
    Ok(true)
}
