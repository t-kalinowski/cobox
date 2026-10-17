pub fn available() -> anyhow::Result<bool> {
    if !codex_sandboxing::windows_mxc_available() {
        anyhow::ensure!(
            std::env::var_os("MCP_CONSOLE_SANDBOX_REQUIRE_MXC").is_none_or(|mode| mode != "1"),
            "required native MXC validation is unavailable on this host"
        );
        eprintln!("SKIP native MXC contract: native runtime is unavailable on this host");
        return Ok(false);
    }
    Ok(true)
}
