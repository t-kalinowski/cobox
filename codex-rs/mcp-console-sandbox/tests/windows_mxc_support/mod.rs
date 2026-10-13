pub fn available() -> anyhow::Result<bool> {
    if !codex_sandboxing::windows_mxc_available() {
        eprintln!("public MXC unavailable: native runtime is unavailable");
        return Ok(false);
    }
    for account in ["McpConsoleSandboxOff", "McpConsoleSandboxOn"] {
        if codex_windows_sandbox::local_user_flags(account)?.is_some() {
            eprintln!("public MXC unavailable: legacy Console accounts exist");
            return Ok(false);
        }
    }
    Ok(true)
}
