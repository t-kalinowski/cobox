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
    if !matches!(
        codex_windows_sandbox::ConsoleProxySlot::is_registered(),
        Ok(false)
    ) {
        eprintln!(
            "public MXC unavailable: Console proxy pool registration exists or is unreadable"
        );
        return Ok(false);
    }
    for index in 0..codex_windows_sandbox::ConsoleProxySlot::COUNT {
        for account in [
            format!("McpConsoleProxyOff{index}"),
            format!("McpConsoleProxyOn{index}"),
        ] {
            if codex_windows_sandbox::local_user_flags(&account)?.is_some() {
                eprintln!("public MXC unavailable: Console proxy accounts exist");
                return Ok(false);
            }
        }
    }
    Ok(true)
}
