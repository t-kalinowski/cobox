#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    codex_windows_sandbox::ConsoleProxySlot::initialize_helper()?;
    codex_windows_sandbox::setup_helper_main()
}

#[cfg(not(windows))]
fn main() {
    panic!("mcp-console-sandbox-setup is Windows-only");
}
