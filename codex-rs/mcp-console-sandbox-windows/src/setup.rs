#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    codex_windows_sandbox::WindowsSandboxProduct::Console.initialize()?;
    codex_windows_sandbox::setup_helper_main()
}

#[cfg(not(windows))]
fn main() {
    panic!("mcp-console-sandbox-setup is Windows-only");
}
