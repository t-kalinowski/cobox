#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

// Compile the upstream implementation in place so its child modules keep their paths.
#[cfg(windows)]
#[path = "../../windows-sandbox-rs/src/bin/command_runner"]
mod upstream {
    pub mod win;
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    codex_windows_sandbox::WindowsSandboxProduct::Console.initialize()?;
    upstream::win::main()
}

#[cfg(not(windows))]
fn main() {
    panic!("mcp-console-sandbox-runner is Windows-only");
}
