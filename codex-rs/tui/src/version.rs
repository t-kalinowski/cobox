/// The current Codex CLI version as embedded at compile time.
#[cfg(not(test))]
pub const CODEX_CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

// Render tests use a fixed version so release bumps do not change their snapshots.
#[cfg(test)]
pub const CODEX_CLI_VERSION: &str = "0.0.0";
