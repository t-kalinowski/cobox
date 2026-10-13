//! Public Windows CLI. The shared sandbox crate owns launch and policy enforcement.

use clap::Parser;
use clap::Subcommand;
use clap::builder::PathBufValueParser;
use clap::builder::TypedValueParser;
use codex_utils_absolute_path::AbsolutePathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "mcp-console-sandbox",
    version,
    about = "Run commands in the MCP Console Windows sandbox",
    after_help = "Execute with --config-env NAME -- command [args...].\nState defaults to %LOCALAPPDATA%\\mcp-console.\nSetup requires adjacent mcp-console-sandbox-setup.exe and mcp-console-sandbox-runner.exe.",
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// Persistent sandbox state directory (absolute path).
    #[arg(long, global = true, value_name = "PATH", value_parser = absolute_path_parser())]
    pub state_dir: Option<AbsolutePathBuf>,

    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Action {
    /// Provision Windows accounts and network rules (requests UAC approval).
    Setup,
    /// Report setup records, accounts, and packaged helpers as JSON.
    Status,
}

fn absolute_path_parser() -> impl TypedValueParser<Value = AbsolutePathBuf> {
    PathBufValueParser::new().try_map(AbsolutePathBuf::from_absolute_path_checked)
}
