//! Apply the workload environment only after native MXC setup and enforcement.

use anyhow::Context;
use anyhow::Result;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::environment_transport;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::Path;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

pub(crate) const ARG1: &str = "--__mcp-console-target";
const PREFIX: &str = "MCP_CONSOLE_SANDBOX_TARGET_";

#[derive(Deserialize, Serialize)]
struct Target {
    command: Vec<String>,
    environment: HashMap<String, String>,
}

fn is_key(name: &str) -> bool {
    name.get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
}

pub(crate) fn encode(
    command: Vec<String>,
    mut environment: HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    environment.retain(|name, _| !is_key(name) && !environment_transport::is_key(name.as_ref()));
    let mut encoded = HashMap::new();
    environment_transport::encode(
        &serde_json::to_string(&Target {
            command,
            environment,
        })?,
        &mut encoded,
    )?;
    // Namespace the existing bounded transport so the native launcher can use
    // its own transport independently. No executor variables enter this map.
    Ok(encoded
        .into_iter()
        .map(|(name, value)| (format!("{PREFIX}{name}"), value))
        .collect())
}

pub(crate) fn helper_environment() -> Result<HashMap<String, String>> {
    let mut environment = std::env::vars_os()
        .map(|(name, value)| {
            Ok((
                name.into_string()
                    .map_err(|_| anyhow::anyhow!("MXC requires Unicode environment names"))?,
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("MXC requires Unicode environment values"))?,
            ))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    environment.retain(|name, _| {
        !name.starts_with('=') && !is_key(name) && !environment_transport::is_key(name.as_ref())
    });
    Ok(environment)
}

fn transport_environment() -> Result<HashMap<String, String>> {
    std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            if !is_key(&name) {
                return None;
            }
            Some(
                value
                    .into_string()
                    .map(|value| (name, value))
                    .map_err(|_| anyhow::anyhow!("invalid Windows target transport")),
            )
        })
        .collect()
}

pub(crate) fn child_environment() -> Result<Option<HashMap<String, String>>> {
    let mut environment = transport_environment()?;
    if environment.is_empty() {
        return Ok(None);
    }
    // The native API requires this entry, then supplies its package defaults.
    // Only the inert entry and bounded target request reach the relay.
    environment.insert("LOCALAPPDATA".to_owned(), String::new());
    Ok(Some(environment))
}

pub(crate) fn run() -> Result<i32> {
    let encoded = transport_environment()?
        .into_iter()
        .map(|(name, value)| (name[PREFIX.len()..].to_owned(), value));
    // Neither decoding nor serde diagnostics may echo workload data.
    let target: Target = environment_transport::decode(encoded)
        .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
        .map_err(|_| anyhow::anyhow!("invalid Windows target request"))?;
    let (program, args) = target.command.split_first().context("missing command")?;
    // This ordinary descendant inherits MXC enforcement and both retained Jobs.
    // The existing native owner still retires the tree before storage cleanup.
    let status = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(target.environment)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("launching the Windows target")?;
    Ok(status.code().unwrap_or(/*default*/ 1))
}

pub(crate) fn materialize_tmpdir(
    filesystem: &mut FileSystemSandboxPolicy,
    environment: &HashMap<String, String>,
) -> Result<()> {
    // Native policy conversion otherwise resolves :tmpdir from the relay's
    // environment. Preserve its target TEMP/TMP semantics before wrapping it.
    let paths = environment
        .iter()
        .filter(|(name, value)| {
            (name.eq_ignore_ascii_case("TEMP") || name.eq_ignore_ascii_case("TMP"))
                && Path::new(value).is_absolute()
        })
        .map(|(_, value)| AbsolutePathBuf::from_absolute_path(value))
        .collect::<std::io::Result<Vec<_>>>()?;
    filesystem.entries = std::mem::take(&mut filesystem.entries)
        .into_iter()
        .flat_map(|entry| {
            if matches!(
                &entry.path,
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Tmpdir
                }
            ) {
                paths
                    .iter()
                    .map(|path| {
                        let mut entry = entry.clone();
                        entry.path = path.clone().into();
                        entry
                    })
                    .collect()
            } else {
                vec![entry]
            }
        })
        .collect();
    Ok(())
}
