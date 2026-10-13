//! Preserve Console control-state denial when using the host-identity MXC backend.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_windows_sandbox::ConsoleProxySlot;
use std::path::Path;
use std::path::PathBuf;

/// Resolve existing junctions even when the final policy path has not been created yet.
pub(crate) fn canonical_policy_path(
    path: &Path,
) -> Result<codex_utils_absolute_path::AbsolutePathBuf> {
    let mut ancestor = path;
    let mut suffix = PathBuf::new();
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(root) => {
                return Ok(
                    codex_utils_absolute_path::AbsolutePathBuf::from_absolute_path(
                        root.join(suffix),
                    )?,
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix = PathBuf::from(
                    ancestor
                        .file_name()
                        .context("policy path has no existing ancestor")?,
                )
                .join(suffix);
                ancestor = ancestor.parent().context("policy path has no parent")?;
            }
            Err(error) => return Err(error).context("resolve Windows policy path"),
        }
    }
}

/// MXC runs as the host user, outside the legacy accounts' secrets-deny group.
/// Protect requested/default state and the registered pool even with broad workload grants.
pub(crate) fn protect_state(
    filesystem: &mut codex_protocol::permissions::FileSystemSandboxPolicy,
    state: &Path,
) -> Result<codex_protocol::permissions::FileSystemSandboxPolicy> {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::permissions::FileSystemSandboxKind;
    use codex_protocol::permissions::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let default_state =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
            .join("mcp-console");
    let mut roots = vec![state.to_path_buf(), default_state];
    roots.extend(ConsoleProxySlot::registered_state_directory()?);
    let mut denied = FileSystemSandboxPolicy::restricted(Vec::new());
    for root in roots {
        ensure!(
            root.parent().is_some(),
            "MXC cannot protect a drive-root Console state directory; use elevated mode or a dedicated state directory"
        );
        let canonical = canonical_policy_path(&root)?;
        ensure!(
            canonical.parent().is_some(),
            "MXC cannot protect a drive-root Console state directory"
        );
        denied.entries.push(FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(root)?.into(),
            FileSystemAccessMode::Deny,
        ));
        denied.entries.push(FileSystemSandboxEntry::new(
            canonical.into(),
            FileSystemAccessMode::Deny,
        ));
    }
    // Even externally managed or otherwise unrestricted files must exclude control state.
    if filesystem.kind == FileSystemSandboxKind::ExternalSandbox {
        *filesystem = FileSystemSandboxPolicy::unrestricted();
    }
    filesystem.preserve_deny_read_restrictions_from(&denied);
    Ok(denied)
}
