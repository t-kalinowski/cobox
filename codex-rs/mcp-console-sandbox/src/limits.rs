//! Immutable launch ceilings. Apply after profiles and runner-owned grants.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_network_proxy::NetworkProxyConfig;
use codex_network_proxy::NetworkProxyLimits;
use codex_network_proxy::RemoteNetworkProxyConfig;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxKind;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSandboxPolicyContext;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_path_uri::PathUri;
use serde::Deserialize;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    filesystem: FileSystemLimits,
    network: NetworkLimits,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileSystemLimits {
    deny: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkLimits {
    domains: DomainLimits,
    allow_local_binding: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DomainLimits {
    allow: Option<Vec<String>>,
    deny: Vec<String>,
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        for path in &self.filesystem.deny {
            literal_absolute_path(path)?;
        }
        self.network_proxy_limits().validate()
    }

    pub fn is_active(&self) -> bool {
        !self.filesystem.deny.is_empty()
            || self.has_domain_limits()
            || self.network.allow_local_binding == Some(false)
    }

    fn has_domain_limits(&self) -> bool {
        self.network.domains.allow.is_some() || !self.network.domains.deny.is_empty()
    }

    #[cfg(target_os = "linux")]
    pub fn denies_local_binding(&self) -> bool {
        self.network.allow_local_binding == Some(false)
    }

    pub fn network_proxy_limits(&self) -> NetworkProxyLimits {
        NetworkProxyLimits {
            allowed_domains: self.network.domains.allow.clone(),
            denied_domains: self.network.domains.deny.clone(),
            allow_local_binding: self.network.allow_local_binding,
        }
    }

    /// Keep the ordinary policy's default denial. Only full networking needs a
    /// new allow-all proxy when an immutable ceiling is supplied.
    pub fn prepare_network(
        &self,
        filesystem: &FileSystemSandboxPolicy,
        network: NetworkSandboxPolicy,
        proxy: &mut Option<RemoteNetworkProxyConfig>,
        extension: Option<&str>,
    ) -> Result<()> {
        ensure!(
            !self.is_active() || filesystem.kind != FileSystemSandboxKind::ExternalSandbox,
            "limits cannot be enforced with external-sandbox filesystem policy"
        );
        let network_limited =
            self.has_domain_limits() || self.network.allow_local_binding == Some(false);
        if !network_limited {
            return Ok(());
        }
        ensure!(
            !cfg!(windows) || self.network.allow_local_binding != Some(false),
            "limits.allow_local_binding=false is unsupported by the Windows MXC backend: bind prohibition is not verified"
        );
        ensure!(
            extension.is_none_or(|extension| extension.trim().is_empty()),
            "network limits cannot be combined with a macOS Seatbelt extension"
        );
        // Linux can deny binding directly after helper setup. A binding-only
        // ceiling therefore does not need to route ordinary outbound traffic.
        if proxy.is_none()
            && network.is_enabled()
            && (self.has_domain_limits() || !cfg!(target_os = "linux"))
        {
            let mut config = NetworkProxyConfig {
                enabled: true,
                enable_socks5_udp: false,
                allow_upstream_proxy: false,
                ..NetworkProxyConfig::default()
            };
            config.set_allowed_domains(vec!["*".to_owned()]);
            // An unrestricted network includes local binding unless capped.
            config.allow_local_binding = Some(self.network.allow_local_binding != Some(false));
            *proxy = Some(RemoteNetworkProxyConfig::from_effective_config(&config)?);
        }
        if let Some(proxy) = proxy {
            // `true` is a ceiling, not a grant.
            proxy.allow_local_binding &= self.network.allow_local_binding != Some(false);
            if self.has_domain_limits() {
                // Upstream proxy endpoints are otherwise exempt from target
                // destination checks. A mandatory cap cannot exempt that hop.
                proxy.allow_upstream_proxy = false;
                ensure!(
                    !proxy.dangerously_allow_all_unix_sockets
                        && proxy
                            .unix_sockets
                            .as_ref()
                            .is_none_or(|sockets| sockets.entries.is_empty()),
                    "domain limits cannot be enforced with host Unix-socket proxy access"
                );
                ensure!(
                    !cfg!(windows),
                    "domain limits are unsupported by the Windows MXC backend: host-loopback access is bidirectional"
                );
                ensure!(
                    !cfg!(target_os = "macos") || !proxy.allow_local_binding,
                    "domain limits require allow_local_binding=false on macOS"
                );
            }
        }
        Ok(())
    }

    /// Clamp concrete and symbolic grants, retaining broad grants with denied
    /// holes. The returned spellings also supply final macOS deny rules.
    pub fn apply_filesystem(
        &self,
        filesystem: &mut FileSystemSandboxPolicy,
        cwd: &AbsolutePathBuf,
        workspace: &AbsolutePathBuf,
        private_storage: Option<&Path>,
    ) -> Result<Vec<AbsolutePathBuf>> {
        if self.filesystem.deny.is_empty() {
            return Ok(Vec::new());
        }
        ensure!(
            filesystem.kind != FileSystemSandboxKind::ExternalSandbox,
            "filesystem limits cannot be enforced with external-sandbox policy"
        );
        ensure!(
            !filesystem
                .entries
                .iter()
                .any(|entry| entry.access.can_read()
                    && matches!(
                        &entry.path,
                        FileSystemPath::Special {
                            value: FileSystemSpecialPath::Minimal
                        }
                    )),
            "filesystem limits cannot be combined with the minimal platform-default grant"
        );
        let mut denied = Vec::new();
        for value in &self.filesystem.deny {
            for path in path_aliases(&literal_absolute_path(value)?)? {
                if !denied.contains(&path) {
                    denied.push(path);
                }
            }
        }
        if let Some(storage) = private_storage {
            let storage = AbsolutePathBuf::from_absolute_path_checked(storage)?;
            ensure!(
                !path_aliases(&storage)?
                    .iter()
                    .any(|path| denied.iter().any(|deny| overlaps(path, deny))),
                "filesystem limits conflict with required private storage: {}",
                storage.display()
            );
        }
        if filesystem.kind == FileSystemSandboxKind::Unrestricted {
            *filesystem = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Write,
            )]);
        }
        let cwd_uri = PathUri::from(cwd.clone());
        let workspace_uri = PathUri::from(workspace.clone());
        let temporary = std::env::var_os("TMPDIR")
            .filter(|path| !path.is_empty() && Path::new(path).is_absolute())
            .map(AbsolutePathBuf::from_absolute_path_checked)
            .transpose()?
            .map(PathUri::from)
            .into_iter()
            .collect::<Vec<_>>();
        let context = FileSystemSandboxPolicyContext {
            cwd: &cwd_uri,
            workspace_roots: std::slice::from_ref(&workspace_uri),
            user_home_dir: None,
            temporary_directories: Some(&temporary),
        };
        let mut entries = Vec::new();
        let mut grant_aliases = Vec::new();
        for entry in std::mem::take(&mut filesystem.entries) {
            match &entry.path {
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::SlashTmp,
                } if !cfg!(unix) || !Path::new("/tmp").is_dir() => continue,
                FileSystemPath::GlobPattern { .. }
                | FileSystemPath::Special {
                    value: FileSystemSpecialPath::Minimal | FileSystemSpecialPath::Unknown { .. },
                } => {
                    entries.push(entry);
                    continue;
                }
                _ => {}
            }
            let single = FileSystemSandboxPolicy::restricted(vec![entry.clone()]);
            for (path, access) in single.resolved_entries(&context) {
                let path = path
                    .to_abs_path()
                    .context("limits require native filesystem paths")?;
                let aliases = path_aliases(&path)?;
                if aliases
                    .iter()
                    .any(|path| denied.iter().any(|deny| contains(deny, path)))
                {
                    // Remove narrower grants and redundant denies alike. Linux
                    // cannot install nested mounts below an ancestor deny mask.
                    continue;
                }
                if access.can_read()
                    && let Some(resolved) = aliases.last()
                    && resolved != &path
                {
                    grant_aliases.push((path.clone(), resolved.clone()));
                }
                let mut concrete = entry.clone();
                if !matches!(
                    &entry.path,
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root
                    }
                ) {
                    concrete.path = path.into();
                }
                concrete.access = access;
                entries.push(concrete);
            }
        }
        // Native mounts may rebind an alias's resolved target after an earlier
        // deny mask. Give each retained grant the corresponding logical deny,
        // so the backend reapplies it after that bind. Merely denying the real
        // path leaves a hole when /alias -> /real is itself a writable root.
        let mut projected = Vec::new();
        for (logical, resolved) in grant_aliases {
            for path in &denied {
                if contains(&resolved, path) {
                    // Component counts also handle Windows case variants; the
                    // containment check above already used native case folding.
                    let suffix: PathBuf = path
                        .as_path()
                        .components()
                        .skip(resolved.as_path().components().count())
                        .collect();
                    projected.push(logical.join(suffix));
                }
            }
        }
        denied.extend(projected);
        // Redundant nested admin denies need only one native mask. Keep both
        // logical and resolved aliases when neither contains the other.
        let mut minimal = Vec::new();
        for path in denied {
            if minimal.iter().any(|parent| contains(parent, &path)) {
                continue;
            }
            minimal.retain(|child| !contains(&path, child));
            minimal.push(path);
        }
        for path in &minimal {
            entries.push(FileSystemSandboxEntry::new(
                path.clone().into(),
                FileSystemAccessMode::Deny,
            ));
        }
        filesystem.entries = entries;
        Ok(minimal)
    }
}

fn literal_absolute_path(value: &str) -> Result<AbsolutePathBuf> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute(),
        "limits.filesystem.deny requires absolute paths: {value}"
    );
    ensure!(
        !value.contains('\0') && !path.components().any(|part| matches!(part,
            Component::Normal(name) if name.to_string_lossy().contains(['*', '?', '[', ']', '{', '}'])
        )),
        "limits.filesystem.deny requires literal paths, without wildcards: {value}"
    );
    AbsolutePathBuf::from_absolute_path_checked(path).map_err(Into::into)
}

#[cfg(not(windows))]
fn contains(parent: &AbsolutePathBuf, path: &AbsolutePathBuf) -> bool {
    PathUri::from(path.clone()).starts_with(&PathUri::from(parent.clone()))
}

#[cfg(windows)]
fn contains(parent: &AbsolutePathBuf, path: &AbsolutePathBuf) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::Globalization::CSTR_EQUAL;
    use windows_sys::Win32::Globalization::CompareStringOrdinal;

    // Match Windows' native case folding, including missing Unicode path tails.
    // Existing prefixes have already had 8.3 and reparse aliases resolved.
    let parent: Vec<u16> = parent.as_path().as_os_str().encode_wide().collect();
    let path: Vec<u16> = path.as_path().as_os_str().encode_wide().collect();
    path.len() >= parent.len()
        && unsafe {
            CompareStringOrdinal(
                parent.as_ptr(),
                parent.len() as i32,
                path.as_ptr(),
                parent.len() as i32,
                TRUE,
            )
        } == CSTR_EQUAL
        && (path.len() == parent.len()
            || parent
                .last()
                .is_some_and(|c| *c == u16::from(b'\\') || *c == u16::from(b'/'))
            || path
                .get(parent.len())
                .is_some_and(|c| *c == u16::from(b'\\') || *c == u16::from(b'/')))
}

fn overlaps(left: &AbsolutePathBuf, right: &AbsolutePathBuf) -> bool {
    contains(left, right) || contains(right, left)
}

fn path_aliases(path: &AbsolutePathBuf) -> Result<Vec<AbsolutePathBuf>> {
    let resolved = resolve_existing_prefix(path, /*links*/ 0)?;
    Ok(if &resolved == path {
        vec![path.clone()]
    } else {
        vec![path.clone(), resolved]
    })
}

/// Resolve existing aliases even when the final components are absent. A
/// dangling symlink still contributes its target plus the absent suffix.
fn resolve_existing_prefix(path: &AbsolutePathBuf, links: usize) -> Result<AbsolutePathBuf> {
    ensure!(
        links < 40,
        "too many symbolic links while resolving filesystem limits: {}",
        path.display()
    );
    for ancestor in path.as_path().ancestors() {
        let suffix = path.as_path().strip_prefix(ancestor)?;
        match AbsolutePathBuf::from_absolute_path_checked(ancestor)?.canonicalize() {
            Ok(base) => return Ok(base.join(suffix)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(ancestor) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        let target = std::fs::read_link(ancestor)?;
                        let parent = ancestor.parent().context("symbolic link has no parent")?;
                        let expanded: PathBuf = if target.is_absolute() {
                            target
                        } else {
                            parent.join(target)
                        };
                        return resolve_existing_prefix(
                            &AbsolutePathBuf::from_absolute_path_checked(expanded.join(suffix))?,
                            links + 1,
                        );
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("inspect filesystem limit alias"),
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("resolve filesystem limit path {}", path.display()));
            }
        }
    }
    anyhow::bail!("cannot resolve filesystem limit path {}", path.display())
}
