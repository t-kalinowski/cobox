//! Console's environment transport, backed by Codex's shared Windows launch APIs.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::config_types::WindowsSandboxProxySettingsMode;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_sandboxing::SandboxCommand;
use codex_sandboxing::SandboxManager;
use codex_sandboxing::SandboxTransformRequest;
use codex_sandboxing::SandboxType;
use codex_sandboxing::SpawnRequest;
use codex_sandboxing::WindowsSandboxLaunchContext;
use codex_sandboxing::WindowsSandboxPreference;
use codex_sandboxing::WindowsSandboxSpawnRequest;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::WindowsSandboxProduct;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;

pub(crate) fn run() -> Result<i32> {
    let crate::bootstrap::Input::Environment(mut request) = crate::bootstrap::take_input()?;
    ensure!(
        request.proxy.is_none()
            || request.excluded_environment.iter().all(|name| {
                !codex_network_proxy::PROXY_ENV_KEYS
                    .iter()
                    .any(|key| name.eq_ignore_ascii_case(key))
            }),
        "configuration transport conflicts with managed proxy environment; use a dedicated --config-env name"
    );
    ensure!(
        request.macos_seatbelt_profile_extension.is_none(),
        "macos_seatbelt_profile_extension is supported only on macOS"
    );
    ensure!(
        request.lifecycle.cleanup_timeout_ms.is_none(),
        "cleanup_timeout_ms is not configurable on Windows"
    );
    let preference = request
        .windows_sandbox_level
        .map(WindowsSandboxPreference::try_from)
        .transpose()?
        .unwrap_or_default();
    let (mut filesystem, network) = crate::profiles::resolve(&request)?;
    let state = match request.windows_state_dir.take() {
        Some(state) => state.into_path_buf(),
        None => {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
                .join("mcp-console")
        }
    };
    WindowsSandboxProduct::Console.initialize()?;
    // Old setup does not register its credential directory. MXC's host identity
    // could read an unknown copy of those credentials, unlike the legacy accounts.
    let mut host_mxc_restriction = None;
    if matches!(
        preference,
        WindowsSandboxPreference::Auto | WindowsSandboxPreference::Mxc
    ) {
        for account in ["McpConsoleSandboxOff", "McpConsoleSandboxOn"] {
            if codex_windows_sandbox::local_user_flags(account)?.is_some() {
                host_mxc_restriction = Some(
                    "MXC is unavailable while legacy Console sandbox accounts exist; use elevated mode",
                );
            }
        }
    }
    let workspace = request.workspace.as_ref().unwrap_or(&request.cwd).clone();
    let (sandbox, level) = codex_sandboxing::select_windows_sandbox(
        preference,
        &PermissionProfile::from_runtime_permissions(&filesystem, network)
            .materialize_project_roots_with_workspace_roots(std::slice::from_ref(&workspace)),
        request.proxy.as_ref(),
        host_mxc_restriction,
    )?;
    ensure!(
        request.proxy.is_none() || sandbox == SandboxType::WindowsMxc,
        "managed proxy configuration is not supported by the legacy Windows sandbox"
    );
    ensure!(
        level != WindowsSandboxLevel::RestrictedToken || network == NetworkSandboxPolicy::Enabled,
        "restricted networking requires the elevated Windows sandbox; unelevated requires network: enabled"
    );
    ensure!(
        level != WindowsSandboxLevel::RestrictedToken
            || (filesystem.has_full_disk_read_access()
                && !filesystem.has_denied_read_restrictions()),
        "unelevated requires host reads and cannot enforce read restrictions"
    );
    ensure!(
        level != WindowsSandboxLevel::Elevated
            || codex_windows_sandbox::check_sandbox_setup(&state)?,
        "Windows sandbox setup is required; run `mcp-console-sandbox setup` with the same state directory from an interactive terminal"
    );
    let parent = Parent::new(request.lifecycle.parent_pid)?;
    for name in &request.excluded_environment {
        request
            .environment
            .retain(|key, _| !key.eq_ignore_ascii_case(name));
        // This standalone executable is still single-threaded.
        unsafe {
            std::env::remove_var(name);
        }
    }
    let mut storage = request
        .lifecycle
        .private_tmp
        .as_ref()
        .map(|config| -> Result<_> {
            let directory = tempfile::Builder::new()
                .prefix("sandbox-")
                .tempdir_in(config.parent.clone().unwrap_or_else(std::env::temp_dir))?;
            let path = AbsolutePathBuf::try_from(directory.path().join("data"))?;
            std::fs::create_dir(path.as_path())?;
            filesystem.entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: path.clone().into(),
                },
                access: FileSystemAccessMode::Write,
                missing_path_behavior: None,
            });
            for name in &config.environment {
                ensure!(
                    !request
                        .excluded_environment
                        .iter()
                        .any(|excluded| excluded.eq_ignore_ascii_case(name)),
                    "configuration transport variable cannot be exported to the target"
                );
                request
                    .environment
                    .retain(|key, _| !key.eq_ignore_ascii_case(name));
                request
                    .environment
                    .insert(name.clone(), path.to_string_lossy().into_owned());
            }
            Ok(directory)
        })
        .transpose()?;
    let profile = PermissionProfile::from_runtime_permissions(&filesystem, network)
        .materialize_project_roots_with_workspace_roots(std::slice::from_ref(&workspace));
    let job = (sandbox == SandboxType::WindowsMxc)
        .then(codex_utils_pty::JobObject::create_without_breakaway)
        .transpose()?
        .map(Arc::new);
    let mut retained_storage = None;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let proxy = match request.proxy {
                Some(config) => Some(
                    crate::windows_proxy::start(
                        config,
                        job.as_ref().context("MXC proxy Job")?,
                        &mut request.environment,
                    )
                    .await?,
                ),
                None => None,
            };
            let executable = std::env::current_exe()?;
            request.environment.retain(|name, _| {
                !request
                    .excluded_environment
                    .iter()
                    .any(|excluded| name.eq_ignore_ascii_case(excluded))
            });
            let (program, args) = request.command.split_first().context("missing command")?;
            let prepared = SandboxManager::default().transform(SandboxTransformRequest {
                command: SandboxCommand {
                    program: program.into(),
                    args: args.to_vec(),
                    cwd: request.cwd.clone().into(),
                    env: request.environment,
                    managed_network: proxy.as_ref().map(|proxy| proxy.context.clone()),
                    additional_permissions: None,
                },
                permissions: &profile,
                sandbox,
                enforce_managed_network: proxy.is_some(),
                environment_id: None,
                network: proxy.as_ref().map(|proxy| &proxy.proxy),
                sandbox_policy_cwd: &request.cwd.clone().into(),
                sandbox_exe: Some(&executable),
                use_legacy_landlock: false,
                windows_sandbox_level: level,
            })?;
            // Before a launch attempt TempDir removes failed preflight storage.
            // Afterwards cleanup requires a confirmed native retirement receipt.
            retained_storage = storage.take().map(tempfile::TempDir::keep);
            let spawned = codex_sandboxing::spawn_process_with_windows_context(
                SpawnRequest {
                    command: &prepared.command,
                    cwd: request.cwd.as_path(),
                    env: &prepared.env,
                    arg0: &prepared.arg0,
                    sandbox: prepared.sandbox,
                    windows_sandbox: Some(WindowsSandboxSpawnRequest {
                        permission_profile: &prepared.permission_profile,
                        workspace_roots: std::slice::from_ref(&workspace),
                        windows_sandbox_level: level,
                        proxy_enforced: proxy.is_some(),
                        network_proxy_restricting_sid: None,
                        proxy_settings_mode: WindowsSandboxProxySettingsMode::Reconcile,
                        filesystem_overrides: None,
                    }),
                    tty: false,
                    stdin_open: true,
                    inherited_fds: codex_utils_pty::ChildFds::Inherited(&[]),
                },
                WindowsSandboxLaunchContext {
                    state_dir: &state,
                    job,
                },
            )
            .await?;
            // The bridge owns I/O and waits for the backend's confirmed Job retirement.
            let cancellation = async move {
                parent.exited().await;
            };
            let result = codex_windows_sandbox::forward_sandbox_session_stdio_with_cancellation(
                spawned,
                cancellation,
            )
            .await;
            if let Some(proxy) = proxy {
                proxy.handle.shutdown().await?;
            }
            Ok::<_, anyhow::Error>(result)
        });
    if let Some(storage) = retained_storage {
        if matches!(result, Ok(None) | Err(_)) {
            eprintln!(
                "private storage retained after unconfirmed retirement: {}",
                storage.display()
            );
        } else {
            // Job retirement precedes cleanup, but Windows can briefly retain
            // image/file mappings. Retry only that sharing violation; success
            // still requires removal, and persistent failures retain the error.
            let deadline = Instant::now() + Duration::from_secs(/*secs*/ 5);
            loop {
                match std::fs::remove_dir_all(&storage) {
                    Ok(()) => break,
                    Err(error)
                        if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(
                            Duration::from_millis(/*millis*/ 10)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                    Err(error) => {
                        return Err(error).context("remove retired Windows private storage");
                    }
                }
            }
        }
    }
    result.map(|receipt| receipt.unwrap_or(/*default*/ 125))
}

struct Parent {
    handles: Vec<OwnedHandle>,
    cancel: std::sync::Arc<OwnedHandle>,
}

impl Parent {
    fn new(owner: Option<i32>) -> Result<Self> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        ensure!(
            snapshot != INVALID_HANDLE_VALUE,
            "cannot inspect sandbox parent"
        );
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of_val(&entry) as u32;
        let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
        while found && entry.th32ProcessID != std::process::id() {
            found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
        }
        ensure!(found, "cannot find the runner's direct parent");
        let mut pids = vec![entry.th32ParentProcessID];
        if let Some(owner) = owner
            && owner as u32 != pids[0]
        {
            pids.push(owner as u32);
        }
        let handles = pids
            .into_iter()
            .map(|pid| -> Result<_> {
                let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
                ensure!(
                    !handle.is_null(),
                    "cannot monitor sandbox owner: {}",
                    std::io::Error::last_os_error()
                );
                Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
            })
            .collect::<Result<Vec<_>>>()?;
        let cancel = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        ensure!(!cancel.is_null(), "cannot create parent cancellation event");
        Ok(Self {
            handles,
            cancel: std::sync::Arc::new(unsafe { OwnedHandle::from_raw_handle(cancel) }),
        })
    }

    async fn exited(self) {
        struct Cancel(std::sync::Arc<OwnedHandle>);
        impl Drop for Cancel {
            fn drop(&mut self) {
                unsafe {
                    SetEvent(self.0.as_raw_handle());
                }
            }
        }
        let _cancel = Cancel(std::sync::Arc::clone(&self.cancel));
        let (send, receive) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut handles: Vec<_> = self
                .handles
                .iter()
                .map(AsRawHandle::as_raw_handle)
                .collect();
            handles.push(self.cancel.as_raw_handle());
            let status = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE)
            };
            if status != WAIT_OBJECT_0 + handles.len() as u32 - 1 {
                let _ = send.send(());
            }
        });
        let _ = receive.await;
    }
}
