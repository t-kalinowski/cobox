//! Console's unversioned policy transport, backed by the native Windows session.

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
use codex_sandboxing::SandboxablePreference;
use codex_sandboxing::SpawnRequest;
use codex_sandboxing::WindowsSandboxLaunchContext;
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
        request.proxy.is_none(),
        "managed proxy configuration is not supported on Windows"
    );
    ensure!(
        request.macos_seatbelt_profile_extension.is_none(),
        "macos_seatbelt_profile_extension is supported only on macOS"
    );
    ensure!(
        request.lifecycle.cleanup_timeout_ms.is_none(),
        "cleanup_timeout_ms is not configurable on Windows"
    );
    use crate::config::WindowsSandboxMode;
    let (mut filesystem, network) = crate::profiles::resolve(&request)?;
    let workspace = request.workspace.as_ref().unwrap_or(&request.cwd).clone();
    filesystem =
        filesystem.materialize_project_roots_with_workspace_roots(std::slice::from_ref(&workspace));
    let state = match request.windows_state_dir.take() {
        Some(state) => state.into_path_buf(),
        None => {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
                .join("mcp-console")
        }
    };
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
    let storage = request
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
            // Keep automatic cleanup until policy preflight and backend selection finish.
            Ok(directory)
        })
        .transpose()?;
    // Resolve only the policy's explicit temporary-directory grants from target inputs.
    // Provisioning still receives the trusted host environment; neither backend may
    // substitute the host's temp path for a target override (or an omitted target value).
    let temporary_paths = request
        .environment
        .iter()
        .filter(|(key, value)| {
            (key.eq_ignore_ascii_case("TEMP") || key.eq_ignore_ascii_case("TMP"))
                && std::path::Path::new(value).is_absolute()
        })
        .map(|(_, value)| AbsolutePathBuf::from_absolute_path(value))
        .collect::<std::io::Result<Vec<_>>>()?;
    filesystem.entries = filesystem
        .entries
        .into_iter()
        .flat_map(|entry| {
            if matches!(
                &entry.path,
                FileSystemPath::Special {
                    value: codex_protocol::permissions::FileSystemSpecialPath::Tmpdir,
                }
            ) {
                temporary_paths
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
    let mut mxc_filesystem = filesystem.clone();
    let mxc_state_protection =
        crate::windows_proxy::protect_state(&mut mxc_filesystem, &state, &request.cwd);
    let initial_profile = PermissionProfile::from_runtime_permissions(&mxc_filesystem, network);
    let (backend, level) = match request
        .windows_sandbox_level
        .unwrap_or(WindowsSandboxMode::Auto)
    {
        WindowsSandboxMode::Disabled => {
            anyhow::bail!("windows_sandbox_level: disabled is not supported")
        }
        WindowsSandboxMode::Mxc => {
            if let Err(error) = &mxc_state_protection {
                anyhow::bail!("{error:#}");
            }
            ensure!(
                codex_sandboxing::windows_mxc_available(),
                "MXC is unavailable on this executor"
            );
            ensure!(
                codex_sandboxing::windows_mxc_available_for(&initial_profile),
                "MXC cannot enforce this filesystem policy on this executor"
            );
            (SandboxType::WindowsMxc, WindowsSandboxLevel::Disabled)
        }
        WindowsSandboxMode::Auto => (
            codex_sandboxing::resolve_windows_sandbox_type(
                SandboxType::WindowsRestrictedToken,
                mxc_state_protection.is_ok()
                    && codex_sandboxing::windows_mxc_available_for(&initial_profile),
            ),
            WindowsSandboxLevel::Elevated,
        ),
        WindowsSandboxMode::Elevated => (
            SandboxType::WindowsRestrictedToken,
            WindowsSandboxLevel::Elevated,
        ),
        WindowsSandboxMode::Unelevated => (
            SandboxType::WindowsRestrictedToken,
            WindowsSandboxLevel::RestrictedToken,
        ),
    };
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
    if backend == SandboxType::WindowsMxc {
        filesystem = mxc_filesystem;
    }
    WindowsSandboxProduct::Console.initialize()?;
    if backend == SandboxType::WindowsRestrictedToken && level == WindowsSandboxLevel::Elevated {
        ensure!(
            codex_windows_sandbox::check_sandbox_setup(&state)?
                && codex_windows_sandbox::sandbox_setup_is_complete_with_settings(
                    &state,
                    &codex_windows_sandbox::WindowsSandboxProvisioningSettings::default()
                ),
            "Windows sandbox setup is required; run `mcp-console-sandbox setup` with the original base state directory from an interactive terminal"
        );
    }
    let job = (backend == SandboxType::WindowsMxc)
        .then(codex_utils_pty::JobObject::create_without_breakaway)
        .transpose()?
        .map(Arc::new);
    let storage = storage.map(tempfile::TempDir::keep);
    let manager = SandboxManager::default();
    let mut spawn_attempted = false;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let profile = PermissionProfile::from_runtime_permissions(&filesystem, network);
            let sandbox = manager.select_initial(
                &profile,
                SandboxablePreference::Require,
                backend,
                /*has_managed_network_requirements*/ false,
            );
            // Projection precedes the final case-insensitive transport exclusion.
            request.environment.retain(|name, _| {
                !request
                    .excluded_environment
                    .iter()
                    .any(|excluded| name.eq_ignore_ascii_case(excluded))
            });
            let (program, args) = request
                .command
                .split_first()
                .context("missing sandbox command")?;
            let policy_cwd = request.cwd.clone().into();
            let executable = std::env::current_exe()?;
            let prepared = manager.transform(SandboxTransformRequest {
                command: SandboxCommand {
                    program: program.into(),
                    args: args.to_vec(),
                    cwd: request.cwd.clone().into(),
                    env: request.environment,
                    managed_network: None,
                    additional_permissions: None,
                },
                permissions: &profile,
                sandbox,
                enforce_managed_network: false,
                environment_id: None,
                network: None,
                sandbox_policy_cwd: &policy_cwd,
                sandbox_exe: Some(&executable),
                use_legacy_landlock: false,
                windows_sandbox_level: level,
            })?;
            spawn_attempted = true;
            let spawned = codex_sandboxing::spawn_process_with_windows_context(
                SpawnRequest {
                    command: &prepared.command,
                    cwd: request.cwd.as_path(),
                    env: &prepared.env,
                    arg0: &prepared.arg0,
                    sandbox: prepared.sandbox,
                    windows_sandbox: Some(WindowsSandboxSpawnRequest {
                        permission_profile: &profile,
                        workspace_roots: std::slice::from_ref(&workspace),
                        windows_sandbox_level: level,
                        proxy_enforced: false,
                        network_proxy_restricting_sid: None,
                        proxy_settings_mode: WindowsSandboxProxySettingsMode::Preserve,
                        filesystem_overrides: None,
                    }),
                    tty: false,
                    stdin_open: true,
                    inherited_fds: codex_utils_pty::ChildFds::Inherited(&[]),
                },
                WindowsSandboxLaunchContext {
                    state_dir: &state,
                    job: job.clone(),
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
            // A missing receipt is distinct from every 32-bit target exit code.
            Ok::<_, anyhow::Error>(result)
        });
    if let Some(storage) = storage {
        if spawn_attempted && matches!(result, Ok(None) | Err(_)) {
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
    result.map(|receipt| receipt.unwrap_or(125))
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
