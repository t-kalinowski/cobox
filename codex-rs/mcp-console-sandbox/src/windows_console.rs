//! Console's versioned policy transport, backed by the native Windows session.

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
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_windows_sandbox::WindowsSandboxProduct;
use codex_windows_sandbox::WindowsSandboxSessionRequest;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::PathBuf;
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
    let level = request
        .windows_sandbox_level
        .map(WindowsSandboxLevel::from)
        .unwrap_or(WindowsSandboxLevel::Elevated);
    ensure!(
        level != WindowsSandboxLevel::Disabled,
        "windows_sandbox_level: disabled is not supported"
    );
    let (mut filesystem, network) = crate::profiles::resolve(&request)?;
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
    let state = match request.windows_state_dir.take() {
        Some(state) => state.into_path_buf(),
        None => {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?)
                .join("mcp-console")
        }
    };
    WindowsSandboxProduct::Console.initialize()?;
    let configured = codex_windows_sandbox::check_sandbox_setup(&state)?;
    ensure!(
        level != WindowsSandboxLevel::Elevated || configured,
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
            // Cleanup belongs to the confirmed Job receipt, including when a
            // later error or panic unwinds this function.
            Ok(directory.keep())
        })
        .transpose()?;
    let profile = PermissionProfile::from_runtime_permissions(&filesystem, network);
    let workspace = request.workspace.as_ref().unwrap_or(&request.cwd).clone();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let spawned = codex_windows_sandbox::spawn_windows_sandbox_session_for_level(
                WindowsSandboxSessionRequest {
                    permission_profile: &profile,
                    workspace_roots: std::slice::from_ref(&workspace),
                    codex_home: &state,
                    command: request.command,
                    cwd: request.cwd.as_path(),
                    env_map: request.environment,
                    windows_sandbox_level: level,
                    proxy_enforced: false,
                    network_proxy_restricting_sid: None,
                    proxy_settings_mode: WindowsSandboxProxySettingsMode::Reconcile,
                    timeout_ms: None,
                    read_roots_override: None,
                    read_roots_include_platform_defaults: false,
                    write_roots_override: None,
                    deny_read_paths_override: &[],
                    deny_write_paths_override: &[],
                    tty: false,
                    stdin_open: true,
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
            Ok::<_, anyhow::Error>(result.unwrap_or(125))
        });
    if let Some(storage) = storage {
        // Code 125 is reserved for an unconfirmed native retirement.
        if matches!(result, Ok(125) | Err(_)) {
            eprintln!(
                "private storage retained after unconfirmed retirement: {}",
                storage.display()
            );
        } else {
            std::fs::remove_dir_all(storage).context("remove retired Windows private storage")?;
        }
    }
    result
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
