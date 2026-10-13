//! Uses an explicitly provisioned Console pool; never installs or refreshes account policy.
#![cfg(windows)]

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_cargo_bin::cargo_bin;
use codex_windows_sandbox::ConsoleProxySlot;
use codex_windows_sandbox::WindowsSandboxProxySettingsMode;
use codex_windows_sandbox::WindowsSandboxSessionRequest;
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::UdpSocket;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore = "requires completed Console pool setup, built Console helpers, and exclusive pool access"]
fn provisioned_slot_runner_and_wfp_guards() -> Result<()> {
    ensure!(
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0,
        "run workload acceptance from an ordinary non-elevated shell after explicit setup"
    );
    // Match the shipped adjacent-helper layout after Cargo/Bazel resolves the helpers.
    // CreateProcessWithLogonW does not search PATH for the fallback bare runner name.
    let bundle = tempfile::tempdir()?;
    let executable = bundle.path().join("console-proxy-native.exe");
    std::fs::copy(std::env::current_exe()?, &executable)?;
    for name in ["mcp-console-sandbox-setup", "mcp-console-sandbox-runner"] {
        std::fs::copy(cargo_bin(name)?, bundle.path().join(format!("{name}.exe")))?;
    }
    // Product and slot selection is immutable in each process. Exercise both classes
    // in separate processes, even when the caller uses libtest rather than nextest.
    for slot in [0, 2] {
        let output = Command::new(&executable)
            .args(["--exact", "slot_driver_entry", "--nocapture"])
            .env("CONSOLE_NATIVE_SLOT", slot.to_string())
            .output()?;
        ensure!(output.status.success(), "slot {slot}: {output:?}");
        for account in ["Off", "On"] {
            ensure!(
                String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("VERIFIED=McpConsoleProxy{account}{slot}")),
                "missing account control: {output:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn slot_driver_entry() -> Result<()> {
    let Ok(index) = std::env::var("CONSOLE_NATIVE_SLOT") else {
        return Ok(());
    };
    let slot = ConsoleProxySlot::new(index.parse()?)?;
    slot.initialize()?;
    let state = PathBuf::from(
        std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR")
            .context("select the already provisioned Console state directory")?,
    );
    ConsoleProxySlot::validate_owner(&state)?;
    assert_eq!(
        ConsoleProxySlot::registered_state_directory()?,
        Some(std::fs::canonicalize(&state)?)
    );
    for index in 0..ConsoleProxySlot::COUNT {
        ensure!(
            !state
                .join(".sandbox-secrets")
                .join(format!("proxy-slot-{index}.lease"))
                .exists(),
            "slot {index} is leased or quarantined"
        );
    }
    let slot_state = state.join("proxy-slots").join(slot.index().to_string());
    ensure!(
        codex_windows_sandbox::sandbox_setup_is_complete_with_settings(
            &slot_state,
            &slot.settings()
        ),
        "explicit Console setup refresh required"
    );
    let executable = std::env::current_exe()?;
    let workspace = tempfile::tempdir()?;
    let read_roots = vec![
        workspace.path().to_path_buf(),
        executable
            .parent()
            .context("test binary directory")?
            .to_path_buf(),
    ];

    // Positive host controls distinguish unavailable/occupied ports or IPv6 from
    // the account-specific resource-assignment and listener guards below.
    for ip in ["127.0.0.1", "::1"] {
        for port in 43180..=43187 {
            drop(TcpListener::bind((ip, port))?);
        }
        let receiver = UdpSocket::bind((ip, 0))?;
        receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
        let sender = UdpSocket::bind((ip, 0))?;
        sender.send_to(b"pool-control", receiver.local_addr()?)?;
        let mut buffer = [0; 32];
        let received = receiver.recv(&mut buffer)?;
        assert_eq!(&buffer[..received], b"pool-control");
    }

    for network in [
        NetworkSandboxPolicy::Restricted,
        NetworkSandboxPolicy::Enabled,
    ] {
        let profile = PermissionProfile::from_runtime_permissions(
            &PermissionProfile::read_only().file_system_sandbox_policy(),
            network,
        );
        let account = if network == NetworkSandboxPolicy::Restricted {
            "Off"
        } else {
            "On"
        };
        let expected_user = format!("McpConsoleProxy{account}{}", slot.index());
        let mut environment: HashMap<String, String> = std::env::vars().collect();
        environment.remove("CONSOLE_NATIVE_SLOT");
        environment.insert("CONSOLE_NATIVE_ACCOUNT".into(), expected_user.clone());
        environment.insert(
            "CONSOLE_NATIVE_DESKTOP".into(),
            format!("ConsoleP{}SandboxDesktop-", slot.index()),
        );
        environment.insert(
            "CONSOLE_NATIVE_LOCAL".into(),
            (network == NetworkSandboxPolicy::Enabled || slot.settings().allow_local_binding)
                .to_string(),
        );
        // Reuse the Console-aware reader with these read roots and platform defaults.
        // Its ACL refresh preserves account policy and refuses automatic provisioning.
        let unrelated_profile = PermissionProfile::from_runtime_permissions(
            &PermissionProfile::read_only().file_system_sandbox_policy(),
            match network {
                NetworkSandboxPolicy::Restricted => NetworkSandboxPolicy::Enabled,
                NetworkSandboxPolicy::Enabled => NetworkSandboxPolicy::Restricted,
            },
        );
        let unrelated_permissions =
            codex_windows_sandbox::ResolvedWindowsSandboxPermissions::try_from_permission_profile(
                &unrelated_profile,
            )?;
        let credentials = codex_windows_sandbox::require_logon_sandbox_creds(
            &unrelated_permissions,
            workspace.path(),
            &HashMap::new(),
            &slot_state,
            Some(&read_roots),
            /*read_roots_include_platform_defaults*/ true,
            Some(&[]),
            &[],
            &[],
            /*proxy_enforced*/ false,
            WindowsSandboxProxySettingsMode::Preserve,
        )?;
        let mut token = 0;
        ensure!(
            unsafe {
                windows_sys::Win32::Security::LogonUserW(
                    codex_windows_sandbox::to_wide(&credentials.username).as_ptr(),
                    codex_windows_sandbox::to_wide(".").as_ptr(),
                    codex_windows_sandbox::to_wide(&credentials.password).as_ptr(),
                    windows_sys::Win32::Security::LOGON32_LOGON_INTERACTIVE,
                    windows_sys::Win32::Security::LOGON32_PROVIDER_DEFAULT,
                    &mut token,
                )
            } != 0,
            "log on unrelated Console account: {}",
            std::io::Error::last_os_error()
        );
        drop(credentials);
        let unrelated = unsafe { OwnedHandle::from_raw_handle(token as _) };
        let mut child = codex_windows_sandbox::spawn_windows_sandbox_session_for_level(
            WindowsSandboxSessionRequest {
                permission_profile: &profile,
                workspace_roots: &[],
                codex_home: &slot_state,
                command: vec![
                    executable.to_string_lossy().into_owned(),
                    "--exact".into(),
                    "slot_workload_probe".into(),
                    "--nocapture".into(),
                ],
                cwd: workspace.path(),
                env_map: environment,
                windows_sandbox_level: WindowsSandboxLevel::Elevated,
                proxy_enforced: false,
                network_proxy_restricting_sid: None,
                proxy_settings_mode: WindowsSandboxProxySettingsMode::Preserve,
                timeout_ms: Some(15_000),
                read_roots_override: Some(&read_roots),
                read_roots_include_platform_defaults: true,
                write_roots_override: Some(&[]),
                deny_read_paths_override: &[],
                deny_write_paths_override: &[],
                tty: false,
                stdin_open: true,
            },
        )
        .await?;
        let stdout = async {
            let mut output = String::new();
            let mut pending = String::new();
            while let Some(bytes) = child.stdout_rx.recv().await {
                let text = String::from_utf8(bytes)?;
                output.push_str(&text);
                pending.push_str(&text);
                while let Some((line, rest)) = pending.split_once('\n') {
                    if let Some(pid) = line.trim().strip_prefix("OBSERVER=") {
                        verify_observer_access(pid.parse()?, &expected_user, &unrelated)?;
                        child
                            .session
                            .writer_sender()
                            .send(b"observed\n".to_vec())
                            .await?;
                    }
                    if let Some(address) = line.trim().strip_prefix("UDP=") {
                        let address: SocketAddr = address.parse()?;
                        let sender = UdpSocket::bind((address.ip(), 0))?;
                        sender.send_to(b"pool-control", address)?;
                    }
                    pending = rest.to_owned();
                }
            }
            Ok::<_, anyhow::Error>(output)
        };
        let stderr = async {
            let mut bytes = Vec::new();
            while let Some(chunk) = child.stderr_rx.recv().await {
                bytes.extend(chunk);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let (exit, stdout, stderr) = tokio::join!(child.exit_rx, stdout, stderr);
        let stdout = stdout?;
        assert_eq!(exit?, 0, "{expected_user}: {stdout} {stderr}");
        ensure!(
            stdout.contains(&format!("SLOT_PROBE_OK={expected_user}")),
            "workload did not complete: {stdout}"
        );
        println!("VERIFIED={expected_user}");
    }
    Ok(())
}

fn verify_observer_access(pid: u32, expected_user: &str, unrelated: &OwnedHandle) -> Result<()> {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            /*binherithandle*/ 0,
            pid,
        )
    };
    ensure!(
        process != 0,
        "owner cannot query workload process: {}",
        std::io::Error::last_os_error()
    );
    let process = unsafe { OwnedHandle::from_raw_handle(process as _) };
    let mut token = 0;
    ensure!(
        unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) }
            != 0,
        "owner cannot query workload token: {}",
        std::io::Error::last_os_error()
    );
    let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
    assert_eq!(
        unsafe { codex_windows_sandbox::get_user_sid_bytes(token.as_raw_handle() as HANDLE) }?,
        codex_windows_sandbox::resolve_sid(expected_user)?,
    );
    // A distinct provisioned account is the negative control, not a synthetic
    // restricted copy of the owner's token. Existing native token ACEs permit
    // the trusted credential owner to duplicate tokens; this grants no new rights
    // to another account. No account or ACL is modified by these access probes.
    ensure!(
        unsafe { codex_windows_sandbox::get_user_sid_bytes(unrelated.as_raw_handle() as HANDLE) }?
            != codex_windows_sandbox::resolve_sid(expected_user)?,
        "negative control reused workload identity"
    );
    ensure!(
        unsafe { ImpersonateLoggedOnUser(unrelated.as_raw_handle() as HANDLE) } != 0,
        "impersonate unrelated account: {}",
        std::io::Error::last_os_error()
    );
    let foreign_process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            /*binherithandle*/ 0,
            pid,
        )
    };
    let process_error = std::io::Error::last_os_error().raw_os_error();
    let foreign_tokens: Vec<_> = [TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ADJUST_PRIVILEGES]
        .into_iter()
        .map(|rights| {
            let mut token = 0;
            let access =
                unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, rights, &mut token) };
            let error = std::io::Error::last_os_error().raw_os_error();
            if access != 0 {
                drop(unsafe { OwnedHandle::from_raw_handle(token as _) });
            }
            (access, error)
        })
        .collect();
    let reverted = unsafe { RevertToSelf() };
    let process_denied = foreign_process == 0;
    if !process_denied {
        drop(unsafe { OwnedHandle::from_raw_handle(foreign_process as _) });
    }
    ensure!(reverted != 0, "restore owner identity");
    assert_eq!(
        (process_denied, process_error, foreign_tokens),
        (
            true,
            Some(ERROR_ACCESS_DENIED as i32),
            vec![(0, Some(ERROR_ACCESS_DENIED as i32)); 3],
        ),
        "unrelated account received observer access",
    );
    Ok(())
}

#[test]
fn slot_workload_probe() -> Result<()> {
    let Ok(expected_user) = std::env::var("CONSOLE_NATIVE_ACCOUNT") else {
        return Ok(());
    };
    ensure!(
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0,
        "workload has an administrator token"
    );
    let local: bool = std::env::var("CONSOLE_NATIVE_LOCAL")?.parse()?;
    // Query native identity and desktop, not environment variables supplied by the driver.
    let mut user = [0_u16; 256];
    let mut user_length = user.len() as u32;
    ensure!(
        unsafe {
            windows_sys::Win32::System::WindowsProgramming::GetUserNameW(
                user.as_mut_ptr(),
                &mut user_length,
            )
        } != 0,
        "query account: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        String::from_utf16(&user[..user_length as usize - 1])?,
        expected_user
    );
    use windows_sys::Win32::System::StationsAndDesktops::*;
    let desktop =
        unsafe { GetThreadDesktop(windows_sys::Win32::System::Threading::GetCurrentThreadId()) };
    let mut name = [0_u16; 256];
    let mut needed = 0;
    ensure!(
        unsafe {
            GetUserObjectInformationW(
                desktop,
                UOI_NAME,
                name.as_mut_ptr().cast(),
                std::mem::size_of_val(&name) as u32,
                &mut needed,
            )
        } != 0,
        "query desktop: {}",
        std::io::Error::last_os_error()
    );
    let name = String::from_utf16(
        &name[..name
            .iter()
            .position(|value| *value == 0)
            .context("desktop terminator")?],
    )?;
    ensure!(
        name.starts_with(&std::env::var("CONSOLE_NATIVE_DESKTOP")?),
        "unexpected runner desktop {name}"
    );

    println!("OBSERVER={}", std::process::id());
    std::io::stdout().flush()?;
    let mut acknowledgment = String::new();
    std::io::stdin().read_line(&mut acknowledgment)?;
    assert_eq!(acknowledgment, "observed\n");

    for ip in ["127.0.0.1".parse::<IpAddr>()?, "::1".parse()?] {
        for port in 43180..=43187 {
            let result = TcpListener::bind((ip, port))
                .map(drop)
                .map_err(|error| error.kind());
            assert_eq!(
                result,
                Err(std::io::ErrorKind::PermissionDenied),
                "reserved {ip}:{port}"
            );
        }
        let listen = TcpListener::bind((ip, 0))
            .map(drop)
            .map_err(|error| error.kind());
        assert_eq!(
            listen,
            if local {
                Ok(())
            } else {
                Err(std::io::ErrorKind::PermissionDenied)
            },
            "local TCP {ip}"
        );
        let receiver = UdpSocket::bind((ip, 0))?;
        receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
        println!("UDP={}", receiver.local_addr()?);
        std::io::stdout().flush()?;
        let mut buffer = [0; 32];
        match receiver.recv(&mut buffer) {
            Ok(length) => {
                ensure!(local, "strict slot received local UDP traffic");
                assert_eq!(&buffer[..length], b"pool-control");
            }
            Err(error) => ensure!(
                !local
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ),
                "local UDP {ip}: {error}"
            ),
        }
    }
    println!("SLOT_PROBE_OK={expected_user}");
    Ok(())
}
