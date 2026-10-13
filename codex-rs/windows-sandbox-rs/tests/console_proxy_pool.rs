//! Explicit machine-changing acceptance for Console's native pool setup API.
#![cfg(windows)]

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_protocol::models::PermissionProfile;
use codex_windows_sandbox::ConsoleProxySlot;
use codex_windows_sandbox::ResolvedWindowsSandboxPermissions;
use codex_windows_sandbox::SandboxSetupRequest;
use codex_windows_sandbox::WindowsSandboxProduct;
use pretty_assertions::assert_eq;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "explicit pool provisioning: requires administrator approval, selected state, and Console setup helper on PATH"]
fn explicit_console_proxy_pool_provisioning() -> Result<()> {
    let state = PathBuf::from(
        std::env::var_os("MCP_CONSOLE_SANDBOX_TEST_STATE_DIR")
            .context("select the stable Console state directory explicitly")?,
    );
    ensure!(state.is_absolute(), "state directory must be absolute");
    WindowsSandboxProduct::Console.initialize()?;
    std::fs::create_dir_all(codex_windows_sandbox::sandbox_bin_dir(&state))?;
    for index in 0..ConsoleProxySlot::COUNT {
        ensure!(
            !state
                .join(".sandbox-secrets")
                .join(format!("proxy-slot-{index}.lease"))
                .exists(),
            "refusing to provision while slot {index} is leased or quarantined"
        );
    }
    let permissions = ResolvedWindowsSandboxPermissions::try_from_permission_profile(
        &PermissionProfile::read_only(),
    )?;
    let environment = HashMap::new();
    let provision = |state: &std::path::Path| {
        ConsoleProxySlot::provision_pool(SandboxSetupRequest {
            permissions: &permissions,
            command_cwd: state,
            codex_home: state,
            env_map: &environment,
            proxy_enforced: false,
        })
    };
    let last = state.join("proxy-slots").join("3").join(".sandbox-secrets");
    if !last.exists() {
        // Fail the final helper after earlier slots were provisioned. Never replace existing secrets.
        std::fs::create_dir_all(last.parent().context("slot directory")?)?;
        std::fs::write(&last, b"intentional setup failure")?;
        let result = provision(&state);
        std::fs::remove_file(&last)?;
        ensure!(result.is_err(), "partial setup unexpectedly succeeded");
        ensure!(
            ConsoleProxySlot::is_registered()?,
            "partial provisioning must reserve pool ownership"
        );
        ensure!(
            state
                .join("proxy-slots/0/.sandbox/setup_marker.json")
                .is_file(),
            "failure did not exercise partial pool provisioning: {result:?}"
        );
    } else {
        eprintln!("UNAVAILABLE partial-failure injection: preserving existing slot credentials");
    }
    provision(&state)?;
    ConsoleProxySlot::validate_owner(&state)?;
    ensure!(
        ConsoleProxySlot::is_registered()?,
        "pool ownership is not registered"
    );
    for index in 0..ConsoleProxySlot::COUNT {
        let slot = ConsoleProxySlot::new(index)?;
        let marker: Value = serde_json::from_slice(&std::fs::read(
            state
                .join("proxy-slots")
                .join(index.to_string())
                .join(".sandbox/setup_marker.json"),
        )?)?;
        assert_eq!(
            (
                marker["offline_username"].clone(),
                marker["online_username"].clone(),
                marker["proxy_ports"].clone(),
                marker["allow_local_binding"].clone()
            ),
            (
                Value::from(format!("McpConsoleProxyOff{index}")),
                Value::from(format!("McpConsoleProxyOn{index}")),
                serde_json::to_value(slot.ports())?,
                Value::from(slot.settings().allow_local_binding)
            )
        );
    }
    let output = Command::new("powershell.exe")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", r#"
$ErrorActionPreference = 'Stop'
$group = Get-LocalGroup ConsoleSandboxUsers
$members = @(Get-LocalGroupMember $group)
$rules = (New-Object -ComObject HNetCfg.FwPolicy2).Rules
foreach ($i in 0..3) {
    foreach ($kind in 'Off','On') {
        $account = Get-LocalUser "McpConsoleProxy$kind$i"
        if (!$account.Enabled -or $members.SID -notcontains $account.SID) { throw 'Missing enabled shared-group member' }
    }
    $sid = (Get-LocalUser "McpConsoleProxyOff$i").SID.Value
    $prefix = "console_p${i}_sandbox_offline_block_"
    foreach ($direction in 'outbound','inbound') {
        $rule = $rules.Item($prefix + $direction)
        if (!$rule.Enabled -or $rule.Action -ne 0 -or !$rule.LocalUserAuthorizedList.Contains($sid)) { throw 'Incorrect account firewall block' }
    }
    if ($i -lt 2) {
        $tcp = $rules.Item($prefix + 'loopback_tcp')
        $udp = $rules.Item($prefix + 'loopback_udp')
        $low = 43180 + 2*$i
        $expected = "1-$($low-1),$($low+2)-65535"
        if ($tcp.RemotePorts -ne $expected -or !$tcp.Enabled -or !$udp.Enabled) { throw 'Incorrect fixed proxy exceptions' }
    } else {
        if (@($rules | Where-Object Name -like ($prefix + 'loopback_*')).Count) { throw 'Local-binding slots still have loopback blocks' }
    }
    $secrets = Join-Path $env:MCP_POOL_STATE "proxy-slots\$i\.sandbox-secrets"
    $denies = @((Get-Acl -LiteralPath $secrets).Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $group.SID.Value
    })
    if (!$denies.Count) { throw 'Missing cross-slot secrets deny' }
}
"#])
        .env("MCP_POOL_STATE", &state)
        .output()?;
    ensure!(
        output.status.success(),
        "pool audit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let before = std::fs::read(state.join(".sandbox-secrets/sandbox_users.json"))?;
    let other = tempfile::tempdir()?;
    let error = provision(other.path()).expect_err("different state owner must be rejected");
    ensure!(
        error.to_string().contains("different state directory"),
        "{error:#}"
    );
    assert_eq!(
        before,
        std::fs::read(state.join(".sandbox-secrets/sandbox_users.json"))?
    );
    ensure!(
        !other.path().join("proxy-slots").exists(),
        "owner mismatch created slot state"
    );
    // Explicit refresh must be repeatable without changing identity/port ownership.
    provision(&state)?;
    ConsoleProxySlot::validate_owner(&state)
}
