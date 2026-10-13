//! Enforce the firewall's loopback policy at ALE, including local TCP/UDP flows.

use super::Engine;
use super::UserMatchCondition;
use super::add_filter_with_conditions;
use super::build_conditions;
use super::delete_filter_if_present;
use super::ensure_provider;
use super::ensure_sublayer;
use super::ensure_success;
use super::filter_specs::ConditionSpec;
use super::filter_specs::FilterSpec;
use crate::WindowsSandboxProduct;
use crate::WindowsSandboxProvisioningSettings;
use anyhow::Result;
use std::ptr::null;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_LOOPBACK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_FLAGS_ALL_SET;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_RANGE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_RANGE_TYPE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_RANGE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT32;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_FLAGS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterCreateEnumHandle0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDestroyEnumHandle0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterEnum0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFreeMemory0;
use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

// Low 16 bits identify the first port of a blocked interval. The preceding
// bytes identify address family and protocol. Keep these identities stable.
const KEY_PREFIX: GUID = GUID::from_u128(/*uuid*/ 0xe2f397d3_307f_41e8_8b5d_140000000000);

/// Installs the configured offline account's loopback restrictions atomically.
/// Called only by the elevated setup helper, alongside the ordinary firewall rules.
pub fn install_loopback_filters_for_account(
    account: &str,
    settings: &WindowsSandboxProvisioningSettings,
) -> Result<usize> {
    let engine = Engine::open(INFINITE)?;
    let mut transaction = engine.begin_transaction()?;
    ensure_provider(engine.handle)?;
    ensure_sublayer(engine.handle)?;
    remove_filters(engine.handle)?;
    let mut installed = 0;
    if !settings.allow_local_binding {
        let user = UserMatchCondition::for_account(account)?;
        let blocked_ports = blocked_tcp_ports(&settings.proxy_ports);
        for (family, layer) in [
            (4, FWPM_LAYER_ALE_AUTH_CONNECT_V4),
            (6, FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        ] {
            for (protocol, ranges) in [
                (IPPROTO_TCP as u8, blocked_ports.as_slice()),
                (IPPROTO_UDP as u8, &[(0, u16::MAX)][..]),
            ] {
                for &(first, last) in ranges {
                    let mut key = KEY_PREFIX;
                    key.data4[4] = family;
                    key.data4[5] = protocol;
                    key.data4[6..].copy_from_slice(&first.to_be_bytes());
                    let spec = FilterSpec {
                        key,
                        name: "codex_wfp_loopback_block",
                        description: "Block offline sandbox loopback outside configured proxy ports",
                        layer_key: layer,
                        conditions: &[],
                    };
                    let mut ports = FWP_RANGE0 {
                        valueLow: FWP_VALUE0 {
                            r#type: FWP_UINT16,
                            Anonymous: FWP_VALUE0_0 { uint16: first },
                        },
                        valueHigh: FWP_VALUE0 {
                            r#type: FWP_UINT16,
                            Anonymous: FWP_VALUE0_0 { uint16: last },
                        },
                    };
                    let mut conditions = build_conditions(
                        &[ConditionSpec::User, ConditionSpec::Protocol(protocol)],
                        &user,
                    );
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_FLAGS,
                        matchType: FWP_MATCH_FLAGS_ALL_SET,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                            },
                        },
                    });
                    conditions.push(FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                        matchType: FWP_MATCH_RANGE,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_RANGE_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                rangeValue: &mut ports,
                            },
                        },
                    });
                    add_filter_with_conditions(engine.handle, &spec, &mut conditions)?;
                    installed += 1;
                }
            }
        }
    }
    transaction.commit()?;
    Ok(installed)
}

fn blocked_tcp_ports(allowed: &[u16]) -> Vec<(u16, u16)> {
    let mut allowed = allowed.to_vec();
    allowed.sort_unstable();
    allowed.dedup();
    let mut first = 1_u32;
    let mut blocked = Vec::new();
    for port in allowed {
        let port = u32::from(port);
        if first < port {
            blocked.push((first as u16, (port - 1) as u16));
        }
        first = first.max(port + 1);
    }
    if first <= u32::from(u16::MAX) {
        blocked.push((first as u16, u16::MAX));
    }
    blocked
}

pub(super) fn remove_filters(engine: HANDLE) -> Result<()> {
    let mut enumeration = HANDLE::default();
    ensure_success(
        unsafe { FwpmFilterCreateEnumHandle0(engine, null(), &mut enumeration) },
        "FwpmFilterCreateEnumHandle0(loopback)",
    )?;
    let result: Result<()> = (|| {
        let prefix = WindowsSandboxProduct::current().wfp_key(KEY_PREFIX);
        let mut keys = Vec::new();
        loop {
            let mut entries = null_mut();
            let mut count = 0;
            ensure_success(
                unsafe {
                    FwpmFilterEnum0(
                        engine,
                        enumeration,
                        /*numentriesrequested*/ 256,
                        &mut entries,
                        &mut count,
                    )
                },
                "FwpmFilterEnum0(loopback)",
            )?;
            for index in 0..count as usize {
                let key = unsafe { (**entries.add(index)).filterKey };
                if key.data1 == prefix.data1
                    && key.data2 == prefix.data2
                    && key.data3 == prefix.data3
                    && key.data4[..4] == prefix.data4[..4]
                {
                    keys.push(key);
                }
            }
            unsafe { FwpmFreeMemory0((&raw mut entries).cast()) };
            if count == 0 {
                break;
            }
        }
        // Enumeration is a snapshot; collect before deleting any members.
        for key in keys {
            delete_filter_if_present(engine, &key)?;
        }
        Ok(())
    })();
    let closed = unsafe { FwpmFilterDestroyEnumHandle0(engine, enumeration) };
    result?;
    ensure_success(closed, "FwpmFilterDestroyEnumHandle0(loopback)")
}

#[cfg(test)]
#[path = "loopback_tests.rs"]
mod tests;
