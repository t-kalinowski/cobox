# Windows managed proxy validation, 2026-10-12

This is an implementation candidate, **not completed dedicated-account acceptance**.
Do not enable Console's Windows proxy admission solely on the passing restricted-token
or ordinary package tests. The final elevated refresh was canceled by Windows (1223),
and no further provisioning attempts were made. The user's authorization had already
been granted; the repeated prompts came from the original per-account implementation.
Setup now batches the base identity and four slots under one elevation. That revised
setup path has compiled but has not completed on this machine.

## Branch and verified starting point

Work is confined to `t-kalinowski/cobox`, branch `console/windows-managed-proxy`,
based on `e9ca3f338136c185154f873ac7082f7b200fd71e`.
Console's supplied pin `42322a3931c2feeab838351e41d8048b1de8eb62` is an ancestor.
The actual baseline still rejected every Windows proxy configuration, used JSON Value
instead of the typed proxy configuration on Windows, and omitted Windows proxy preparation.
The existing Windows ingress/attribution machinery and native offline proxy-port exceptions
were present. Account-wide firewall settings and process-local shared ingress did not
provide ownership across separate companions.

## Executed commands and results

Commands below ran in `codex-rs`, except the Bazel lock command at the repository root.
This machine used Rust 1.95.0/MSVC, bundled Python on PATH, and
`CARGO_TARGET_DIR=C:/Users/kalin/.cache/mcp-console/cobox-target`.

| Command / checkpoint | Actual result |
| --- | --- |
| Initial public `windows_proxy` regression before implementation | Failed on the existing blanket Windows proxy rejection. |
| `cargo check --locked -p mcp-console-sandbox --tests` | Passed during implementation. |
| `cargo build --locked -p mcp-console-sandbox -p mcp-console-sandbox-windows --bins` | Passed on the final implementation before formatting/lint fixes. |
| `just test --locked -p mcp-console-sandbox -p mcp-console-sandbox-windows -p codex-network-proxy --retries 0` | 334 passed, 16 skipped, 9.002 s; run `86f690f1-f2f1-4c35-b038-24a292a4ef30`. Includes public environment projection/validation and native unelevated retirement tests. The 16 skips are 14 managed-proxy acceptance cases and 2 existing elevated offline network cases. |
| `just test --locked -p mcp-console-sandbox -p mcp-console-sandbox-windows -p codex-network-proxy -p codex-windows-sandbox --retries 0` | Earlier combined run: 598 run, 594 passed, 3 failed, 1 timeout, 17 skipped; run `89f27d3c-43cd-4048-8593-75f6170b3ef8`. Failures detailed below. |
| `just test --locked -p codex-windows-sandbox --lib -E 'not test(elevated_non_tty_cmd_forwards_env_output_and_exit) and not test(legacy_capture_cancellation_terminates_descendants_without_timeout) and not test(legacy_workspace_write_delete_is_limited_to_writable_roots)' --retries 0` | 258 passed, 1 fixture expectation failed, 8 skipped; run `080834bc-c472-4178-8192-b3277a9e31bf`. |
| `just test --locked -p codex-windows-sandbox --lib -E 'test(credential_setup_reconciles_policy_and_repairs_accounts)' --retries 0` | Passed after fixing the fixture to use actual product account names and compare the selected name; run `3fc5ee6a-e623-47e0-9ecc-e911c4c954d1`. This is a mocked credential setup test and does not establish dedicated-account enforcement. |
| `just bazel-lock-update` | Passed; `MODULE.bazel.lock` did not change. Invocation `13923a59-ca4a-4f7d-8ef8-c7383e441cff`. |
| `just fix -p mcp-console-sandbox -p mcp-console-sandbox-windows -p codex-network-proxy -p codex-windows-sandbox` | Passed. Two test-helper unwrap warnings from the first pass were corrected; the final pass completed without warnings. |
| `just fmt` | Passed. Unrelated Starlark CRLF rewrites from the formatter were inspected and restored; the feature's Cargo and Bazel sources remain formatted. Tests were not rerun after lint/format, following repository instructions. |
| `mcp-console-sandbox.exe status` | Final read-only check: `configured=true`, `helpers_available=true`, `managed_proxy_provisioned=false`. |

The native failures were:

- `legacy_capture_cancellation_terminates_descendants_without_timeout`: exceeded its
  10-second bound; an isolated rerun also failed at 14.664 seconds. Not fixed here.
- `legacy_workspace_write_delete_is_limited_to_writable_roots`: the unelevated deletion
  boundary failed. This limitation was already recorded in the existing Windows footprint
  documentation; this work does not claim to repair it.
- `credential_setup_reconciles_policy_and_repairs_accounts`: its invented `offline`/`online`
  names conflicted with the existing product identity guard. The corrected fixture passed.
- `elevated_non_tty_cmd_forwards_env_output_and_exit`: timed out at 60 seconds while using
  fresh Codex provisioning. It was not retried; it is not Console pool acceptance.

An earlier, smaller version of the dedicated-account suite passed 8 tests in 31.644 seconds
(run `be94a0d3-eac7-4a14-9a14-949434212193`). Those results precede the strict listener/UDP
receive guards, capability-store protection, receipt-adapter correction, TLS and forged-SID
tests. They **do not validate the final revision**. A new local TCP binding assertion then
failed (run `aea25c18-ce9a-42b5-8b46-27225af73f19`), demonstrating the missing native listen
restriction. The new WFP guards require the uncompleted setup refresh.

Two earlier per-identity setup runs completed. The subsequent consolidated setup attempts
returned Windows error 1223. The incomplete pool marker is intentionally absent, so ordinary
managed-proxy launches reject admission. Existing machine resources were not uninstalled.
No UAC dialog was pending when the final status check ran.

## Acceptance present but not established on the final revision

The ignored tests use the public unversioned `--config-env` transport and separately spawned
companions with the provisioned accounts. They cover:

- HTTP, CONNECT, SOCKS5 TCP, domain allow/deny precedence, limited GET versus POST/tunnels,
  authenticated TLS through CONNECT, and trusted HTTP/CONNECT upstream routing.
- Mixed-case hostile workload proxy values, independent policies and local-access classes,
  simultaneous proxyless restricted execution, other sessions' endpoints, forged restricting
  SIDs under both another sandbox account and the host account, and protected pool canaries
  even with an explicit write grant over the state directory.
- IPv4/IPv6 loopback TCP/UDP, actual UDP receipt, TCP listening and inbound UDP, with online
  and local-enabled positive controls; all reserved ingress-port bind attempts.
- Fixed-port conflicts, pool exhaustion, missing provisioning/capabilities, prelaunch failure,
  normal and nonzero exits, descendant retirement, owner-death cancellation, companion loss,
  native helper loss, blocked cleanup, quarantines and reuse of the exact retired slot.

External IPv4/IPv6 TCP cases report unavailable positive controls. Non-loopback UDP requires
`MCP_CONSOLE_SANDBOX_TEST_ECHO_ADDR`; run with controlled IPv4 and IPv6 peers separately.
A WSL IPv4 echo server had a successful host UDP control, but the final sandbox probe was
not run. External IPv6 and final native UDP enforcement are therefore not established.
An explicit Ctrl+C managed-proxy acceptance case and a transport variable whose name itself
collides with a projected proxy variable are not covered by the new suite. Owner death covers
the cancellation path, not delivery of the actual console signal. Linux/macOS runtime tests
and a Windows Bazel build/test were not run in this session.

## Review and delivery order

The full change, including added files, was reviewed against the branch baseline, with
focused security, integration/context, test, and size reviews. Findings corrected:

| Finding | Correction |
| --- | --- |
| Cross-slot capability-store tampering could borrow an identity | Console mappings moved into `.sandbox-secrets/cap_sid`; every Console account receives the common secrets-deny group; slot write grants exclude the pool. A public canary regression was added. |
| Generic PTY adaptation converted missing native receipts to `-1` | Console preserves receipt absence across the adapter and suppresses native Exit on failed retirement. |
| A confirmed target exit 125 looked like retirement failure | Receipt presence is retained separately from all 32-bit exit codes. |
| Prelaunch failures consumed durable slots | Lease drop rolls back before the native spawn boundary; post-spawn uncertainty remains quarantined. |
| Explicit setup could not repair stale account passwords | Explicit setup refreshes even when account records exist. |
| Slot recovery guidance referred only to plain setup | Managed-session diagnostics now point to `setup --managed-proxy` against the original base state directory. |
| Status overstated pool readiness | `managed_proxy_provisioned` reports the completed marker and registered owner; it makes no free-capacity/account-health claim. |
| Lifecycle tests could reuse a different slot or erase a quarantine without observing death | Tests derive the actual lease from the endpoint, assert exact-slot reuse, retain process handles, and serialize acceptance. Startup/reply/retirement waits are bounded. |

The feature exceeds the usual 800-line change guidance. Reviewable dependency stages are
native pool/provisioning and environment isolation; authenticated fixed ingress and native
receipt preservation; companion activation; network/lifecycle acceptance and documentation.
The first native stage is the smallest coherent prerequisite; it must remain dormant until
the companion and final dedicated-account acceptance ship together. No PR, publish, merge,
Console change, or resolver change was performed.

## Required setup and mcp-console follow-up

1. Ship matching companion, setup, and runner binaries together. From an ordinary interactive
   terminal, explicitly run `mcp-console-sandbox.exe setup --managed-proxy` with the existing
   state directory. Expect **one** UAC request. Do not automate setup during worker launch.
2. Run the serial acceptance recipe in [WINDOWS.md](WINDOWS.md#managed-proxy-ownership),
   including controlled external TCP/UDP peers and the untested signal case, before rollout.
3. In mcp-console, update the companion pin to the reviewed final cobox commit only after that
   acceptance succeeds. Enable Windows configuration admission for the supported capability
   set, retain rejection of UDP/Unix options, and retain the unversioned environment transport.
4. Surface setup-required, port-busy, pool-busy and quarantine diagnostics. Capacity is two
   strict and two local-enabled sessions; queue or report exhaustion without backend fallback.
   Treat failed cleanup as failed retirement, preserving replacement gating.
5. Keep resolver sandbox parity as a separate integration task. SOCKS uses the existing direct
   connector; trusted upstream selection applies to HTTP/CONNECT as on the existing runtime.

Recovery after unconfirmed retirement is deliberately manual and conservative; see
[WINDOWS.md](WINDOWS.md#managed-proxy-ownership). A disappearing companion PID does not
authorize deleting its lease or admitting a replacement.
