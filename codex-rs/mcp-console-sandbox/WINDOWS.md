# Windows native sandbox

The Windows executable uses the existing Windows sandbox implementation without `codex-core` or a running Codex application. It supports explicit `setup` and `status`, native `run` options, and Console's versioned environment transport.

The public backend names are `elevated` and `unelevated`, for both `--windows-sandbox-level` and the JSON `windows_sandbox_level` field. Elevated setup requires administrator approval and creates dedicated sandbox accounts; commands do not run as administrator. Unelevated runs under the current user's restricted token without administrator setup. The former `restricted-token` spelling is no longer accepted.

## Build and distribute

Install Rust 1.95.0 with the `x86_64-pc-windows-msvc` toolchain, Visual Studio C++ build tools, a Windows SDK, and CMake. From `codex-rs`:

```powershell
cargo build --locked --release -p codex-mcp-console-sandbox -p codex-windows-sandbox --bin mcp-console-sandbox --bin mcp-console-sandbox-setup --bin mcp-console-sandbox-runner
just test --locked --release -p codex-mcp-console-sandbox --retries 0
```

Distribute `mcp-console-sandbox.exe`, `mcp-console-sandbox-setup.exe`, and `mcp-console-sandbox-runner.exe` together. The helpers reuse the existing setup and command-runner implementations with Console's product identity. Only the main executable is needed by the unelevated backend.

## Explicit setup

Run from an ordinary interactive PowerShell session:

```powershell
.\target\release\mcp-console-sandbox.exe setup
.\target\release\mcp-console-sandbox.exe status
```

Setup requests Windows UAC approval when provisioning is needed. Repeating it reuses current setup records and enabled accounts. Status prints JSON and exits zero when current records, enabled accounts, and adjacent helpers are present. It is a readiness check, not an audit of every firewall rule.

Setup version 6 also installs account-scoped WFP loopback filters. Older installations need one approved setup refresh. Installation must succeed before setup records are committed. The filters preserve the native proxy-port exceptions and local-binding setting; uninstall removes them with the other product-specific WFP objects.

The launcher creates `.sandbox-bin` as the caller before elevation, so ordinary launches can refresh its protected DACL. An older installation whose helper directory is administrator-owned can fail with `helper_sandbox_lock_failed`; it needs an ownership repair before ordinary launches will work.

State defaults to `%LOCALAPPDATA%\mcp-console`; native commands accept an absolute `--state-dir`. Use one stable state directory per Windows user. Accounts and network policy are machine resources, so separate directories are not independent installations. Existing Codex accounts, firewall rules, and WFP identifiers retain their names. Another product's account records are rejected.

Console display names are **McpConsoleSandboxOffline** and **McpConsoleSandboxOnline**; login names are `McpConsoleSandboxOff` and `McpConsoleSandboxOn` to fit Windows' 20-character limit. Setup also uses `ConsoleSandboxUsers`, protected credentials in `.sandbox-secrets`, and versioned records under `.sandbox`.

## Versioned Console transport

`--config-env NAME -- COMMAND ...` consumes protocol version 2 as described in [PROTOCOL.md](PROTOCOL.md), with these platform fields and limits:

- `windows_sandbox_level` defaults to `elevated`. `unelevated` is explicit; `disabled` is rejected.
- Targets run on a private Windows desktop, matching Codex's default. Native `run` also defaults to a private desktop; `--windows-sandbox-private-desktop=false` explicitly opts out.
- `windows_state_dir` optionally selects an absolute persistent state directory.
- The elevated mode requires prior explicit setup. Ordinary versioned launches fail with setup guidance when accounts are missing.
- Unelevated execution requires `network: enabled`, host reads, and no read-deny policies. It does not provide OS-enforced network isolation or a read allowlist boundary. Selected write operations are restricted, but the deletion boundary failed native validation; see the limits below.
- Profiles use the same native constructors and workspace metadata defaults as Unix. Unsupported policy fails before launching the target.
- Managed proxy configuration, custom cleanup timeouts, macOS policy extensions, and Linux backend selection are rejected. `--bootstrap-fd` is Unix-only.
- The selected configuration and reserved transport variable are removed from the target environment case insensitively. Excluded variables cannot be reused as private temporary environment names.

The ordinary command arguments, cwd, and stdio remain the target's inputs. Environment inheritance and overrides retain the shared protocol rules. Private storage grants its data directory and can export `TMPDIR`, `TEMP`, and `TMP`.

## Native CLI

Run `--help` or `run --help` for the typed native options. `run` consumes a serialized `PermissionProfile` and explicit environment map rather than a versioned request. The command must follow `--`; target flags pass through unchanged. Clap syntax errors exit 2 before setup or launch. Paths and JSON are validated at that boundary. The native CLI retains the upstream setup/repair behavior; versioned Console launches require explicit initial provisioning.

Targets still need host read/traverse permission. In particular, Python 3.14's private temporary directories can grant access only through owner/admin/system ACL entries that a restricted token cannot use. Ordinary directories inheriting the current user's access work without machine-wide ACL changes. Use native Windows paths with backslashes for `cmd.exe`. Targets also remain subject to host Application Control policy; error 4551 is a host policy rejection.

Unelevated launches create capability SIDs and save mappings in `cap_sid`. Capability ACL entries persist on filesystem objects; deleting the state directory does not undo them. Elevated launches use provisioned accounts and refresh workspace ACLs. Backend upgrades or network-setting changes can require administrator repair.

## Lifecycle

Console's pipe-launched workloads enter a non-breakaway Job at process creation. After normal root exit, timeout, or cancellation, the backend terminates remaining members and confirms zero active processes before returning an exit receipt. A native Job completion port wakes the waiter; an accounting query confirms the barrier, with a five-second cleanup allowance. Failure uses reserved exit code 125. A missing exit receipt is distinct from a target exit code of `0xffffffff` (`-1`). Codex's default product continues to preserve descendants after normal root exit.

The versioned transport watches its direct caller and optional `lifecycle.parent_pid` owner through retained process handles. Owner death or Ctrl+C requests session termination. It removes private storage only after a confirmed receipt; startup errors and unconfirmed retirement retain storage with diagnostics. Private storage is not deleted while target descendants are known to remain.

Unelevated runner loss and elevated helper loss close kill-on-close Jobs. Runner loss does not guarantee storage deletion. A forcibly killed waiting Console frontend is not evidence of completed native retirement and cannot admit a replacement. Windows console signals and desktop behavior are not Unix terminal semantics.

## Validation limits

The public versioned-transport regression exercises unelevated policy, private storage, environment exclusion, unsupported configuration, and 32-bit exit codes. Native fixture contracts exercise binary stdin, denied file creation, descendant retirement before storage removal, caller death, and runner loss. CLI regressions cover typed validation and target argument forwarding. Elevated account provisioning needs an interactive administrator setup. After setup, the opt-in network regression can be run with:

```powershell
just test --locked -p codex-mcp-console-sandbox --retries 0 --run-ignored only -E 'test(elevated_offline_account_denies_loopback_)'
```

The TCP and UDP tests use host listeners and a compiled target fixture on IPv4 and IPv6. Each verifies online connectivity first, then requires the offline account to be blocked. UDP checks actual receipt because a successful send does not establish delivery. The tests do not provision accounts. Linux/macOS lifecycle suites remain separate platform coverage.

On the Windows host tested on 2026-10-02, the unelevated backend allowed deletion outside the writable roots, including with the `:read-only` profile. The upstream `legacy_workspace_write_delete_is_limited_to_writable_roots` test also failed at the unmodified `rust-v0.154.0` release. Successful file-creation denial does not establish deletion isolation. This is an unresolved native enforcement limitation, not a passing security gate; this branch does not replace the upstream token/ACL model to conceal the failure.

Before the WFP correction, the elevated offline account connected to loopback listeners despite enabled firewall profiles and installed Console rules. Account-scoped filters at the ALE connect layers now enforce the existing offline loopback policy. After an approved setup refresh, the IPv4/IPv6 TCP and UDP regressions passed with online positive controls. External offline TCP remained blocked. Elevated stdio, exit codes, denied file creation, descendant retirement, caller death, and private cleanup also passed. The [dated audit](VALIDATION_2026_10_02.md) records the complete scope.

Direct comparison with the installed official `codex-cli 0.160.0` reproduced the original loopback connection and unelevated deletion failures. After the correction, the official executable still delivered offline loopback TCP/UDP while Console blocked them. Both elevated implementations denied external TCP connections and protected files in a directory whose ACL gave sandbox accounts read/execute access. Both allowed deletion in the Public directory's broadly writable inherited ACLs. These results distinguish native backend and host-ACL limits from extraction differences; they do not certify the remaining deletion boundary. The extraction's disabled private-desktop default was a separate defect and is corrected with executable desktop-identity tests.

The upstream control-pipe regression invokes `python` by name. On this host the Windows app execution alias started a descendant outside the tested Job; placing the actual Python installation on the test process's `PATH` made the same test pass. The standalone lifecycle contracts use the compiled fixture directly.
