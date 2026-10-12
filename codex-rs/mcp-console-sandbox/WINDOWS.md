# Windows native sandbox

The Windows executable uses the existing Windows sandbox implementation without `codex-core` or a running Codex application. It supports explicit `setup` and `status` and uses Console's environment transport for all execution.

The public backend names are `elevated` and `unelevated`, in the JSON `windows_sandbox_level` field. Elevated setup requires administrator approval and creates dedicated sandbox accounts; commands do not run as administrator. Unelevated runs under the current user's restricted token without administrator setup. The former `restricted-token` spelling is no longer accepted.

## Build and distribute

Install Rust 1.95.0 with the `x86_64-pc-windows-msvc` toolchain, Visual Studio C++ build tools, a Windows SDK, and CMake. From `codex-rs`:

```powershell
cargo build --locked --release -p mcp-console-sandbox -p mcp-console-sandbox-windows --bin mcp-console-sandbox --bin mcp-console-sandbox-setup --bin mcp-console-sandbox-runner
just test --locked --release -p mcp-console-sandbox --retries 0
```

Distribute `mcp-console-sandbox.exe`, `mcp-console-sandbox-setup.exe`, and `mcp-console-sandbox-runner.exe` together. The additive `mcp-console-sandbox-windows` package registers the helpers and reuses the existing setup and command-runner implementations with Console's product identity. Only the main executable is needed by the unelevated backend.

For debug builds omit `--release`. Cargo output remains `target/debug` or `target/release`, and the distribution layout is unchanged.

For local Bazel builds, start an **x64 Visual Studio Developer PowerShell** and run from the repository root. Install Git for Windows and use its Bash executable explicitly (adjust the path if installed elsewhere). Use a short, writable output directory reserved for this checkout. Match upstream CI's MSVC host platform and forward its Windows SDK environment. The existing test toolchain allows GNU LLVM test executables to run on the MSVC host:

```powershell
$env:BAZEL_SH = "$env:ProgramFiles/Git/bin/bash.exe"
$windowsBazel = @(
    '--host_platform=//:local_windows_msvc',
    '--platforms=//:local_windows',
    '--workspace_status_command=./scripts/workspace-status.cmd',
    '--extra_toolchains=//:windows_gnullvm_tests_on_msvc_host_toolchain',
    "--shell_executable=$env:BAZEL_SH"
)
foreach ($name in @(
    'INCLUDE', 'LIB', 'LIBPATH', 'PATH', 'UCRTVersion',
    'UniversalCRTSdkDir', 'VCINSTALLDIR', 'VCToolsInstallDir',
    'WindowsLibPath', 'WindowsSdkBinPath', 'WindowsSdkDir',
    'WindowsSDKLibVersion', 'WindowsSDKVersion'
)) {
    if ([Environment]::GetEnvironmentVariable($name)) {
        $windowsBazel += "--action_env=$name", "--host_action_env=$name"
    }
}
bazel --output_base=C:/b/cobox --noexperimental_remote_repo_contents_cache build @windowsBazel //codex-rs/mcp-console-sandbox:mcp-console-sandbox //codex-rs/mcp-console-sandbox-windows:mcp-console-sandbox-setup //codex-rs/mcp-console-sandbox-windows:mcp-console-sandbox-runner
bazel --output_base=C:/b/cobox --noexperimental_remote_repo_contents_cache test @windowsBazel --test_env=PATH --test_arg=--test-threads=1 //codex-rs/mcp-console-sandbox:windows-cli-test //codex-rs/mcp-console-sandbox:windows-console-test //codex-rs/mcp-console-sandbox:windows-native-test //codex-rs/mcp-console-sandbox:windows-lifecycle-test
```

`local_windows` keeps the GNU LLVM target ABI; `local_windows_msvc` selects the ABI required by the Windows-hosted Rust compiler's proc-macros and build tools. A bare Windows Bazel invocation defaults the host to GNU LLVM, causing Rust to reject proc-macro DLLs such as `time_macros` with `E0463`. This is a build configuration mismatch, not a missing crate or a reason to patch its source. Short output paths also avoid the Windows linker path-length failure. Select the `.cmd` workspace-status script explicitly so `cmd.exe` does not try to open the `.sh` script through Windows file associations. These local settings mirror the existing upstream CI setup without changing shared Bazel defaults. The ordinary Bazel tests skip the two opt-in elevated network cases; run those against explicitly provisioned state using the Cargo recipe below.

Stage the three executables from those targets together under their existing names. The setup manifest retains `asInvoker`; elevation is explicitly requested by the native setup launcher. The command runner retains the Windows GUI subsystem. See [INTEGRATION.md](INTEGRATION.md#windows-integration) for module and resource resolution.

## Explicit setup

Run from an ordinary interactive PowerShell session:

```powershell
.\target\release\mcp-console-sandbox.exe setup
.\target\release\mcp-console-sandbox.exe status
```

Explicit setup requests Windows UAC approval and refreshes the existing accounts and records. Status prints JSON and exits zero when current records, enabled accounts, and adjacent helpers are present. It is a readiness check, not an audit of every firewall rule or managed-proxy slot.

Setup version 6 also installs account-scoped WFP loopback filters. Older installations need one approved setup refresh. Installation must succeed before setup records are committed. The filters preserve the native proxy-port exceptions and local-binding setting; uninstall removes them with the other product-specific WFP objects.

The launcher creates `.sandbox-bin` as the caller before elevation, so ordinary launches can refresh its protected DACL. An older installation whose helper directory is administrator-owned can fail with `helper_sandbox_lock_failed`; it needs an ownership repair before ordinary launches will work.

State defaults to `%LOCALAPPDATA%\mcp-console`; `setup` and `status` accept an absolute `--state-dir`. Use one stable state directory per Windows user. Accounts and network policy are machine resources, so separate directories are not independent installations. Existing Codex accounts, firewall rules, and WFP identifiers retain their names. Another product's account records are rejected.

Console display names are **McpConsoleSandboxOffline** and **McpConsoleSandboxOnline**; login names are `McpConsoleSandboxOff` and `McpConsoleSandboxOn` to fit Windows' 20-character limit. Setup also uses `ConsoleSandboxUsers`, protected credentials in `.sandbox-secrets`, and versioned records under `.sandbox`.

## Console transport

`--config-env NAME -- COMMAND ...` consumes the unversioned configuration described in [PROTOCOL.md](PROTOCOL.md), with these platform fields and limits:

- `windows_sandbox_level` defaults to `elevated`. `unelevated` is explicit; `disabled` is rejected.
- Targets run on a private Windows desktop, matching upstream behavior, with Console-specific desktop names.
- `windows_state_dir` optionally selects an absolute persistent state directory.
- The elevated mode requires prior explicit setup. Ordinary launches fail with setup guidance when accounts are missing.
- Unelevated execution requires `network: enabled`, host reads, and no read-deny policies. It does not provide OS-enforced network isolation or a read allowlist boundary. Selected write operations are restricted, but the deletion boundary failed native validation; see the limits below.
- Profiles use the same native constructors and workspace metadata defaults as Unix. Unsupported policy fails before launching the target.
- Managed HTTP/HTTPS CONNECT and SOCKS5 TCP use the same domain and full/limited policy as Unix, with the ownership and capability limits below. Custom cleanup timeouts, macOS policy extensions, and Linux backend selection are rejected. `--bootstrap-fd` is Unix-only.
- The selected configuration and reserved transport variable are removed from the target environment case insensitively. Excluded variables cannot be reused as private temporary environment names.

The ordinary command arguments, cwd, and stdio remain the target's inputs. Environment inheritance and overrides retain the shared protocol rules. Private storage grants its data directory and can export `TMPDIR`, `TEMP`, and `TMP`.

## Managed proxy ownership

Run the adjacent, matching binaries from this revision, then explicitly refresh the same state directory:

```powershell
.\mcp-console-sandbox.exe setup --managed-proxy
.\mcp-console-sandbox.exe status
```

This is one UAC request for the complete pool: the elevated Console setup helper provisions the base accounts and launches its four slot setup operations without further elevation. Ordinary launches never invoke UAC, repair accounts, alter proxy ports/local-access policy, or fall back to unelevated execution. Missing accounts, stale setup records, failed logon, a missing pool marker, foreign ownership, occupied ports, and exhausted/quarantined slots fail with diagnostics. An existing plain `setup` installation needs this explicit refresh. Explicit `setup` refreshes records even when accounts still exist, so it can repair stale passwords; `status` never changes them. `managed_proxy_provisioned` reports the matching completed pool marker and owner, not current free-slot capacity or a live account health probe. Future changes to the fixed pool contract require a new pool marker before admission. Ship all three binaries together; workload environment overrides never choose these helpers.

The bounded pool contains four account pairs (`McpConsoleProxyOff0`/`McpConsoleProxyOn0` through `3`) and TCP ports 43180–43187. Slots 0–1 deny local access; slots 2–3 permit it. Each companion leases one matching slot and uses Codex's existing shared Windows ingress for its HTTP/SOCKS pair, even when SOCKS service is disabled. The ingress is shared within that companion process only. There is capacity for two concurrent sessions per local-access setting. Domain rules, mode and route identity remain private to that companion. Proxyless restricted execution uses the base offline account with no proxy exceptions. Accounts, helper names, WFP identifiers and locks are separate from Codex. Every Console account belongs to the common secrets-deny group; slot groups retain their other native roles.

`allowLocalBinding: false` blocks direct IPv4/IPv6 TCP and UDP, loopback connects, TCP listeners and UDP receive admission. Explicitly allowed local destinations remain reachable through the managed proxy. True permits native loopback traffic and listeners; these direct local channels do not have domain filtering. External direct traffic remains blocked by the offline identity. Every Console account is forbidden from binding TCP ports 43180–43187, preventing a workload from impersonating a retired companion. A proxy connection must carry both its registered restricting SID and the owning dedicated account SID. A copied endpoint or forged route SID under another account cannot borrow policy.

The public proxy object is `RemoteNetworkProxyConfig`. Full mode supports HTTP methods, CONNECT and SOCKS5 TCP; limited mode allows GET/HEAD/OPTIONS and rejects POST, CONNECT and SOCKS. Explicit denials take precedence. `enableSocks5Udp: true`, nonempty Unix-socket maps and `dangerouslyAllowAllUnixSockets: true` fail before launching a workload. HTTP/CONNECT upstream proxy selection uses the trusted companion environment; SOCKS keeps the existing direct connector. Managed environment values replace workload values case insensitively. The unversioned transport adds no listener/account selection fields.

An administrator-protected HKLM ownership record binds the pool to one Windows user and canonical state directory. A cross-process admission mutex serializes setup and leasing. Atomic creation of `.sandbox-secrets/proxy-slot-N.lease` claims the slot; the same durable file prevents automatic reuse after an owner disappears. There is no second per-slot lock or lease registry. Setup refuses outstanding leases. The native runner obtains the trusted proxy observer SID from that protected owner record, without an extra launch-protocol field.

The companion supplies its provisioned URLs through the existing proxy configuration APIs and checks the actual bound ports before registering a route or launching the workload. If Codex's listener allocator chooses a fallback, admission fails; the companion never reconciles firewall rules to it. Native setup records must match the slot before launch, then Codex's `Preserve` mode retains those settings. After native Job retirement, the companion stops the route, drops its entire Tokio runtime, removes private storage, verifies listener closure and removes the lease. Runtime teardown is required because upstream shared ingress retains listeners for the host process lifetime; route shutdown alone does not close them. Any failure prevents a successful receipt and retains the slot quarantine.

The account pool is the remaining adaptation to Console's process model. Sharing an account between independent companions would share firewall settings and let a copied restricting SID borrow another route under that account. A shared proxy host would need an additional authenticated session protocol and coordinated retirement, and still need distinct account-wide local-access policies. This implementation retains native account provisioning and native Job ownership rather than introducing that host. Four slots are a bounded product choice, not an upstream requirement; increasing capacity requires an explicit setup contract update. Protocol parsing, domain/method policy, HTTP/SOCKS services, listener allocation, environment projection and route retirement remain in Codex.

There is deliberately no force-reclaim command. Never remove a lease merely because its companion PID disappeared: native retirement and cleanup may still be pending. For crash recovery, stop Console, reboot Windows to establish that old Jobs and listeners are gone, clean up the retained private directories identified in diagnostics, and remove only the corresponding lease files from the registered state directory. Then run explicit setup if its marker is absent. Do not copy state, change the owner record, or delete the whole state directory to bypass quarantine. An unrelated unrestricted process running as the trusted host user or an administrator remains outside this workload threat model.

Opt-in acceptance uses provisioned dedicated accounts and the public environment transport, not only restricted-token proxy unit tests:

```powershell
$env:MCP_CONSOLE_SANDBOX_TEST_STATE_DIR = "$env:LOCALAPPDATA\mcp-console"
# Optional non-loopback peer: accepts TCP and echoes UDP at this address.
$env:MCP_CONSOLE_SANDBOX_TEST_ECHO_ADDR = '192.0.2.2:44090'
just test --locked -p mcp-console-sandbox --test windows_proxy --run-ignored ignored-only --test-threads 1 --retries 0 --success-output immediate
```

Replace the example echo address with a reachable controlled peer or omit it; unavailable external controls are reported explicitly. UDP echo assertions check round trips only; proving external UDP egress is blocked requires receiver-side observation at that peer, which the suite reports as unestablished. Run acceptance serially against an idle pool. Tests never provision accounts. The adversarial cleanup tests independently observe their known fixture processes before removing their own deliberately retained leases; production launch has no such reclaim path. See [recorded validation](WINDOWS_PROXY_VALIDATION.md) for actual results and unavailable coverage.

## Command interface

Run `--help` for `setup` and `status`. Execute workloads only with `--config-env NAME -- command [args...]`. The former `run` subcommand and its permission, environment, root-override, proxy, and desktop arguments are removed; they fail with a CLI diagnostic and exit 2. They are not mapped onto JSON fields. The shared configuration has no version field; cwd comes from the caller, environment follows its inheritance/override rules, and policy uses its existing profile and filesystem fields. Target arguments after `--` pass through unchanged, including names that used to be runner options. Ordinary launches require explicit initial provisioning for elevated mode.

Targets still need host read/traverse permission. In particular, Python 3.14's private temporary directories can grant access only through owner/admin/system ACL entries that a restricted token cannot use. Ordinary directories inheriting the current user's access work without machine-wide ACL changes. Use native Windows paths with backslashes for `cmd.exe`. Targets also remain subject to host Application Control policy; error 4551 is a host policy rejection.

Console launches save capability mappings in `.sandbox-secrets/cap_sid`; elevated setup denies every Console account access to these records. This revision creates fresh protected mappings rather than trusting old unprotected `cap_sid` files. Capability ACL entries persist on filesystem objects; deleting the state directory does not undo them. Elevated launches use provisioned accounts and refresh workspace ACLs. Backend upgrades or network-setting changes can require administrator repair.

## Lifecycle

Console's pipe-launched workloads enter a non-breakaway Job at process creation. After normal root exit, timeout, or cancellation, the backend terminates remaining members and confirms zero active processes before returning an exit receipt. A native Job completion port wakes the waiter; an accounting query confirms the barrier, with a five-second cleanup allowance. A missing native retirement receipt returns exit code 125 without claiming cleanup. Genuine target exit codes, including 125 and -1, remain distinct internally and permit cleanup only when a receipt exists. A missing exit receipt is distinct from a target exit code of `0xffffffff` (`-1`). Codex's default product continues to preserve descendants after normal root exit.

The environment transport watches its direct caller and optional `lifecycle.parent_pid` owner through retained process handles. Owner death or Ctrl+C requests session termination. It removes private storage only after a confirmed receipt; startup errors and unconfirmed retirement retain storage with diagnostics. Private storage is not deleted while target descendants are known to remain. After confirmed Job retirement, storage removal retries Windows sharing violations for up to five seconds while file or image mappings finish releasing. Other errors and persistent sharing violations remain cleanup failures; no successful receipt is returned before removal completes.

Unelevated runner loss and elevated helper loss close kill-on-close Jobs. Runner loss does not guarantee storage deletion. A forcibly killed waiting Console frontend is not evidence of completed native retirement and cannot admit a replacement. Windows console signals and desktop behavior are not Unix terminal semantics.

## Validation limits

The [2026-10-06 footprint validation](WINDOWS_FOOTPRINT_2026_10_06.md) records the current builds, runtime checks, restored files, counts, and provisioning/Bazel limits.

The public environment-transport regression exercises unelevated policy, private storage, environment exclusion, unsupported configuration, and 32-bit exit codes. Native fixture contracts exercise binary stdin, denied file creation, descendant retirement before storage removal, caller death, and runner loss. CLI regressions cover setup/status path validation; transport regressions cover JSON/path validation and exact target argument forwarding. Rejection of the removed CLI was verified separately during the migration, without retaining a test for unsupported options. Elevated account provisioning needs an interactive administrator setup. After setup, the opt-in network regression can be run with:

```powershell
just test --locked -p mcp-console-sandbox --retries 0 --run-ignored only -E 'test(elevated_offline_account_denies_loopback_)'
```

The TCP and UDP tests use host listeners and a compiled target fixture on IPv4 and IPv6. Each verifies online connectivity first, then requires the offline account to be blocked. UDP checks actual receipt because a successful send does not establish delivery. For a nondefault provisioned directory, set `MCP_CONSOLE_SANDBOX_TEST_STATE_DIR` to its absolute path; this supplies `windows_state_dir` without changing the test harness's `LOCALAPPDATA`. The tests do not provision accounts. Linux/macOS lifecycle suites remain separate platform coverage.

On the Windows host tested on 2026-10-02, the unelevated backend allowed deletion outside the writable roots, including with the `:read-only` profile. The upstream `legacy_workspace_write_delete_is_limited_to_writable_roots` test also failed at the unmodified `rust-v0.154.0` release. Successful file-creation denial does not establish deletion isolation. This is an unresolved native enforcement limitation, not a passing security gate; this branch does not replace the upstream token/ACL model to conceal the failure.

Before the WFP correction, the elevated offline account connected to loopback listeners despite enabled firewall profiles and installed Console rules. Account-scoped filters at the ALE connect layers now enforce the existing offline loopback policy. After an approved setup refresh, the IPv4/IPv6 TCP and UDP regressions passed with online positive controls. External offline TCP remained blocked. Elevated stdio, exit codes, denied file creation, descendant retirement, caller death, and private cleanup also passed. The [dated audit](VALIDATION_2026_10_02.md) records the complete scope.

Direct comparison with the installed official `codex-cli 0.160.0` reproduced the original loopback connection and unelevated deletion failures. After the correction, the official executable still delivered offline loopback TCP/UDP while Console blocked them. Both elevated implementations denied external TCP connections and protected files in a directory whose ACL gave sandbox accounts read/execute access. Both allowed deletion in the Public directory's broadly writable inherited ACLs. These results distinguish native backend and host-ACL limits from extraction differences; they do not certify the remaining deletion boundary. The extraction's disabled private-desktop default was a separate defect and is corrected with executable desktop-identity tests.

The upstream control-pipe regression invokes `python` by name. On this host the Windows app execution alias started a descendant outside the tested Job; placing the actual Python installation on the test process's `PATH` made the same test pass. The standalone lifecycle contracts use the compiled fixture directly.
