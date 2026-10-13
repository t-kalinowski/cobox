# Windows native sandbox

The Windows executable uses Codex's shared sandbox selection, policy transform, and launch APIs without `codex-core` or a running Codex application. It supports explicit `setup` and `status` and uses Console's environment transport for all execution.

The JSON `windows_sandbox_level` accepts `auto` (the default), `mxc`, `elevated`, and `unelevated`. Auto resolves target temporary-directory and private-storage grants, validates canonical protected-state exclusions, and prefers the native MXC process security environment when the complete policy is compatible; otherwise it selects elevated execution. An explicit mode is never changed after selection or launch failure. A new MXC-only installation needs no sandbox accounts, setup, or UAC. Existing unregistered legacy installations require explicit setup against their existing state directory before MXC can protect the credentials. Elevated setup requires administrator approval and creates dedicated sandbox accounts; commands do not run as administrator. Unelevated runs under the current user's restricted token without administrator setup. The former `restricted-token` spelling is no longer accepted.

Omitting this field previously selected elevated execution. Console must update its pinned companion and admission logic together: callers that require the legacy account backend must now pass `elevated` explicitly. The private transport remains unversioned. Resolver sandbox parity is separate work.

## Build and distribute

Install Rust 1.95.0 with the `x86_64-pc-windows-msvc` toolchain, Visual Studio C++ build tools, a Windows SDK, and CMake. From `codex-rs`:

```powershell
cargo build --locked --release -p mcp-console-sandbox -p mcp-console-sandbox-windows --bin mcp-console-sandbox --bin mcp-console-sandbox-setup --bin mcp-console-sandbox-runner
just test --locked --release -p mcp-console-sandbox --retries 0
```

Distribute `mcp-console-sandbox.exe`, `mcp-console-sandbox-setup.exe`, and `mcp-console-sandbox-runner.exe` together. The additive `mcp-console-sandbox-windows` package registers the helpers and reuses the existing setup and command-runner implementations with Console's product identity. Only the main executable is needed by MXC and the unelevated backend.

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

Explicit setup provisions or refreshes the base accounts and all four proxy account pairs under one Windows UAC approval. It reserves the protected owner, rotates credentials and marks pool completion only after every helper succeeds, enabling the legacy-to-MXC migration. Ordinary launches never perform this refresh. Status prints JSON and exits zero when current records, enabled accounts, and adjacent helpers are present. It is a readiness check, not an audit of every firewall rule.

Setup version 6 also installs account-scoped WFP loopback filters. Older installations need one approved setup refresh. Installation must succeed before setup records are committed. The filters preserve the native proxy-port exceptions and local-binding setting; uninstall removes them with the other product-specific WFP objects.

The launcher creates `.sandbox-bin` as the caller before elevation, so ordinary launches can refresh its protected DACL. An older installation whose helper directory is administrator-owned can fail with `helper_sandbox_lock_failed`; it needs an ownership repair before ordinary launches will work.

State defaults to `%LOCALAPPDATA%\mcp-console`; `setup` and `status` accept an absolute `--state-dir`. Use one stable state directory per Windows user. Accounts and network policy are machine resources, so separate directories are not independent installations. Existing Codex accounts, firewall rules, and WFP identifiers retain their names. Another product's account records are rejected.

Console display names are **McpConsoleSandboxOffline** and **McpConsoleSandboxOnline**; login names are `McpConsoleSandboxOff` and `McpConsoleSandboxOn` to fit Windows' 20-character limit. Setup also uses `ConsoleSandboxUsers`, protected credentials in `.sandbox-secrets`, and versioned records under `.sandbox`.

Console's native proxy-slot identity is selected once by the trusted launcher and passed directly to its helpers. Base and slot identities exclude write grants overlapping their pool state, including ancestors, and share a mandatory secrets-deny group. Required group enrollment errors fail setup instead of leaving an account outside that protection. Ordinary Console launches cannot repair or reconcile account provisioning automatically.

The native Console proxy-pool API additionally provisions four isolated account pairs with fixed ports and local-access settings. Pool setup claims its protected machine owner under the native setup lock before changing any base or slot account. A failed first setup keeps that owner registration so only the same user and state directory can retry. Completion requires the helper to return this invocation's random nonce in protected state after all four slots finish; an older adjacent helper or an earlier receipt cannot report success. A failing slot's diagnostic, index, and report path are also saved to the base setup report consumed by the launcher. Codex's setup version is unchanged. Replace Console's companion and both adjacent helpers together when upgrading. Companion transport admission for this pool is introduced separately in the stack.

Owner reservation does not admit MXC: a separate administrator-protected registry value stays pending during provisioning and becomes complete only after the helper's receipt is written. Failed first migrations and interrupted refreshes remain unavailable to host-identity launches; this prevents old, copied credentials from remaining usable outside the protected registered directory. Older registrations without completion tracking require one explicit setup refresh.

The opt-in native provisioning regression changes machine accounts and firewall rules. Run this multi-refresh acceptance from one explicitly approved elevated shell to avoid repeated UAC prompts. Build current Console helpers, put their directory on `PATH`, select the stable state directory explicitly, and run only after all Console workers have retired:

```powershell
cargo build --locked -p mcp-console-sandbox-windows
$helperDirectory = if ($env:CARGO_TARGET_DIR) { "$env:CARGO_TARGET_DIR\debug" } else { "$PWD\target\debug" }
$env:PATH = "$helperDirectory;$env:PATH"
$env:MCP_CONSOLE_SANDBOX_TEST_STATE_DIR = "$env:LOCALAPPDATA\mcp-console"
just test --locked -p codex-windows-sandbox --test console_proxy_pool --run-ignored only --test-threads 1 --retries 0
```

The regression drives the real native setup API and audits enabled account identities, shared secrets-deny membership/ACLs, fixed firewall exceptions, wrong-state rejection, and repeated explicit refresh. It injects a final-slot setup failure only when that slot has no secrets yet, then checks partial progress and retry; an existing installation reports that injection unavailable and preserves its credentials. Different-user rejection still requires a separate Windows-user control. Ordinary tests never invoke provisioning.

After setup completes, run the native pool workload regression from an ordinary, non-elevated shell with the same state variable. It resolves built Console helpers through Cargo's binary lookup or Bazel runfiles and stages them beside its copied executable. All Console workers must be retired; the test requires exclusive access to the pool and its reserved ports:

```powershell
just test --locked -p codex-windows-sandbox --test console_proxy_native --run-ignored all --test-threads 1 --retries 0
just test --locked -p mcp-console-sandbox --test windows_environment_native --run-ignored all --test-threads 1 --retries 0
```

The native test launches its executable through the real selected-slot runner under both offline and online accounts in strict slot 0 and local-access slot 2. It checks the native account identity and slot-specific private desktop, then attempts reserved proxy-port binds and ordinary TCP listeners on IPv4 and IPv6. Host-to-worker UDP packets establish actual receive admission, with host controls for both address families. The strict offline account blocks local TCP listeners and UDP reception; the local-access slot and online accounts provide positive controls. Each tested account rejects proxy-port binds. While each workload waits on stdin, the registered owner queries its process and token SID; impersonating the other provisioned account must deny process query and token query, duplication and privilege adjustment. Existing native ACEs already permit the trusted credential owner to duplicate tokens; the observer adds query access without revoking that baseline, so owner duplication is not an isolation assertion.

The companion test uses the public environment transport and actual write attempts to verify that mixed-case workload TEMP/TMP grants work, conflicting host paths stay read-only, and omitting workload TEMP/TMP grants neither host nor target paths. Host proxy/local-binding variables with `inherit_environment=false` must not reconcile provisioning or reach the workload. These executable probes use existing provisioning, perform ordinary filesystem ACL refreshes, and never request UAC or change account network policy. Missing provisioning or unavailable ports fail the opt-in tests instead of silently skipping coverage.

## Console transport

`--config-env NAME -- COMMAND ...` consumes the unversioned configuration described in [PROTOCOL.md](PROTOCOL.md), with these platform fields and limits:

- `windows_sandbox_level` defaults to `auto`. Explicit `mxc` fails if unavailable or incompatible; explicit `elevated` and `unelevated` preserve their previous behavior. `disabled` is rejected.
- Targets use upstream private desktop isolation. Legacy desktop names retain Console's product identity; MXC uses the SDK's desktop implementation.
- `windows_state_dir` optionally selects an absolute persistent legacy state directory. MXC does not read, create, or provision it.
- The elevated mode requires prior explicit setup. Ordinary launches fail with setup guidance when accounts are missing.
- Unelevated execution requires `network: enabled`, host reads, and no read-deny policies. It does not provide OS-enforced network isolation or a read allowlist boundary. Selected write operations are restricted, but the deletion boundary failed native validation; see the limits below.
- Profiles use the same native constructors and workspace metadata defaults as Unix. Unsupported policy fails before launching the target.
- Managed proxy configuration, custom cleanup timeouts, macOS policy extensions, and Linux backend selection are rejected. `--bootstrap-fd` is Unix-only.
- The selected configuration and reserved transport variable are removed from the target environment case insensitively. Excluded variables cannot be reused as private temporary environment names.

The ordinary command arguments, cwd, and stdio remain the target's inputs. Environment inheritance and overrides retain the shared protocol rules. Private storage grants its data directory and can export `TMPDIR`, `TEMP`, and `TMP`.

## Command interface

Run `--help` for `setup` and `status`. Execute workloads only with `--config-env NAME -- command [args...]`. The former `run` subcommand and its permission, environment, root-override, proxy, and desktop arguments are removed; they fail with a CLI diagnostic and exit 2. They are not mapped onto JSON fields. The shared configuration has no version field; cwd comes from the caller, environment follows its inheritance/override rules, and policy uses its existing profile and filesystem fields. Target arguments after `--` pass through unchanged, including names that used to be runner options. Ordinary launches require explicit initial provisioning for elevated mode.

Targets still need host read/traverse permission. In particular, Python 3.14's private temporary directories can grant access only through owner/admin/system ACL entries that a restricted token cannot use. Ordinary directories inheriting the current user's access work without machine-wide ACL changes. Use native Windows paths with backslashes for `cmd.exe`. Targets also remain subject to host Application Control policy; error 4551 is a host policy rejection.

Unelevated launches create capability SIDs and save mappings in `cap_sid`. Capability ACL entries persist on filesystem objects; deleting the state directory does not undo them. Elevated launches use provisioned accounts and refresh workspace ACLs. Backend upgrades or network-setting changes can require administrator repair.

## Lifecycle

Console's pipe-launched workloads enter a non-breakaway Job at process creation. After normal root exit, timeout, or cancellation, the backend terminates remaining members and confirms zero active processes before returning an exit receipt. A native Job completion port wakes the waiter; an accounting query confirms the barrier, with a five-second cleanup allowance. Failure uses reserved exit code 125. A missing exit receipt is distinct from a target exit code of `0xffffffff` (`-1`). Codex's default product continues to preserve descendants after normal root exit.

The environment transport watches its direct caller and optional `lifecycle.parent_pid` owner through retained process handles. Owner death or Ctrl+C requests session termination. It removes private storage only after a confirmed receipt; startup errors and unconfirmed retirement retain storage with diagnostics. Private storage is not deleted while target descendants are known to remain.
After confirmed Job retirement, storage removal retries Windows sharing violations for up to five seconds while file or image mappings finish releasing. Other errors and persistent sharing violations remain cleanup failures; no successful receipt is returned before removal completes.

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
