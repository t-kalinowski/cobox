# Windows native sandbox

The Windows executable uses Codex's shared capability, policy conversion, and launch APIs without `codex-core` or a running Codex application. Console's backend preferences and proxy-mode validation live in this leaf crate. It supports explicit `setup` and `status` and uses Console's environment transport for all execution.

The JSON `windows_backend` field accepts `auto` (the default), `mxc`, `elevated`, and `unelevated`. Auto prefers native MXC when the Windows build and policy support it, otherwise selects elevated. Explicit selections fail closed; launch failures never trigger a backend retry. MXC requires no setup. Elevated setup requires administrator approval and creates dedicated sandbox accounts; commands do not run as administrator. Unelevated runs under the current user's restricted token without administrator setup.

`windows_sandbox_level` is an alias for `windows_backend`. Supply only one of the two names; a configuration containing both is rejected.

Existing Console sandbox accounts keep Auto on the legacy elevated backend. Old setup does not register every directory containing account credentials, so MXC's host identity cannot safely protect those unknown locations. This patch does not migrate or remove those accounts; explicit MXC reports the incompatibility. `setup` and `status` continue to manage only the legacy backend.

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

Setup requests Windows UAC approval when provisioning is needed. Repeating it reuses current setup records and enabled accounts. Status prints JSON and exits zero when current records, enabled accounts, and adjacent helpers are present. It is a readiness check, not an audit of every firewall rule.

Setup version 6 installs account-scoped WFP loopback filters; installations with an older setup version require an approved refresh. Installation must succeed before setup records are committed. The filters preserve the native proxy-port exceptions and local-binding setting; uninstall removes them with the other product-specific WFP objects.

The launcher creates `.sandbox-bin` as the caller before elevation, so ordinary launches can refresh its protected DACL. An older installation whose helper directory is administrator-owned can fail with `helper_sandbox_lock_failed`; it needs an ownership repair before ordinary launches will work.

State defaults to `%LOCALAPPDATA%\mcp-console`; `setup` and `status` accept an absolute `--state-dir`. Use one stable state directory per Windows user. Accounts and network policy are machine resources, so separate directories are not independent installations. Existing Codex accounts, firewall rules, and WFP identifiers retain their names. Another product's account records are rejected.

Console display names are **McpConsoleSandboxOffline** and **McpConsoleSandboxOnline**; login names are `McpConsoleSandboxOff` and `McpConsoleSandboxOn` to fit Windows' 20-character limit. Setup also uses `ConsoleSandboxUsers`, protected credentials in `.sandbox-secrets`, and versioned records under `.sandbox`.

## Console transport

`--config-env NAME -- COMMAND ...` consumes the unversioned configuration described in [PROTOCOL.md](PROTOCOL.md), with these platform fields and limits:

- Omitted or null `windows_backend` means `auto`. Explicit backend names are `auto`, `mxc`, `elevated`, and `unelevated`.
- Legacy targets run on a private Windows desktop with Console-specific names; MXC uses the native backend's desktop isolation.
- `windows_state_dir` optionally selects an absolute persistent legacy state directory. Only legacy backends resolve its `LOCALAPPDATA` default; MXC needs neither and does not inspect setup records.
- The elevated mode requires prior explicit setup. Ordinary launches fail with setup guidance when accounts are missing.
- Unelevated execution requires `network: enabled`, host reads, and no read-deny policies. It does not provide OS-enforced network isolation or a read allowlist boundary. Selected write operations are restricted, but deletion outside writable roots is not reliably denied; see the limits below.
- Profiles use the same native constructors and workspace metadata defaults as Unix. Unsupported policy fails before launching the target.
- `external-sandbox` delegates enforcement to the caller's outer sandbox when no managed proxy is requested. Codex's selection rules omit native restrictions, while the runner uses the existing supervised Job helper for descendant retirement and private-storage cleanup.
- MXC supports managed HTTP/CONNECT and SOCKS5 TCP proxies when `allowLocalBinding` is true. Dedicated listeners admit only clients in the workload's Job. MXC host loopback is bidirectional, so Auto falls back when local binding is disallowed; legacy Windows retains its existing managed-proxy rejection. Active SOCKS5 UDP and Unix-socket configurations fail preflight for every backend because neither Console path supports them. An unused UDP flag is accepted when SOCKS5 is disabled.
- Custom cleanup timeouts, macOS policy extensions, and Linux backend selection are rejected. `--bootstrap-fd` is Unix-only.
- The selected configuration and reserved transport variable are removed from the target environment case insensitively. Excluded variables cannot be reused as private temporary environment names.
- With a managed proxy, the selected configuration variable must not collide case insensitively with generated proxy variables such as `HTTP_PROXY` or `NODE_USE_ENV_PROXY`; such requests fail before creating resources.

The ordinary command arguments, cwd, and stdio remain the target's inputs. Environment inheritance and overrides retain the shared protocol rules. Private storage grants its data directory and can export `TMPDIR`, `TEMP`, and `TMP`.

Elevated setup grants non-inheriting directory metadata access to the command's working directory before launching the sandbox account. Content read grants still run through the read helper; opening the working directory must not race that helper.
Existing access through the sandbox group or built-in read principals avoids an ACL write, including a NULL DACL. The check conservatively rejects metadata denies that apply to those principals even when an allow is also present. If an existing deny ACE prevents a missing metadata grant, setup fails before launching the command; it never overrides that deny.

## Command interface

Run `--help` for `setup` and `status`. Execute workloads with `--config-env NAME -- command [args...]`. Arguments after `--` pass through unchanged. Cwd comes from the caller; target environment and policy use the shared JSON fields. Elevated mode requires explicit initial provisioning.

Targets still need host read/traverse permission. In particular, Python 3.14's private temporary directories can grant access only through owner/admin/system ACL entries that a restricted token cannot use. Ordinary directories inheriting the current user's access work without machine-wide ACL changes. Use native Windows paths with backslashes for `cmd.exe`. Targets also remain subject to host Application Control policy; error 4551 is a host policy rejection.

Unelevated launches create capability SIDs and save mappings in `cap_sid`. Capability ACL entries persist on filesystem objects; deleting the state directory does not undo them. Elevated launches use provisioned accounts and refresh workspace ACLs. Backend upgrades or network-setting changes can require administrator repair.

## Lifecycle

Console's pipe-launched workloads enter a non-breakaway Job at process creation. After normal root exit, timeout, or cancellation, the backend terminates remaining members and confirms zero active processes before returning an exit receipt. A native Job completion port wakes the waiter; an accounting query confirms the barrier, with a five-second cleanup allowance. Failure uses reserved exit code 125. A missing exit receipt is distinct from a target exit code of `0xffffffff` (`-1`). Codex's default product continues to preserve descendants after normal root exit.

The environment transport watches its direct caller and optional `lifecycle.parent_pid` owner through retained process handles. Owner death or Ctrl+C requests session termination. Failed preflight removes temporary storage; after a launch attempt, cleanup requires a confirmed receipt. Unconfirmed retirement retains storage with diagnostics. A target exit code of 125 is a valid receipt and still permits cleanup. After confirmed Job retirement, storage removal retries Windows sharing violations for up to five seconds while file or image mappings finish releasing. Other errors and persistent sharing violations remain cleanup failures; no successful receipt is returned before removal completes.

Unelevated runner loss and elevated helper loss close kill-on-close Jobs. Runner loss does not guarantee storage deletion. A forcibly killed waiting Console frontend is not evidence of completed native retirement and cannot admit a replacement. Windows console signals and desktop behavior are not Unix terminal semantics.

## Validation limits

Unelevated token/ACL enforcement does not reliably deny deletion outside writable roots, including with `:read-only`. Broadly writable inherited ACLs can also permit elevated-account deletion. File-creation denial does not establish deletion isolation; the runner retains the native token/ACL model.

The ordinary Windows suite covers environment transport, policy rejection, private desktops, binary stdin, exit codes, Job retirement, owner death, and runner loss. Public MXC contracts return early with a diagnostic when the native runtime is unavailable or existing Console accounts prevent MXC selection. The fixed-command native MXC proxy contract also runs on provisioned hosts. These tests never provision, migrate, or delete accounts.

Elevated TCP/UDP regressions require interactive administrator setup and are opt-in:

```powershell
just test --locked -p mcp-console-sandbox --retries 0 --run-ignored only -E 'test(elevated_offline_account_denies_loopback_)'
```

These tests use IPv4/IPv6 host listeners and a compiled target fixture, first verifying online connectivity and then offline denial. UDP checks actual receipt. For a nondefault provisioned directory, set `MCP_CONSOLE_SANDBOX_TEST_STATE_DIR` to its absolute path. Missing setup or skipped runtime contracts must be reported separately from passing checks.

The upstream control-pipe fixture invokes `python` by name; use an actual Python installation on the test process's `PATH`, since the Windows app execution alias can create a descendant outside the tested Job. Standalone lifecycle contracts use the compiled fixture directly.
